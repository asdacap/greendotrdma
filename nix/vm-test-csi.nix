# The CSI end-to-end fence proof, on real kernels + Soft-RoCE:
#
#   client VM ── csi-e2e (real controller code) ── ssh ── greendotctl pipe ──▶ daemon
#   client VM ── nvme connect -t rdma :4421 ─────────────────────────────────▶ nvmet
#
# The script walks the whole lifecycle: create (export is born CLOSED — the
# initiator's connect is rejected until granted), publish (grant this host's
# NQN), connect + write, a concurrent web reconcile that must leave the CSI
# subsystem alone, unpublish (the three-step fence: the LIVE controller is
# severed and the reconnect is DNR-rejected), delete (configfs + zvol + the
# empty CSI port reaped).
{ pkgs, greendot, greendot-csi }:

let
  common = import ./common.nix { inherit pkgs; };
  # nixpkgs' well-known throwaway SSH keypair for tests.
  snakeOil = import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs;
in
pkgs.testers.runNixOSTest {
  name = "greendot-vm-csi";

  nodes.target = { config, lib, ... }: {
    imports = [ (common.mkGreendotNode { inherit greendot; }) ];
    services.openssh.enable = true;
    # The CSI controller's login exactly as the deb's sysusers/tmpfiles leave
    # it: the user, its group membership, an empty home — and *no* authorized
    # key. The test installs the key through greendot-web's SSH access page,
    # so what sshd ends up parsing is the forced command the daemon
    # synthesized, not one this file wrote.
    users.groups.greendot-csi = { };
    users.users.greendot-csi = {
      isSystemUser = true;
      group = "greendot-csi";
      extraGroups = [ "greendot" ];
      home = "/var/lib/greendotrdma/csi";
      createHome = true;
      useDefaultShell = true; # sshd runs the forced command via the shell
    };
    # Exactly what pkg/tmpfiles.conf gives the deb, and for the same reason:
    # sshd refuses an authorized_keys whose home directory belongs to another
    # user. The parent is listed too — without it greendot-web's
    # `StateDirectory=` adopts /var/lib/greendotrdma and chowns the tree,
    # taking the CSI home with it.
    systemd.tmpfiles.rules = [
      "d /var/lib/greendotrdma 0750 greendot greendot -"
      "d /var/lib/greendotrdma/csi 0750 greendot-csi greendot-csi -"
    ];
  };

  nodes.client = { config, lib, ... }: {
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.firewall.enable = false;
    # No boot.kernelModules and no manual rxe setup: the node plugin loads
    # nvme-rdma / rdma_rxe and stands up Soft-RoCE itself (that is what we prove).
    environment.systemPackages = with pkgs; [ greendot-csi nvme-cli rdma-core kmod openssh ];
  };

  testScript = ''
    netdev = "eth1"

    start_all()
    target.wait_for_unit("greendotctl.service")
    target.wait_for_unit("greendot-web.service")
    target.wait_for_unit("sshd.service")

    # --- Soft-RoCE on both nodes ---
    target.succeed("mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config")
    target.succeed("modprobe nvmet nvmet_rdma rdma_rxe")
    target.wait_until_succeeds(f"ip -o -4 addr show dev {netdev} | grep -q 'inet '")
    target.succeed(f"rdma link add rxe0 type rxe netdev {netdev}")
    target_ip = target.succeed(f"ip -o -4 addr show dev {netdev} | awk '{{print $4}}' | cut -d/ -f1 | head -1").strip()
    print(f"target_ip={target_ip}")

    # The client's fabric/RDMA setup is left to the node plugin (node-stage,
    # below); we only wait for the netdev the driver will hang Soft-RoCE off.
    client.wait_until_succeeds(f"ip -o -4 addr show dev {netdev} | grep -q 'inet '")

    # The node's identity is its /etc/nvme/hostnqn, generated exactly as the
    # DaemonSet's initContainer does and passed verbatim as --nodeid; deriving
    # the test's hostnqn from it keeps the initiator identity consistent (the
    # kernel's default hostid binds to this nqn on the driver's autoconnect).
    client.succeed("mkdir -p /etc/nvme")
    client.succeed(
        "test -s /etc/nvme/hostnqn || "
        "echo nqn.2014-08.org.nvmexpress:uuid:$(cat /proc/sys/kernel/random/uuid) > /etc/nvme/hostnqn"
    )
    client.succeed("test -s /etc/nvme/hostid || cat /proc/sys/kernel/random/uuid > /etc/nvme/hostid")
    hostnqn = client.succeed("cat /etc/nvme/hostnqn").strip()
    hostid = client.succeed("cat /etc/nvme/hostid").strip()

    # --- pool + parent dataset on the target ---
    target.succeed("truncate -s 1G /var/tmp/pool.img")
    target.succeed("zpool create tank /var/tmp/pool.img")
    target.succeed("zfs create tank/csi")

    # --- authorize the controller's key through the web UI ---
    # This is the whole trust path under test: an admin pastes a public key,
    # greendot-web hands it to the daemon, and the daemon — not the web —
    # writes the command="…greendotctl pipe",restrict line that sshd enforces.
    target.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -c /tmp/jar.txt "
        "--data 'username=gdadmin&password=test' http://127.0.0.1:8080/login"
    )
    dash = target.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/")
    csrf = dash.split('X-Greendot-Csrf":"')[1].split('"')[0]
    # snakeOilPublicKey is a literal string, not a store path: materialize it so
    # curl can form-encode the file and ssh-keygen can fingerprint it.
    target.succeed("printf '%s\\n' '${snakeOil.snakeOilPublicKey}' > /tmp/csi-key.pub")
    add = target.succeed(
        "curl -sf -b /tmp/jar.txt -H 'X-Greendot-Csrf: " + csrf + "' "
        "--data-urlencode public_key@/tmp/csi-key.pub "
        "--data 'label=vm-test' "
        "http://127.0.0.1:8080/ssh-access/add"
    )
    assert "view task" in add, f"the add must dispatch a task: {add}"
    # The task is dispatched asynchronously; wait for the file the daemon writes.
    authk = "/var/lib/greendotrdma/csi/.ssh/authorized_keys"
    target.wait_until_succeeds(f"test -s {authk}", timeout=30)
    line = target.succeed(f"cat {authk}").strip()
    print(f"authorized_keys={line}")
    # The daemon writes its own resolved executable, whatever the store path is.
    assert line.startswith('command="/nix/store/'), f"no forced command: {line}"
    assert '/bin/greendotctl pipe",restrict ' in line, f"no forced command: {line}"
    # The pasted key was re-serialized with the label as its comment.
    assert line.endswith(" vm-test"), f"label not applied: {line}"
    assert target.succeed(f"stat -c '%a %U' {authk}").strip() == "600 greendot-csi"
    assert target.succeed("stat -c '%a %U' /var/lib/greendotrdma/csi/.ssh").strip() == "700 greendot-csi"
    # The page now lists it, restricted to the pipe.
    page = target.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/ssh-access")
    assert "vm-test" in page, "the key is listed under its label"
    assert "Full shell" not in page, "a key we wrote is never flagged as a shell"
    # Every criterion green — including sshd's StrictModes on the home dir,
    # which is what silently refuses a key when the packaging gets it wrong.
    diag = target.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/ssh-access/diagnose")
    assert "dot-red" not in diag, f"the trust path must diagnose clean:\n{diag}"

    # --- the controller's credentials on the client ---
    client.succeed("install -m 600 ${snakeOil.snakeOilPrivateKey} /root/csi-key")
    client.wait_until_succeeds(f"ssh-keyscan {target_ip} > /root/known_hosts && test -s /root/known_hosts")
    e2e = (
        "csi-e2e"
        f" -ssh-addr {target_ip}:22 -ssh-user greendot-csi"
        " -ssh-key /root/csi-key -ssh-known-hosts /root/known_hosts"
        " -ssh-command ignored-by-forced-command"
        f" -dataset-parent tank/csi -traddr {target_ip} -transport rdma"
    )

    # --- create: closed export, pinned identity ---
    out = client.succeed(f"{e2e} -action create -volume pvc-1 -size 67108864")
    print(out)
    ctxvals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    nqn, uuid = ctxvals["nqn"], ctxvals["deviceUUID"]
    # The initiator side driven through the real node plugin: transport prep
    # (modprobe nvme-rdma + Soft-RoCE on {netdev}) then the fabric connect.
    node_stage = (
        f"csi-e2e -action node-stage -volume pvc-1 -nqn {nqn} -device-uuid {uuid}"
        f" -traddr {target_ip} -trsvcid 4421 -transport rdma"
        f" -hostnqn {hostnqn} -hostid {hostid} -soft-roce-netdev {netdev}"
    )
    subsys = f"/sys/kernel/config/nvmet/subsystems/{nqn}"
    target.succeed(f"test -d {subsys}")
    assert target.succeed(f"cat {subsys}/attr_allow_any_host").strip() == "0", "export must be born closed"
    assert target.succeed(f"cat {subsys}/namespaces/1/device_uuid").strip() == uuid, "uuid must be pinned"
    assert target.succeed("cat /sys/kernel/config/nvmet/ports/61000/addr_trsvcid").strip() == "4421"

    # Closed means closed: the node plugin readies RDMA (modprobe + Soft-RoCE)
    # and its fabric connect is still rejected before any grant.
    client.fail(node_stage)

    # --- publish: grant exactly this host, then the node connect succeeds ---
    client.succeed(f"{e2e} -action publish -volume pvc-1 -hostnqn {hostnqn}")
    client.succeed(node_stage)
    dev = f"/dev/disk/by-id/nvme-uuid.{uuid}"
    client.wait_until_succeeds(f"test -e {dev}", timeout=30)
    client.succeed(f"dd if=/dev/urandom of={dev} bs=1M count=4 oflag=direct")

    # --- a concurrent web reconcile must not touch the CSI export ---
    # (as the greendot user: the daemon admits only that uid / its group)
    target.succeed("su greendot -s /bin/sh -c '${greendot}/bin/greendotctl reconcile'")
    target.succeed(f"test -d {subsys}")
    target.succeed(f"test -e /sys/kernel/config/nvmet/ports/61000/subsystems/{nqn}")

    # --- the fence: unpublish severs the LIVE controller ---
    client.succeed(f"{e2e} -action unpublish -volume pvc-1 -hostnqn {hostnqn}")
    # The target killed the controller; the client's reconnect is rejected
    # with DNR, so its kernel deletes the controller and the device vanishes.
    client.wait_until_fails(f"test -e {dev}", timeout=60)
    client.fail(f"nvme connect -t rdma -a {target_ip} -s 4421 -n {nqn} --hostnqn={hostnqn}")
    # The subsystem itself is still exported (relinked) for future grants.
    target.succeed(f"test -e /sys/kernel/config/nvmet/ports/61000/subsystems/{nqn}")

    # --- delete: everything gone, the empty CSI port reaped ---
    client.succeed(f"{e2e} -action delete -volume pvc-1")
    target.fail(f"test -d {subsys}")
    target.fail("test -d /sys/kernel/config/nvmet/ports/61000")
    target.fail("zfs list tank/csi/pvc-1")

    # Idempotent re-delete over the same channel.
    client.succeed(f"{e2e} -action delete -volume pvc-1")

    # --- revoke: the controller loses the box at once ---
    # The fingerprint carries `+` and `/`, so it must be form-encoded, not
    # pasted into a query string.
    target.succeed(
        "curl -sf -b /tmp/jar.txt -H 'X-Greendot-Csrf: " + csrf + "' "
        "--data-urlencode \"fingerprint=$(ssh-keygen -lf /tmp/csi-key.pub | awk '{print $2}')\" "
        "http://127.0.0.1:8080/ssh-access/revoke > /dev/null"
    )
    target.wait_until_succeeds(f"test ! -s {authk}", timeout=30)
    client.fail(f"{e2e} -action delete -volume pvc-1")
  '';
}
