# The CSI end-to-end fence proof, on real kernels + Soft-RoCE:
#
#   client VM ── csi-e2e (real controller code) ── ssh ── greendotctl pipe ──▶ daemon
#   client VM ── nvme connect -t rdma :4421 ─────────────────────────────────▶ nvmet
#
# Exercise lazy exports, generation fencing, raw-block retries, detached/online
# growth and target-daemon restart recovery using only disposable VM resources.
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
        f" -dataset-parent tank/csi -traddr {target_ip} -transport rdma -attachment-id vm-attachment-1"
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
    target.fail(f"test -d {subsys}")
    # Detached growth must not create an export.
    client.succeed(f"{e2e} -action expand -volume pvc-1 -size 100663296")
    target.fail(f"test -d {subsys}")
    assert target.succeed("zfs get -Hp -o value volsize tank/csi/pvc-1").strip() == "100663296"

    # --- publish: grant exactly this host, then the node connect succeeds ---
    client.succeed(f"{e2e} -action publish -volume pvc-1 -hostnqn {hostnqn}")
    target.succeed(f"test -d {subsys}")
    assert target.succeed(f"cat {subsys}/attr_allow_any_host").strip() == "0"
    assert target.succeed(f"cat {subsys}/namespaces/1/device_uuid").strip() == uuid
    client.succeed(node_stage)
    dev = f"/dev/disk/by-id/nvme-uuid.{uuid}"
    client.wait_until_succeeds(f"test -e {dev}", timeout=30)
    client.succeed(f"dd if=/dev/urandom of={dev} bs=1M count=4 oflag=direct")

    node_publish = node_stage.replace("-action node-stage", "-action node-publish")
    client.succeed(node_publish)
    client.succeed(node_publish)
    assert client.succeed("awk '$5 == \"/tmp/csi-e2e-target\" {n++} END {print n+0}' /proc/self/mountinfo").strip() == "1"
    client.succeed(node_stage.replace("-action node-stage", "-action node-unpublish"))
    client.fail("mountpoint /tmp/csi-e2e-target")

    # Online grow retries must leave the real namespace at its new capacity.
    client.succeed(f"{e2e} -action expand -volume pvc-1 -size 134217728")
    client.succeed(f"{e2e} -action expand -volume pvc-1 -size 134217728")
    client.wait_until_succeeds(f"test $(blockdev --getsize64 {dev}) -eq 134217728")

    # Restart the target daemon, then reapply the SAME generation. Existing
    # initiator I/O remains valid and persisted ownership is recovered.
    target.succeed("systemctl restart greendotctl.service")
    target.wait_for_unit("greendotctl.service")
    client.succeed(f"{e2e} -action publish -volume pvc-1 -hostnqn {hostnqn}")
    client.succeed(f"dd if={dev} of=/dev/null bs=1M count=4 iflag=direct")

    # --- a concurrent web reconcile must not touch the CSI export ---
    # (as the greendot user: the daemon admits only that uid / its group)
    target.succeed("su greendot -s /bin/sh -c '${greendot}/bin/greendotctl reconcile'")
    target.succeed(f"test -d {subsys}")
    target.succeed(f"test -e /sys/kernel/config/nvmet/ports/61000/subsystems/{nqn}")

    # --- the fence: unpublish severs the LIVE controller ---
    client.succeed(f"{e2e} -action unpublish -volume pvc-1 -hostnqn {hostnqn}")
    # Lazy teardown removes the listener, so the initiator may retain a
    # reconnecting device until ctrl_loss_tmo instead of receiving DNR.
    # Prove the live controller is no longer usable, not immediate udev removal.
    client.wait_until_succeeds("test $(cat /sys/class/nvme/nvme0/state) != live")
    client.fail(f"timeout -s KILL 5 dd if={dev} of=/dev/null bs=4096 count=1 iflag=direct")
    client.fail(f"nvme connect -t rdma -a {target_ip} -s 4421 -n {nqn} --hostnqn={hostnqn}")
    target.fail(f"test -d {subsys}")
    # A restarted controller cannot resurrect the fenced generation.
    client.fail(f"{e2e} -action publish -volume pvc-1 -hostnqn {hostnqn}")
    target.fail(f"test -d {subsys}")

    # --- delete: everything gone, the empty CSI port reaped ---
    client.succeed(f"{e2e} -action delete -volume pvc-1")
    target.fail(f"test -d {subsys}")
    target.fail("test -d /sys/kernel/config/nvmet/ports/61000")
    target.fail("zfs list tank/csi/pvc-1")

    # Idempotent re-delete over the same channel.
    client.succeed(f"{e2e} -action delete -volume pvc-1")

    # Filesystem growth exercises NodeExpandVolume against real sysfs/mounts.
    out = client.succeed(f"{e2e} -action create -volume pvc-fs -size 67108864")
    fsctx = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    client.succeed(f"{e2e} -action publish -volume pvc-fs -hostnqn {hostnqn}")
    fsnode = (
        f"csi-e2e -volume pvc-fs -nqn {fsctx['nqn']} -device-uuid {fsctx['deviceUUID']}"
        f" -traddr {target_ip} -trsvcid 4421 -transport rdma -hostnqn {hostnqn} -hostid {hostid}"
        f" -soft-roce-netdev {netdev} -filesystem -staging-path /tmp/csi-fs-stage"
    )
    client.succeed(f"{fsnode} -action node-stage")
    client.succeed("echo preserved > /tmp/csi-fs-stage/proof && sync")
    before = int(client.succeed("stat -f -c %b /tmp/csi-fs-stage").strip())
    client.succeed(f"{e2e} -action expand -volume pvc-fs -size 134217728")
    print(client.succeed("readlink -f /sys/class/block/nvme1n1/device; ls -l /sys/class/nvme /sys/class/nvme-subsystem; for p in /sys/class/nvme/nvme*; do echo $p; cat $p/subsysnqn; done"))
    client.succeed(f"{fsnode} -action node-expand -size 134217728")
    after = int(client.succeed("stat -f -c %b /tmp/csi-fs-stage").strip())
    assert after > before, "filesystem did not grow"
    assert client.succeed("cat /tmp/csi-fs-stage/proof").strip() == "preserved"
    client.succeed(f"{fsnode} -action node-unstage")
    client.succeed(f"{e2e} -action unpublish -volume pvc-fs -hostnqn {hostnqn}")
    client.succeed(f"{e2e} -action delete -volume pvc-fs")

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
