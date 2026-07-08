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
    # The CSI controller's login: forced command + group greendot, exactly the
    # shape the deb's sysusers/postinst set up.
    users.groups.greendot-csi = { };
    users.users.greendot-csi = {
      isSystemUser = true;
      group = "greendot-csi";
      extraGroups = [ "greendot" ];
      home = "/var/lib/greendotrdma/csi";
      createHome = true;
      useDefaultShell = true; # sshd runs the forced command via the shell
      openssh.authorizedKeys.keys = [
        ''command="${greendot}/bin/greendotctl pipe",restrict ${snakeOil.snakeOilPublicKey}''
      ];
    };
  };

  nodes.client = { config, lib, ... }: {
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.firewall.enable = false;
    boot.kernelModules = [ "rdma_rxe" "nvme_rdma" "nvme_fabrics" ];
    environment.systemPackages = with pkgs; [ greendot-csi nvme-cli rdma-core kmod openssh ];
  };

  testScript = ''
    netdev = "eth1"
    hostnqn = "nqn.2014-08.org.nvmexpress:uuid:11111111-2222-3333-4444-555555555555"

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

    client.succeed("modprobe rdma_rxe nvme_rdma nvme_fabrics")
    client.wait_until_succeeds(f"ip -o -4 addr show dev {netdev} | grep -q 'inet '")
    client.succeed(f"rdma link add rxe0 type rxe netdev {netdev}")

    # --- pool + parent dataset on the target ---
    target.succeed("truncate -s 1G /var/tmp/pool.img")
    target.succeed("zpool create tank /var/tmp/pool.img")
    target.succeed("zfs create tank/csi")

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
    subsys = f"/sys/kernel/config/nvmet/subsystems/{nqn}"
    target.succeed(f"test -d {subsys}")
    assert target.succeed(f"cat {subsys}/attr_allow_any_host").strip() == "0", "export must be born closed"
    assert target.succeed(f"cat {subsys}/namespaces/1/device_uuid").strip() == uuid, "uuid must be pinned"
    assert target.succeed("cat /sys/kernel/config/nvmet/ports/61000/addr_trsvcid").strip() == "4421"

    # Closed means closed: the initiator is rejected before any grant.
    client.fail(f"nvme connect -t rdma -a {target_ip} -s 4421 -n {nqn} --hostnqn={hostnqn}")

    # --- publish: grant exactly this host, then the connect succeeds ---
    client.succeed(f"{e2e} -action publish -volume pvc-1 -hostnqn {hostnqn}")
    client.succeed(f"nvme connect -t rdma -a {target_ip} -s 4421 -n {nqn} --hostnqn={hostnqn}")
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
  '';
}
