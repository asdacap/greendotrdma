# Boots TWO NixOS VMs and proves cross-host RDMA: a `target` VM serves an
# NVMe-oF export and an iSCSI export over Soft-RoCE, and a separate `initiator`
# VM reaches BOTH across the test LAN — `nvme connect -t rdma` for NVMe/RDMA and
# `iscsiadm ... -I iser` for iSER. This is the honest version of the green dot:
# RDMA between two hosts, not loopback to self (see vm-test.nix for that).
{ pkgs, greendot }:

let
  common = import ./common.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "greendot-vm-two-node";

  nodes.target = common.mkGreendotNode {
    inherit greendot;
    # iSCSI/iSER target side on top of the NVMe-oF module set.
    extraKernelModules = [ "target_core_mod" "iscsi_target_mod" "ib_isert" ];
  };

  # The initiator runs no greendot services: just the client stacks.
  nodes.initiator = { config, pkgs, lib, ... }: {
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.firewall.enable = false;
    boot.kernelModules = [ "rdma_rxe" "nvme_rdma" "nvme_fabrics" "ib_iser" ];
    environment.systemPackages = with pkgs; [ nvme-cli rdma-core util-linux openiscsi kmod ];
    # Brings up iscsid and sets the initiator IQN (target uses allow-any-host).
    services.openiscsi = {
      enable = true;
      name = "iqn.2026-06.io.greendot:initiator";
    };
  };

  testScript = ''
    netdev = "eth1"

    start_all()
    target.wait_for_unit("greendot-helper.service")
    target.wait_for_unit("greendot-web.service")
    target.wait_for_open_port(8080)

    # --- Soft-RoCE on both nodes so RDMA across the test LAN is real ---
    target.succeed("mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config")
    target.succeed("modprobe nvmet nvme_loop nvmet_rdma rdma_rxe nvme_rdma nvme_fabrics target_core_mod iscsi_target_mod ib_isert")
    # rtslib/targetcli-fb store their db under /etc/target; the apt package ships
    # this dir on Ubuntu, but NixOS doesn't create it live, so targetctl restore
    # would fail with "db_root: cannot open: /etc/target".
    target.succeed("mkdir -p /etc/target")
    target.wait_until_succeeds(f"ip -o -4 addr show dev {netdev} | grep -q 'inet '")
    target.succeed(f"rdma link add rxe0 type rxe netdev {netdev}")
    target.succeed("rdma link show | grep -q rxe0")
    target_ip = target.succeed(f"ip -o -4 addr show dev {netdev} | awk '{{print $4}}' | cut -d/ -f1 | head -1").strip()
    assert target_ip, "no IPv4 address on the target netdev"
    print(f"target_ip={target_ip}")

    initiator.succeed("modprobe rdma_rxe nvme_rdma nvme_fabrics ib_iser")
    initiator.wait_until_succeeds(f"ip -o -4 addr show dev {netdev} | grep -q 'inet '")
    initiator.succeed(f"rdma link add rxe0 type rxe netdev {netdev}")
    initiator.succeed("rdma link show | grep -q rxe0")

    # --- pool + one zvol per protocol on the target ---
    target.succeed("truncate -s 1G /var/tmp/pool.img")
    target.succeed("zpool create tank /var/tmp/pool.img")
    target.succeed("zfs create -V 128M tank/nvme1")
    target.succeed("zfs create -V 128M tank/iscsi1")
    target.wait_until_succeeds("test -e /dev/zvol/tank/nvme1")
    target.wait_until_succeeds("test -e /dev/zvol/tank/iscsi1")

    # --- admin login + CSRF (all web calls run locally on the target) ---
    out = target.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -c /tmp/jar.txt "
        "--data 'username=gdadmin&password=test' http://127.0.0.1:8080/login"
    )
    assert out == "303", f"admin login should redirect (303), got {out}"
    dash = target.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/")
    csrf = dash.split('X-Greendot-Csrf":"')[1].split('"')[0]
    print(f"csrf={csrf}")

    # Bind the export portals to the RDMA-backed address.
    target.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        f"--data 'listen_addr={target_ip}' http://127.0.0.1:8080/settings/listen"
    )
    # Create both exports with RDMA + TCP. Empty initiators -> allow any host,
    # so the initiator VM can connect without per-host ACLs.
    target.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        "--data 'kind=nvme&name=nvme1&device=/dev/zvol/tank/nvme1&want_rdma=1&want_tcp=1' "
        "http://127.0.0.1:8080/exports/create"
    )
    target.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        "--data 'kind=iscsi&name=iscsi1&device=/dev/zvol/tank/iscsi1&want_rdma=1&want_tcp=1' "
        "http://127.0.0.1:8080/exports/create"
    )

    # --- target-side: both realized in configfs, RDMA-linked ---
    target.wait_until_succeeds("test -d /sys/kernel/config/nvmet/subsystems/nqn.2026-06.io.greendot:nvme1", timeout=120)
    trtype = target.succeed("cat /sys/kernel/config/nvmet/ports/1/addr_trtype").strip()
    assert trtype == "rdma", f"nvmet port 1 should be rdma, got {trtype}"

    iser_np = f"/sys/kernel/config/target/iscsi/iqn.2026-06.io.greendot:iscsi1/tpgt_1/np/{target_ip}:3260"
    target.wait_until_succeeds(f"test -d {iser_np}", timeout=120)
    iser = target.succeed(f"cat {iser_np}/iser").strip()
    assert iser == "1", f"iSCSI portal should be iSER-enabled, got iser={iser}"

    # Both exports listed; Prometheus gauge = 2 (green) for each.
    page = target.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/exports")
    assert "nvme1" in page and "iscsi1" in page, f"exports not listed:\n{page}"
    metrics = target.succeed("curl -s http://127.0.0.1:8080/metrics")
    print(metrics)
    assert 'greendot_export_status{export="nvme1"} 2' in metrics, "nvme export not green in /metrics"
    assert 'greendot_export_status{export="iscsi1"} 2' in metrics, "iscsi export not green in /metrics"

    # --- the proof: a SEPARATE host reaches both exports over real RDMA ---
    initiator.wait_until_succeeds(f"ping -c1 -W2 {target_ip}")  # LAN reachable
    # NVMe-oF over RDMA.
    initiator.succeed(f"nvme connect -t rdma -a {target_ip} -s 4420 -n nqn.2026-06.io.greendot:nvme1")
    initiator.wait_until_succeeds("nvme list | grep -q 'Linux'")
    initiator.succeed("nvme disconnect -n nqn.2026-06.io.greendot:nvme1")

    # iSCSI over iSER (RDMA). Use a dedicated iSER iface.
    initiator.succeed("iscsiadm -m iface -I iser -o new || true")
    initiator.succeed("iscsiadm -m iface -I iser -o update -n iface.transport_name -v iser")
    initiator.succeed(f"iscsiadm -m discovery -t st -p {target_ip}:3260 -I iser")
    initiator.succeed(
        f"iscsiadm -m node -T iqn.2026-06.io.greendot:iscsi1 -p {target_ip}:3260 -I iser --login"
    )
    initiator.wait_until_succeeds("iscsiadm -m session -P3 | grep -iq iser")
    initiator.wait_until_succeeds("lsblk -S -o VENDOR | grep -iq LIO")
    initiator.succeed(
        f"iscsiadm -m node -T iqn.2026-06.io.greendot:iscsi1 -p {target_ip}:3260 -I iser --logout"
    )

    # --- disabling reconciles both back out of configfs ---
    target.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        "--data 'id=1&enable=false' http://127.0.0.1:8080/exports/toggle"
    )
    target.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        "--data 'id=2&enable=false' http://127.0.0.1:8080/exports/toggle"
    )
    target.wait_until_fails("test -d /sys/kernel/config/nvmet/subsystems/nqn.2026-06.io.greendot:nvme1", timeout=60)
    target.wait_until_fails("test -d /sys/kernel/config/target/iscsi/iqn.2026-06.io.greendot:iscsi1", timeout=60)
  '';
}
