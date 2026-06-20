# Boots a NixOS VM and drives the whole GreenDotRDMA stack against a real
# kernel: ZFS zvol -> NVMe-oF export over Soft-RoCE -> green dot, via the
# web API (login -> helper -> configfs -> read-back -> dot), plus the
# Prometheus endpoint and a real `nvme connect`.
#
# This is the single-node (loopback) test: the VM connects to its own RDMA
# address. See vm-test-two-node.nix for the cross-host NVMe/RDMA + iSER test.
{ pkgs, greendot }:

let
  common = import ./common.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "greendot-vm";

  nodes.machine = common.mkGreendotNode { inherit greendot; };

  testScript = ''
    machine.wait_for_unit("greendot-helper.service")
    machine.wait_for_unit("greendot-web.service")
    machine.wait_for_open_port(8080)

    # configfs + a Soft-RoCE device so RDMA is real. eth1 is the deterministic
    # NixOS-test LAN (192.168.1.1); wait for its address before using it.
    machine.succeed("mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config")
    machine.succeed("modprobe nvmet nvme_loop nvmet_rdma rdma_rxe nvme_rdma nvme_fabrics")
    netdev = "eth1"
    machine.wait_until_succeeds(f"ip -o -4 addr show dev {netdev} | grep -q 'inet '")
    machine.succeed(f"rdma link add rxe0 type rxe netdev {netdev}")
    machine.succeed("rdma link show | grep -q rxe0")
    ip = machine.succeed(f"ip -o -4 addr show dev {netdev} | awk '{{print $4}}' | cut -d/ -f1 | head -1").strip()
    assert ip, "no IPv4 address on the test netdev"
    print(f"netdev={netdev} ip={ip}")

    # A file-backed pool and a zvol to export.
    machine.succeed("truncate -s 1G /var/tmp/pool.img")
    machine.succeed("zpool create tank /var/tmp/pool.img")
    machine.succeed("zfs create -V 128M tank/vm1")
    machine.wait_until_succeeds("test -e /dev/zvol/tank/vm1")

    # --- web auth ---
    # Non-admin system user is rejected (PAM ok, group check fails).
    out = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -c /tmp/bad.jar "
        "--data 'username=gduser&password=test' http://127.0.0.1:8080/login"
    )
    assert out == "401", f"non-admin login should be 401, got {out}"
    # Wrong password rejected.
    out = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' "
        "--data 'username=gdadmin&password=wrong' http://127.0.0.1:8080/login"
    )
    assert out == "401", f"bad password should be 401, got {out}"
    # Admin login succeeds and sets a session cookie.
    out = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -c /tmp/jar.txt "
        "--data 'username=gdadmin&password=test' http://127.0.0.1:8080/login"
    )
    assert out == "303", f"admin login should redirect (303), got {out}"
    machine.succeed("grep -q gd_session /tmp/jar.txt")

    # CSRF token from the dashboard, for the mutating calls.
    dash = machine.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/")
    csrf = dash.split('X-Greendot-Csrf":"')[1].split('"')[0]
    print(f"csrf={csrf}")

    # Point the targets at the RDMA-backed address, then create an NVMe-oF
    # export of the zvol with RDMA + TCP.
    machine.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        f"--data 'listen_addr={ip}' http://127.0.0.1:8080/settings/listen"
    )
    machine.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        "--data 'kind=nvme&name=vm1&device=/dev/zvol/tank/vm1&want_rdma=1&want_tcp=1' "
        "http://127.0.0.1:8080/exports/create"
    )

    # The apply wrote configfs directly as a recorded task: the subsystem must
    # now exist in configfs, RDMA-linked.
    machine.wait_until_succeeds("test -d /sys/kernel/config/nvmet/subsystems/nqn.2026-06.io.greendot:vm1", timeout=120)
    machine.succeed("test -L /sys/kernel/config/nvmet/ports/1/subsystems/nqn.2026-06.io.greendot:vm1")
    trtype = machine.succeed("cat /sys/kernel/config/nvmet/ports/1/addr_trtype").strip()
    assert trtype == "rdma", f"port 1 should be rdma, got {trtype}"

    # The dashboard must show this export GREEN (served via RDMA).
    page = machine.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/exports")
    assert "vm1" in page, "export not listed"
    assert "dot-green" in page, f"expected a green dot, page was:\n{page}"

    # Prove it actually serves: connect to our own target over RDMA.
    machine.succeed(f"nvme connect -t rdma -a {ip} -s 4420 -n nqn.2026-06.io.greendot:vm1")
    machine.wait_until_succeeds("nvme list | grep -q 'Linux'")
    machine.succeed("nvme disconnect -n nqn.2026-06.io.greendot:vm1")

    # Prometheus endpoint (no auth) reports the export status gauge = 2 (green).
    metrics = machine.succeed("curl -s http://127.0.0.1:8080/metrics")
    print(metrics)
    assert 'greendot_export_status{export="vm1"} 2' in metrics, "export status gauge not green in /metrics"

    # The operation was recorded as a task: the Tasks page lists a succeeded
    # nvmet-apply that wrote configfs directly (no external CLI).
    tasks = machine.succeed("curl -s -b /tmp/jar.txt http://127.0.0.1:8080/tasks")
    assert "nvmet-apply" in tasks, f"apply not recorded as a task:\n{tasks}"
    assert "configfs" in tasks, "apply should run as a direct configfs write"
    assert "dot-red" not in tasks, f"a task failed:\n{tasks}"

    # Disabling the export tears the subsystem back down (reconcile works).
    machine.succeed(
        f"curl -s -b /tmp/jar.txt -H 'X-Greendot-Csrf: {csrf}' "
        "--data 'id=1&enable=false' http://127.0.0.1:8080/exports/toggle"
    )
    machine.wait_until_fails("test -d /sys/kernel/config/nvmet/subsystems/nqn.2026-06.io.greendot:vm1", timeout=60)
  '';
}
