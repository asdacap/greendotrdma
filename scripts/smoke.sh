#!/bin/sh
# End-to-end smoke test. Run as root inside a disposable Ubuntu VM:
#
#   sudo scripts/smoke.sh
#
# Covers: file-backed zpool, zvol create, NVMe-oF loop export, local
# nvme connect, Soft-RoCE (rxe) RDMA port bind = the green dot's
# precondition, and the LIO iSER portal write.
set -eu

say() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run as root"

IMG=/var/tmp/greendot-smoke.img
POOL=gdsmoke
NQN=nqn.2026-06.io.greendot:smoke

cleanup() {
    set +e
    nvme disconnect -n "$NQN" >/dev/null 2>&1
    for port in /sys/kernel/config/nvmet/ports/*; do
        [ -d "$port" ] && rm -f "$port"/subsystems/* && rmdir "$port"
    done
    if [ -d "/sys/kernel/config/nvmet/subsystems/$NQN" ]; then
        for ns in "/sys/kernel/config/nvmet/subsystems/$NQN"/namespaces/*; do
            [ -d "$ns" ] && rmdir "$ns"
        done
        rmdir "/sys/kernel/config/nvmet/subsystems/$NQN"
    fi
    zpool destroy "$POOL" >/dev/null 2>&1
    rm -f "$IMG"
}
trap cleanup EXIT

say "creating file-backed zpool"
truncate -s 1G "$IMG"
zpool create -f "$POOL" "$IMG"
zfs create -V 100M "$POOL/vol1"
[ -e "/dev/zvol/$POOL/vol1" ] || fail "zvol device node missing"

say "NVMe-oF loop export"
modprobe nvmet nvme_loop
SUBSYS="/sys/kernel/config/nvmet/subsystems/$NQN"
mkdir -p "$SUBSYS/namespaces/1"
echo 1 > "$SUBSYS/attr_allow_any_host"
echo "/dev/zvol/$POOL/vol1" > "$SUBSYS/namespaces/1/device_path"
echo 1 > "$SUBSYS/namespaces/1/enable"
mkdir -p /sys/kernel/config/nvmet/ports/3
echo loop > /sys/kernel/config/nvmet/ports/3/addr_trtype
ln -sf "$SUBSYS" /sys/kernel/config/nvmet/ports/3/subsystems/

say "connecting via nvme loop"
modprobe nvme_fabrics
nvme connect -t loop -n "$NQN" || fail "nvme connect failed"
sleep 1
nvme list | grep -q "$NQN" || nvme list-subsys | grep -q "$NQN" || fail "connected subsystem not visible"
nvme disconnect -n "$NQN" >/dev/null

say "Soft-RoCE RDMA port bind (the green-dot precondition)"
modprobe rdma_rxe nvmet_rdma 2>/dev/null || fail "rdma modules unavailable (linux-modules-extra?)"
NETDEV=$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$NETDEV" ] || fail "no default-route netdev found"
rdma link add rxe-smoke type rxe netdev "$NETDEV" 2>/dev/null || true
ADDR=$(ip -o -4 addr show dev "$NETDEV" | head -1 | sed -n 's/.*inet \([0-9.]*\).*/\1/p')
mkdir -p /sys/kernel/config/nvmet/ports/1
echo ipv4 > /sys/kernel/config/nvmet/ports/1/addr_adrfam
echo "$ADDR" > /sys/kernel/config/nvmet/ports/1/addr_traddr
echo 4420 > /sys/kernel/config/nvmet/ports/1/addr_trsvcid
echo rdma > /sys/kernel/config/nvmet/ports/1/addr_trtype
# This symlink is where nvmet binds the RDMA listener; it failing without
# usable RDMA is what makes "linked" mean "listening".
ln -sf "$SUBSYS" /sys/kernel/config/nvmet/ports/1/subsystems/ \
    || fail "RDMA port bind failed over rxe"
echo "RDMA bind OK on $ADDR (rxe over $NETDEV)"
rm -f "/sys/kernel/config/nvmet/ports/1/subsystems/$NQN"
rmdir /sys/kernel/config/nvmet/ports/1

say "LIO iSER portal write"
if modprobe target_core_mod iscsi_target_mod ib_isert 2>/dev/null; then
    IQN=iqn.2026-06.io.greendot:smoke
    mkdir -p "/sys/kernel/config/target/iscsi/$IQN/tpgt_1/np/$ADDR:3260"
    if echo 1 > "/sys/kernel/config/target/iscsi/$IQN/tpgt_1/np/$ADDR:3260/iser"; then
        echo "iSER portal enable OK"
    else
        echo "WARN: iser write failed (acceptable: dot stays yellow)"
    fi
    rmdir "/sys/kernel/config/target/iscsi/$IQN/tpgt_1/np/$ADDR:3260" \
          "/sys/kernel/config/target/iscsi/$IQN/tpgt_1" \
          "/sys/kernel/config/target/iscsi/$IQN" 2>/dev/null || true
else
    echo "WARN: iSCSI/iSER modules unavailable, skipping"
fi

say "smoke test passed"
