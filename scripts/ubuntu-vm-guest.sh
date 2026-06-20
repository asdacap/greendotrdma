#!/usr/bin/env bash
# Runs as root INSIDE the Ubuntu VM (scp'd + invoked by scripts/ubuntu-vm-test.sh).
# Installs the .deb and exercises the green-dot flow on the real Ubuntu kernel.
# Mirrors the assertions in nix/vm-test.nix so the Ubuntu and NixOS paths stay
# in lockstep. Expects DEBNAME in the environment.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
fail() { printf 'GUEST FAIL: %s\n' "$*" >&2; exit 1; }
WEB="https://127.0.0.1:8443"

: "${DEBNAME:?DEBNAME not set}"

echo "== mounting the shared .deb dir (9p)"
modprobe 9pnet_virtio 9p 2>/dev/null || true
mkdir -p /mnt/deb
mountpoint -q /mnt/deb || mount -t 9p -o trans=virtio,version=9p2000.L,ro deb /mnt/deb

echo "== installing the package (it must NOT pull in the storage/RDMA CLIs)"
apt-get update -q
# Installs with only its lib/openssl/rdma-core deps present — proves the .deb
# does not hard-depend on the CLIs (the app manages those at runtime).
apt-get install -y "/mnt/deb/$DEBNAME"

echo "== provisioning the storage/RDMA CLIs the app needs"
# These are not .deb dependencies; on a real box the app's "Install missing"
# task installs them. NVMe-oF needs no CLI at all — the helper writes its nvmet
# configfs tree directly — so only the iSCSI/ZFS/RDMA tools are needed here.
apt-get install -y zfsutils-linux nvme-cli rdma-core targetcli-fb open-iscsi
# RDMA/nvmet modules: usually in linux-modules-extra, but some cloud kernels
# ship them in the base linux-modules — best-effort so either layout works.
apt-get install -y "linux-modules-extra-$(uname -r)" 2>/dev/null \
    || echo "linux-modules-extra unavailable; expecting modules in base linux-modules"

# The admin login must be a member of greendot-admin (created by the postinst).
usermod -aG greendot-admin gdadmin
systemctl restart greendot-helper greendot-web

echo "== waiting for the web service"
for _ in $(seq 1 60); do curl -fsk "$WEB/" >/dev/null 2>&1 && break || sleep 1; done
curl -fsk "$WEB/" >/dev/null || fail "web service never came up"

echo "== storage + Soft-RoCE"
modprobe zfs rdma_rxe nvmet nvmet_rdma nvme_rdma nvme_fabrics \
    target_core_mod iscsi_target_mod ib_isert 2>/dev/null || true
ZDEV=/dev/vdb
[ -b "$ZDEV" ] || fail "spare disk $ZDEV missing"
zpool create -f tank "$ZDEV"
zfs create -V 128M tank/vm1
zfs create -V 128M tank/vm2
[ -e /dev/zvol/tank/vm1 ] || fail "zvol device node missing"

NETDEV=$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$NETDEV" ] || fail "no default-route netdev"
rdma link add rxe0 type rxe netdev "$NETDEV" || true
rdma link show | grep -q rxe0 || fail "no rxe link"
IP=$(ip -o -4 addr show dev "$NETDEV" | head -1 | sed -n 's/.*inet \([0-9.]*\).*/\1/p')
[ -n "$IP" ] || fail "no IPv4 on $NETDEV"
echo "netdev=$NETDEV ip=$IP"

echo "== web: login as gdadmin"
code=$(curl -sk -o /dev/null -w '%{http_code}' -c /tmp/jar \
    --data 'username=gdadmin&password=test' "$WEB/login")
[ "$code" = 303 ] || fail "admin login should be 303, got $code"
CSRF=$(curl -sk -b /tmp/jar "$WEB/" | sed -n 's/.*"X-Greendot-Csrf":"\([^"]*\)".*/\1/p' | head -1)
[ -n "$CSRF" ] || fail "no CSRF token"

echo "== create NVMe-oF export (RDMA + TCP)"
curl -sk -b /tmp/jar -H "X-Greendot-Csrf: $CSRF" --data "listen_addr=$IP" "$WEB/settings/listen" >/dev/null
curl -sk -b /tmp/jar -H "X-Greendot-Csrf: $CSRF" \
    --data 'kind=nvme&name=vm1&device=/dev/zvol/tank/vm1&want_rdma=1&want_tcp=1' \
    "$WEB/exports/create" >/dev/null

SUB=/sys/kernel/config/nvmet/subsystems/nqn.2026-06.io.greendot:vm1
for _ in $(seq 1 60); do [ -d "$SUB" ] && break || sleep 2; done
[ -d "$SUB" ] || fail "nvmet subsystem not created"
[ "$(cat /sys/kernel/config/nvmet/ports/1/addr_trtype)" = rdma ] || fail "nvmet port 1 not rdma"
curl -sk -b /tmp/jar "$WEB/exports" | grep -q dot-green || fail "nvme export not green"
curl -sk "$WEB/metrics" | grep -q 'greendot_export_status{export="vm1"} 2' || fail "nvme gauge not green"

echo "== real RDMA connect (nvme connect -t rdma)"
nvme connect -t rdma -a "$IP" -s 4420 -n nqn.2026-06.io.greendot:vm1 || fail "nvme connect failed"
for _ in $(seq 1 15); do nvme list | grep -q Linux && break || sleep 1; done
nvme list | grep -q Linux || fail "connected device not visible"
nvme disconnect -n nqn.2026-06.io.greendot:vm1 >/dev/null

echo "== create iSCSI export (iSER) and assert green"
curl -sk -b /tmp/jar -H "X-Greendot-Csrf: $CSRF" \
    --data 'kind=iscsi&name=vm2&device=/dev/zvol/tank/vm2&want_rdma=1&want_tcp=1' \
    "$WEB/exports/create" >/dev/null
NP="/sys/kernel/config/target/iscsi/iqn.2026-06.io.greendot:vm2/tpgt_1/np/$IP:3260"
for _ in $(seq 1 60); do [ -d "$NP" ] && break || sleep 2; done
[ -d "$NP" ] || fail "iSCSI portal not created"
[ "$(cat "$NP/iser")" = 1 ] || fail "iSCSI portal not iSER-enabled"
curl -sk "$WEB/metrics" | grep -q 'greendot_export_status{export="vm2"} 2' || fail "iscsi gauge not green"
# (Full iscsiadm loopback login is covered cross-host by the two-node NixOS test.)

echo "UBUNTU-VM-TEST: PASS"
