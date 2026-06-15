#!/usr/bin/env bash
# Full real-kernel Ubuntu VM test.
#
# Builds the .deb (scripts/build-deb.sh), boots a real Ubuntu Server cloud image
# under qemu, installs the package, and drives the green-dot flow end to end on
# the real Ubuntu kernel: ZFS zvol -> NVMe-oF export over Soft-RoCE -> green dot
# via the web API, a real `nvme connect -t rdma`, and an iSCSI/iSER export. This
# is what the NixOS VM test cannot cover: packaging, the patchelf loader
# retargeting, the postinst (user/group/cert/units), and the Ubuntu kernel.
#
# NON-HERMETIC: downloads an Ubuntu cloud image and apt packages; wants KVM
# (falls back to slow TCG). Run from the repo root:
#
#   nix run .#ubuntuVmTest          # deps provided by the flake app
#   # or, with qemu/cloud-utils/openssh on PATH:
#   scripts/ubuntu-vm-test.sh
#
# Env overrides: UBUNTU_IMG_URL, SSHPORT, SKIP_BUILD=1, DEB=<path>, KEEP=1
set -euo pipefail

err() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

[ -f Cargo.toml ] && [ -f scripts/build-deb.sh ] || err "run from the repo root"

UBUNTU_IMG_URL=${UBUNTU_IMG_URL:-https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img}
SSHPORT=${SSHPORT:-2222}
WORK=.tmp/ubuntu-vm-test
mkdir -p "$WORK"

# --- 1. build (or reuse) the .deb -------------------------------------------
if [ -n "${DEB:-}" ]; then
    DEB=$(realpath "$DEB")
elif [ -n "${SKIP_BUILD:-}" ] && DEB=$(ls -1 target/debian/greendotrdma_*.deb 2>/dev/null | head -1); then
    DEB=$(realpath "$DEB")
else
    say "building the .deb"
    nix develop --command scripts/build-deb.sh
    DEB=$(realpath "$(ls -1 target/debian/greendotrdma_*.deb | head -1)")
fi
[ -f "$DEB" ] || err "no .deb found"
DEBDIR=$(dirname "$DEB")
DEBNAME=$(basename "$DEB")
echo "using deb: $DEB"

# --- 2. image, overlay, spare disk, ssh key ---------------------------------
say "preparing disk images"
BASE="$WORK/base.img"
[ -f "$BASE" ] || wget -O "$BASE" "$UBUNTU_IMG_URL"
OVERLAY="$WORK/overlay.qcow2"
rm -f "$OVERLAY"
qemu-img create -f qcow2 -F qcow2 -b "$(realpath "$BASE")" "$OVERLAY" 20G >/dev/null
DISK2="$WORK/disk2.img"
rm -f "$DISK2"
qemu-img create -f raw "$DISK2" 2G >/dev/null

KEY="$WORK/id"
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -f "$KEY" -q
PUBKEY=$(cat "$KEY.pub")

# --- 3. cloud-init seed -----------------------------------------------------
say "building cloud-init seed"
cat > "$WORK/meta-data" <<EOF
instance-id: greendot-ubuntu
local-hostname: greendot-ubuntu
EOF
cat > "$WORK/user-data" <<EOF
#cloud-config
ssh_pwauth: false
users:
  - name: gdadmin
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - $PUBKEY
chpasswd:
  expire: false
  users:
    - name: gdadmin
      password: test
      type: text
EOF
cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

# --- 4. boot qemu (KVM if available, else TCG) ------------------------------
say "booting Ubuntu VM (ssh on 127.0.0.1:$SSHPORT)"
if [ -w /dev/kvm ]; then ACCEL=(-enable-kvm -cpu host); else ACCEL=(-cpu max); echo "no KVM: using slow TCG"; fi
PIDFILE="$WORK/qemu.pid"
SERIAL="$WORK/serial.log"
rm -f "$PIDFILE" "$SERIAL"
qemu-system-x86_64 \
    -name greendot-ubuntu \
    -m 4096 -smp 4 "${ACCEL[@]}" \
    -drive file="$OVERLAY",if=virtio \
    -drive file="$DISK2",if=virtio,format=raw \
    -drive file="$WORK/seed.iso",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp::"$SSHPORT"-:22 \
    -device virtio-net-pci,netdev=net0 \
    -virtfs local,path="$DEBDIR",mount_tag=deb,security_model=none,readonly=on \
    -display none -serial "file:$SERIAL" \
    -daemonize -pidfile "$PIDFILE"

cleanup() {
    [ -n "${KEEP:-}" ] && { echo "KEEP set; leaving VM running (pid $(cat "$PIDFILE" 2>/dev/null || echo ?))"; return; }
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
}
trap cleanup EXIT

SSHOPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
         -o ConnectTimeout=5 -o LogLevel=ERROR -p "$SSHPORT" -i "$KEY")

say "waiting for ssh (cloud-init may take a few minutes)"
for i in $(seq 1 120); do
    ssh "${SSHOPTS[@]}" gdadmin@127.0.0.1 true 2>/dev/null && break
    sleep 5
    [ "$i" = 120 ] && err "ssh never came up; see $SERIAL"
done

# --- 5. drive the in-guest provisioning + verification ----------------------
# Feed the guest script over ssh stdin (no scp, so no -p/-P portability traps).
say "provisioning + verifying inside the VM"
if ssh "${SSHOPTS[@]}" gdadmin@127.0.0.1 "sudo DEBNAME='$DEBNAME' bash -s" < scripts/ubuntu-vm-guest.sh; then
    say "UBUNTU VM TEST PASSED"
else
    err "in-guest verification failed (see output above and $SERIAL)"
fi
