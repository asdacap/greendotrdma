#!/usr/bin/env bash
# Install the greendotrdma .deb in a clean Ubuntu container and assert that the
# maintainer scripts run cleanly.
#
# The NixOS VM tests (nix/vm-test*.nix) build a NixOS module and never touch the
# .deb, so the whole Debian packaging path is otherwise untested: cargo-deb's
# #DEBHELPER# expansion, systemd-sysusers/tmpfiles, unit enablement and the
# self-signed cert generation in pkg/debian/postinst. A shell bug there (e.g. a
# stray `#DEBHELPER#` inside a comment expanding into a broken command) sails
# through cargo test and the VM tests but fails on a real `apt install`. This
# test closes that gap on the same Ubuntu release the deploy box runs (26.04).
#
# Requires docker access: run under `sudo`, or be in the `docker` group. Build
# the .deb first with scripts/build-deb.sh; this script builds it when missing.
#
#   TEST_IMAGE=ubuntu:24.04 scripts/test-deb-docker.sh   # override the release
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${TEST_IMAGE:-ubuntu:26.04}"
DEB_DIR="target/debian"

DEB=$(ls -1 "$DEB_DIR"/greendotrdma_*_amd64.deb 2>/dev/null | head -1 || true)
if [ -z "$DEB" ]; then
    echo "== no .deb found, building"
    scripts/build-deb.sh
    DEB=$(ls -1 "$DEB_DIR"/greendotrdma_*_amd64.deb | head -1)
fi

DOCKER=docker
if ! docker info >/dev/null 2>&1; then DOCKER="sudo docker"; fi

echo "== testing $(basename "$DEB") in $IMAGE"

$DOCKER run --rm -v "$PWD/$DEB_DIR:/debs:ro" "$IMAGE" bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # The postinst calls systemd-sysusers/systemd-tmpfiles directly; a real
    # Ubuntu server has the systemd package. It is never started as PID 1 here,
    # so the daemons themselves are not launched inside the container.
    apt-get install -y -qq systemd >/dev/null

    echo "--- installing package (exit code IS the primary assertion)"
    apt-get install -y /debs/greendotrdma_*_amd64.deb

    echo "--- asserting postinst side effects"
    fail=0
    check() { if eval "$2"; then echo "  ok  : $1"; else echo "  FAIL: $1"; fail=1; fi; }

    W=/etc/systemd/system/multi-user.target.wants
    check "greendot user created"        "id greendot >/dev/null 2>&1"
    check "greendot-admin group created" "getent group greendot-admin >/dev/null"
    check "greendot-csi user created"    "id greendot-csi >/dev/null 2>&1"
    check "web unit installed"           "test -f /lib/systemd/system/greendot-web.service"
    check "greendotctl unit installed"   "test -f /lib/systemd/system/greendotctl.service"
    check "web unit enabled"             "test -L $W/greendot-web.service"
    check "greendotctl unit enabled"     "test -L $W/greendotctl.service"
    check "runtime dir created"          "test -d /var/lib/greendotrdma"
    check "tls cert generated"           "test -f /etc/greendotrdma/cert.pem"
    check "tls key generated"            "test -f /etc/greendotrdma/key.pem"
    check "config installed"             "test -f /etc/greendotrdma/config.toml"

    # A reinstall exercises the upgrade path (postinst $1=configure with $2 set,
    # and the greendot-helper -> greendotctl migration branch).
    echo "--- reinstalling to exercise the upgrade path"
    apt-get install -y --reinstall /debs/greendotrdma_*_amd64.deb

    exit $fail
'
echo "== PASS: $(basename "$DEB") installs cleanly on $IMAGE"
