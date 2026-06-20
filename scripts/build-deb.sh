#!/usr/bin/env bash
# Build a deployable .deb from NixOS.
#
# The flake's toolchain links binaries against the nix store (the ELF
# interpreter and rpath point at /nix/store/...), which does not exist on
# Ubuntu. We retarget both binaries onto Ubuntu's standard loader and strip
# the nix rpath so they resolve libc6/libpam0g/libgcc-s1/... from Ubuntu's
# normal library path. This is safe because nixpkgs 25.11 builds against an
# older glibc (2.40) than Ubuntu 26.04 ships, and glibc is forward-compatible.
#
# Run inside the dev shell:  nix develop --command scripts/build-deb.sh
# Set DEB_VERSION to override the package version (e.g. from a release tag);
# otherwise the version comes from greendot-web's Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

LOADER=/lib64/ld-linux-x86-64.so.2

echo "== building release workspace"
cargo build --release --workspace

echo "== retargeting binaries onto Ubuntu's loader ($LOADER)"
for bin in greendot-web greendot-helper; do
    patchelf --set-interpreter "$LOADER" --remove-rpath "target/release/$bin"
    echo "   $bin -> $(patchelf --print-interpreter "target/release/$bin"), needs: $(patchelf --print-needed "target/release/$bin" | tr '\n' ' ')"
done

echo "== packaging (cargo deb --no-build)"
if [ -n "${DEB_VERSION:-}" ]; then
    cargo deb -p greendot-web --no-build --deb-version "$DEB_VERSION"
else
    cargo deb -p greendot-web --no-build
fi

echo "== done"
ls -1 target/debian/*.deb
