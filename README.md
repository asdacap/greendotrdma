# GreenDotRDMA

A small storage-appliance web UI for Ubuntu Server: expose ZFS zvols and
partitions over **NVMe-oF** and **iSCSI**, and know at a glance whether each
export is actually served via **RDMA** — that's the green dot.

- 🟢 green — initiators reach this export over RDMA (NVMe/RDMA or iSER)
- 🟡 yellow — serving, but TCP only (with the reason why RDMA isn't active)
- 🔴 red — not serving (with the reason)

Also on board: ZFS zvol management, LVM volume management (volume groups and
linear + thin logical volumes), GPT partitioning, scheduled snapshots with
retention, live + historical traffic charts, a Prometheus `/metrics` endpoint,
and one-click Soft-RoCE so any NIC can do real RDMA.

Every privileged operation runs as a recorded **task** — a real CLI command
(`zfs`, `sfdisk`, `modprobe`, `rdma`, `targetctl`, `apt-get`) or, for NVMe-oF, a
direct configfs write — with its output, exit status, and a live stream, all
visible on a central **Tasks** page. NVMe-oF state is written straight to the
kernel's nvmet configfs tree (no external tool); iSCSI state is applied by
rendering the desired config and running the official `targetctl` restore. If a
required CLI is missing its task fails with an install hint, and a one-click
**Install missing** action (itself a task) installs the packages. The typed
allowlist in the root helper still bounds exactly which commands can run.

## Architecture

Two systemd services:

- **greendot-web** — the UI (Rust, axum + htmx). Runs as the unprivileged
  `greendot` user. Reads all system state directly (configfs, /sys, `zfs
  list`); desired state lives in SQLite and is reconciled to the kernel at
  startup and every minute.
- **greendot-helper** — a small root daemon owning every privileged
  operation. The wire protocol's request enum *is* the allowlist; every
  string that becomes a path or argv element is a validated newtype, checked
  again on deserialization. Only the `greendot` uid may connect
  (SO_PEERCRED). It also runs the PAM login check.

Log in with any system account that is a member of the **greendot-admin**
group:

```sh
sudo usermod -aG greendot-admin <user>
```

## Building the package

```sh
cargo build --release --workspace
cargo deb -p greendot-web --no-build
sudo apt install ./target/debian/greendotrdma_*.deb
```

Then browse to `https://<host>:8443/` (self-signed certificate generated at
install time; config in `/etc/greendotrdma/config.toml`).

Kernel modules (`nvmet`, `nvmet-rdma`, `iscsi_target_mod`, `ib_isert`,
`rdma_rxe`, ...) are loaded on demand; on Ubuntu cloud kernels they live in
`linux-modules-extra-$(uname -r)`.

## Development

A nix dev shell is provided (`nix develop`). Tests, lints:

```sh
cargo test --workspace
cargo clippy --all-targets -- -D warnings
```

Everything privileged is testable without hardware: configfs writers run
against tempdir trees, command execution is recorded and asserted as argv,
and the web tests talk to a fake helper over a real unix socket.

### Automated VM tests

The flake boots real NixOS VMs and drives the whole stack against a live
kernel — ZFS, nvmet/LIO configfs, and Soft-RoCE — fully headless.

**Single-node (loopback):**

```sh
nix build .#checks.x86_64-linux.vmTest -L
```

It creates a zpool and zvol, logs in through PAM (asserting that a non-admin
system user and a wrong password are both rejected), creates an NVMe-oF
export over RDMA via the web API, checks the dashboard shows it **green**,
then runs `nvme connect -t rdma` against the VM's *own* address to prove the
dot is honest, verifies the Prometheus `greendot_export_status` gauge, and
confirms disabling the export reconciles the subsystem back out of configfs.

**Two-node (cross-host RDMA):**

```sh
nix build .#checks.x86_64-linux.vmTestTwoNode -L
```

This is the honest version: a **target** VM serves an NVMe-oF export *and* an
iSCSI export over Soft-RoCE, and a **separate initiator** VM reaches both
across the test LAN — `nvme connect -t rdma` for NVMe/RDMA and
`iscsiadm ... -I iser` for iSER — proving RDMA between two hosts, not loopback.

### Ubuntu VM test

Since the product ships as a `.deb`, a full real-Ubuntu test builds the
package, boots a real Ubuntu Server cloud image under qemu, installs it, and
runs the green-dot flow + a real `nvme connect -t rdma` on the Ubuntu kernel —
exercising the packaging, the patchelf loader retargeting, the postinst
(user/group/cert/units), and Ubuntu's module stack:

```sh
nix run .#ubuntuVmTest
```

This one is **not** part of `nix flake check`: it downloads an Ubuntu cloud
image and apt packages (non-hermetic) and wants KVM (falls back to slow TCG).

The `.deb` deliberately does **not** depend on the storage/RDMA CLIs (`zfs`,
`nvme`, `targetctl`, …) — the app detects whichever are missing and offers a
one-click install. The test installs the package first (proving that), then
provisions those CLIs. NVMe-oF needs no CLI at all: the helper writes its nvmet
configfs tree directly, which is also why no `nvmetcli` package is required
(handy, since Ubuntu 26.04 dropped it).

### Manual smoke test

On a disposable VM (no RDMA hardware needed — Soft-RoCE gives real RDMA on
any NIC):

```sh
sudo scripts/smoke.sh
```
