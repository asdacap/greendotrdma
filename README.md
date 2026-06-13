# GreenDotRDMA

A small storage-appliance web UI for Ubuntu Server: expose ZFS zvols and
partitions over **NVMe-oF** and **iSCSI**, and know at a glance whether each
export is actually served via **RDMA** — that's the green dot.

- 🟢 green — initiators reach this export over RDMA (NVMe/RDMA or iSER)
- 🟡 yellow — serving, but TCP only (with the reason why RDMA isn't active)
- 🔴 red — not serving (with the reason)

Also on board: ZFS zvol management, GPT partitioning, scheduled snapshots
with retention, live + historical traffic charts, a Prometheus `/metrics`
endpoint, and one-click Soft-RoCE so any NIC can do real RDMA.

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

For end-to-end verification use a disposable Ubuntu VM (no RDMA hardware
needed — Soft-RoCE provides real RDMA semantics on any NIC):

```sh
sudo scripts/smoke.sh
```

For a full two-machine test, run a second VM and connect with
`nvme connect -t rdma -a <target-ip> -s 4420 -n <nqn>` (package
`nvme-cli`, modules `nvme_rdma` + `rdma_rxe` with an rxe link on the
client side too), or `iscsiadm` with `iface.transport_name = iser`.
