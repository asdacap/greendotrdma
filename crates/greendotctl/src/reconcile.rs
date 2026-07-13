//! The desired-state reconcile driver and the `greendotctl reconcile
//! [config.toml]` subcommand. Reconcile runs everything inline, in-process —
//! the render/diff comes from `crate::render`, the applies are this crate's
//! own — so the *caller* supplies the privilege: the daemon runs
//! [`run`] on the `Reconcile` rpc (the path greendot-web takes), and the
//! standalone subcommand proxies to a running daemon or, given an explicit
//! config (or no daemon), applies locally as root.

use crate::cmd::EventSink;
use crate::render::{
    NicAction, foreign_port_ids, iscsi_modules, lio_satisfied, nfs_modules, nfs_satisfied,
    nic_actions, nic_satisfied, nvme_modules, nvmet_satisfied, render_issues, render_lio,
    render_nfs, render_nvmet,
};
use crate::{cmd, hardware, lio, modules, nfs, nvmet};
use anyhow::Result;
use greendot_proto::actual::nfs::from_report;
use greendot_proto::actual::nic::{NicNetwork, NicStatus};
use greendot_proto::config::Config;
use greendot_proto::{NFS_RDMA_PORT, SubStatus, SubTask, Task, TaskEvent, pb};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

/// The sysfs class root for RDMA devices (the classification's `ib_root`).
const IB_ROOT: &str = "/sys/class/infiniband";

/// The live NIC state reconcile diffs desired NIC config against: per-NIC
/// network config (`ip -j addr`/`route`, for MTU) and the structural RDMA
/// classification (sysfs + the vendor RoCE-capable verdict, for RoCE gating).
/// Mirrors the `NicNetwork` and `NicInterfaces` read ops so reconcile and the
/// web see one model; combined here so a pass takes a single read.
fn read_live_nics() -> (Vec<NicNetwork>, Vec<NicStatus>) {
    let networks = greendot_proto::actual::nic::networks_from_json(
        &crate::exec::run_ip(&["-j", "addr"]),
        &crate::exec::run_ip(&["-j", "route", "show", "default"]),
    );
    let roce_hw: HashMap<String, String> = hardware::roce_capable(Path::new(hardware::NET_ROOT))
        .into_iter()
        .map(|(netdev, vendor)| (netdev, vendor.to_owned()))
        .collect();
    let netdev_addrs = crate::actual::rdma::netdev_addrs();
    let statuses = crate::actual::nic::classify(
        Path::new(hardware::NET_ROOT),
        Path::new(IB_ROOT),
        &netdev_addrs,
        &roce_hw,
    );
    (networks, statuses)
}

/// Applies each NIC action as its own subtask — an MTU set, a Soft-RoCE link
/// add, or the vendor hardware-RoCE enable — reusing the exact code the one-shot
/// `SetMtu`/`RxeAdd`/`EnableRoce` ops run, so a mixed pass shows one line per
/// change. A satisfied config emits a single grey `Skipped` subtask, matching
/// the export areas. `Err` is only a sink failure; domain failures fold into the
/// task aggregate as failed subtasks.
fn apply_nic(task: &mut Task, actions: &[NicAction]) -> io::Result<()> {
    if actions.is_empty() {
        task.skipped_subtask("Apply NIC configuration");
        return Ok(());
    }
    for act in actions {
        match act {
            NicAction::SetMtu(netdev, mtu) => {
                let mut sub = task.begin_subtask(format!("Set MTU {mtu} on {netdev}"));
                let status = cmd::run_into(&mut sub, &crate::net::set_mtu(netdev, *mtu))?;
                sub.complete(status);
            }
            NicAction::AddRxe(netdev) => modules::rxe_add(task, netdev)?,
            NicAction::EnableRoce(netdev) => {
                let mut sub = task.begin_subtask(format!("Enable RoCE on {netdev}"));
                let status =
                    hardware::enable_into(Path::new(hardware::NET_ROOT), netdev, &mut sub)?;
                sub.complete(status);
            }
        }
    }
    Ok(())
}

/// Runs the `reconcile` subcommand and exits with status 1 if any step failed.
/// With no explicit config it prefers a running daemon — proxying
/// the `Reconcile` rpc over its socket, so an unprivileged caller can heal
/// drift and the daemon's mutate lock keeps every privileged task serialized.
/// With an explicit config, or no daemon, it applies in-process, which needs
/// root (the daemon reconciles only against its own `--config`, so a custom
/// config cannot be pushed through the socket).
pub fn cli(cfg_path: Option<String>) -> Result<()> {
    if cfg_path.is_none() {
        let socket = Config::default().helper_socket;
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            return proxy(socket);
        }
    }
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!(
            "standalone reconcile applies everything in-process and must run as \
             root (an unprivileged `greendotctl reconcile` needs the daemon running)"
        );
    }
    let mut sink = StdoutSink;
    let mut task = Task::new(&mut sink);
    run(cfg_path, &Mutex::new(()), &mut task)?;
    let ok = task.aggregate() != SubStatus::Failed;
    task.complete()?;
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// Asks the running daemon to reconcile (inline, against its own config) and
/// mirrors the streamed task to stdout/stderr, exiting 1 on a failed pass —
/// the same outcome surface as the standalone path.
fn proxy(socket: std::path::PathBuf) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut client = greendot_proto::client::connect_uds(socket)?;
        let mut stream = client.reconcile(pb::Reconcile {}).await?.into_inner();
        let mut sink = StdoutSink;
        let mut failed = false;
        while let Some(ev) = stream.message().await? {
            let ev = TaskEvent::try_from(ev)?;
            failed |= matches!(
                ev,
                TaskEvent::Finished {
                    status: SubStatus::Failed,
                    ..
                }
            );
            sink.emit(ev)?;
        }
        if failed {
            std::process::exit(1);
        }
        Ok(())
    })
}

/// The web's cheap drift pre-check (`ReconcileDryRun`): the per-area
/// drift-satisfied flags, *without applying* and without the mutate lock. A
/// config/desired read error reports drift on all areas, so the web then
/// dispatches a real `Reconcile` that surfaces it. The NIC flag is what makes an
/// MTU/RoCE-only drift (no export drift) still trigger a reconcile — otherwise a
/// reboot with satisfied exports would skip re-applying NIC config.
pub fn drift(cfg_path: Option<String>) -> (bool, bool, bool, bool) {
    let Ok(cfg) = Config::load(cfg_path) else {
        return (false, false, false, false);
    };
    let Ok(desired) = greendot_proto::desired::read_desired(&cfg.state_path) else {
        return (false, false, false, false);
    };
    let pci_addrs = crate::actual::nic::pci_addrs();
    let actual_nvmet = crate::actual::nvmet::read(&cfg.nvmet_root);
    let nvmet_desired = render_nvmet(
        &desired.nvme_exports,
        desired.listen,
        &pci_addrs,
        &foreign_port_ids(&actual_nvmet),
    );
    let nvmet_ok = nvmet_satisfied(&nvmet_desired, &actual_nvmet);
    let lio_ok = lio_satisfied(
        &render_lio(&desired.iscsi_exports, desired.listen, &pci_addrs),
        &crate::actual::lio::read(&cfg.lio_root),
    );
    let nfs_actual = from_report(&nfs::report(
        Path::new(nfs::NFSD_PORTLIST),
        Path::new(nfs::NFS_EXPORTS_FILE),
    ));
    let nfs_ok = nfs_satisfied(
        &render_nfs(&desired.nfs_exports, NFS_RDMA_PORT),
        &nfs_actual,
    );
    let (nic_networks, nic_statuses) = read_live_nics();
    let nic_ok = nic_satisfied(&desired.nic_configs, &nic_networks, &nic_statuses);
    (nvmet_ok, lio_ok, nfs_ok, nic_ok)
}

/// Reconciles desired → actual wholly in this (root) process, streaming each
/// area as its own subtask on `task` — applied when drifted, a grey `Skipped`
/// subtask when already satisfied, so a run that only touched one area shows
/// the rest greyed rather than silently absent. Loads the config itself, so
/// every entry point (daemon and CLI) reports a bad config the same way: as a
/// failed `Load config` subtask. The whole pass holds `mutate_lock` so no
/// other task interleaves. Domain failures fold into the task aggregate as
/// failed subtasks; `Err` is only a sink error (the client hung up).
pub fn run(cfg_path: Option<String>, mutate_lock: &Mutex<()>, task: &mut Task) -> io::Result<()> {
    let cfg = match Config::load(cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            task.begin_subtask("Load config").fail(format!("{e:#}"));
            return Ok(());
        }
    };
    let _guard = mutate_lock.lock().unwrap();
    let desired = match greendot_proto::desired::read_desired(&cfg.state_path) {
        Ok(d) => d,
        Err(e) => {
            task.begin_subtask("Read desired state")
                .fail(format!("{e:#}"));
            return Ok(());
        }
    };
    // Surface entries the renderers must skip — an invalid export would
    // otherwise be silently absent from the applies: never served, no error.
    let issues = render_issues(
        &desired.nvme_exports,
        &desired.iscsi_exports,
        &desired.nfs_exports,
    );
    if !issues.is_empty() {
        let mut sub = task.begin_subtask("Validate desired state");
        for issue in &issues {
            writeln!(sub.stderr(), "{issue}")?;
        }
        sub.fail(format!(
            "{} desired-state entr{} cannot be served as configured",
            issues.len(),
            if issues.len() == 1 { "y" } else { "ies" }
        ));
    }
    let pci_addrs = crate::actual::nic::pci_addrs();
    let actual_nvmet = crate::actual::nvmet::read(&cfg.nvmet_root);
    let nvmet_desired = render_nvmet(
        &desired.nvme_exports,
        desired.listen,
        &pci_addrs,
        &foreign_port_ids(&actual_nvmet),
    );
    let lio_desired = render_lio(&desired.iscsi_exports, desired.listen, &pci_addrs);
    let nfs_desired = render_nfs(&desired.nfs_exports, NFS_RDMA_PORT);
    let nvmet_ok = nvmet_satisfied(&nvmet_desired, &actual_nvmet);
    let lio_ok = lio_satisfied(&lio_desired, &crate::actual::lio::read(&cfg.lio_root));
    // We are root, so the NFS actual state reads in-process; a failed read
    // parses as the empty state, which registers as drift and re-applies NFS.
    let nfs_actual = from_report(&nfs::report(
        Path::new(nfs::NFSD_PORTLIST),
        Path::new(nfs::NFS_EXPORTS_FILE),
    ));
    let nfs_ok = nfs_satisfied(&nfs_desired, &nfs_actual);
    // NIC config (MTU + Soft-RoCE/RoCE enablement) re-applied so it survives a
    // reboot; the actions are gated on live classification so a realized NIC is
    // never re-touched.
    let (nic_networks, nic_statuses) = read_live_nics();
    let nic_acts = nic_actions(&desired.nic_configs, &nic_networks, &nic_statuses);
    tracing::info!(
        nvme = desired.nvme_exports.len(),
        iscsi = desired.iscsi_exports.len(),
        nfs = desired.nfs_exports.len(),
        nic = desired.nic_configs.len(),
        nvmet_ok,
        lio_ok,
        nfs_ok,
        nic_ok = nic_acts.is_empty(),
        "reconcile pass"
    );

    let mut wanted = nvme_modules(&desired.nvme_exports);
    wanted.extend(iscsi_modules(&desired.iscsi_exports));
    wanted.extend(nfs_modules(&desired.nfs_exports));

    // `autoload_modules = false` greys the area out rather than dropping it,
    // so a pass that then fails on a missing transport points at the setting.
    area(
        task,
        !cfg.autoload_modules || wanted.is_empty(),
        "Load kernel modules",
        |sub| {
            let nics = crate::hardware::rdma_driver_modules(Path::new(crate::hardware::NET_ROOT));
            match modules::ensure(&wanted, &nics) {
                Some(spec) => cmd::run_into(sub, &spec),
                // Nothing to load once deduplicated.
                None => Ok(SubStatus::Success),
            }
        },
    )?;
    area(task, nvmet_ok, "Apply NVMe-oF configuration", |sub| {
        nvmet::apply(&nvmet_desired, Path::new(nvmet::NVMET_ROOT), sub)
    })?;
    area(task, lio_ok, "Apply iSCSI configuration", |sub| {
        cmd::run_into(sub, &lio::apply_spec(&lio_desired))
    })?;
    area(task, nfs_ok, "Apply NFS configuration", |sub| {
        nfs::apply(
            &nfs_desired,
            Path::new(nfs::NFS_EXPORTS_FILE),
            Path::new(nfs::NFSD_PORTLIST),
            sub,
        )
    })?;
    apply_nic(task, &nic_acts)
}

/// One reconcile area: a grey `Skipped` subtask when already satisfied,
/// otherwise `apply` runs inside a subtask labelled `label` and completes it
/// with the applied status.
fn area(
    task: &mut Task,
    satisfied: bool,
    label: &str,
    apply: impl FnOnce(&mut SubTask) -> io::Result<SubStatus>,
) -> io::Result<()> {
    if satisfied {
        task.skipped_subtask(label);
    } else {
        let mut sub = task.begin_subtask(label);
        let status = apply(&mut sub)?;
        sub.complete(status);
    }
    Ok(())
}

/// Prints streamed task events for the human running the standalone
/// subcommand: subtask names as headers, output passthrough, and the statuses
/// that would otherwise be invisible (skips and the terminal failure).
struct StdoutSink;

impl EventSink for StdoutSink {
    fn emit(&mut self, ev: TaskEvent) -> io::Result<()> {
        match ev {
            TaskEvent::SubtaskStarted { name, .. } => println!("== {name} =="),
            TaskEvent::Stdout { data } => print!("{data}"),
            TaskEvent::Stderr { data } => eprint!("{data}"),
            TaskEvent::SubtaskFinished {
                status: SubStatus::Skipped,
                ..
            } => println!("already satisfied"),
            TaskEvent::Finished {
                status: SubStatus::Failed,
                error,
            } => eprintln!("{}", error.as_deref().unwrap_or("reconcile failed")),
            _ => {}
        }
        Ok(())
    }
}
