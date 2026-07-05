//! The desired-state reconcile driver and the `greendotctl reconcile
//! [config.toml]` subcommand. Reconcile runs everything inline, in-process —
//! the render/diff comes from `greendot-reconcile`, the applies are this
//! crate's own — so the *caller* supplies the privilege: the daemon runs
//! [`run`] on `Request::Reconcile` (the path greendot-web takes), and the
//! standalone subcommand refuses to start without root.

use crate::cmd::EventSink;
use crate::dispatch::{self, Ctx, Dispatch};
use crate::{cmd, nfs, nvmet, pam};
use anyhow::Result;
use greendot_proto::{NFS_RDMA_PORT, Request, Response, SubStatus, SubTask, Task, TaskEvent};
use greendot_reconcile::actual::nfs::{ActualNfs, from_report};
use greendot_reconcile::config::Config;
use greendot_reconcile::reconcile::{
    iscsi_modules, lio_satisfied, nfs_modules, nfs_satisfied, nvme_modules, nvmet_satisfied,
    render_lio, render_nfs, render_nvmet,
};
use std::io;
use std::path::Path;

/// Runs the `reconcile` subcommand and exits with status 1 if any step failed.
/// Root-only: the standalone path is for recovery / a daemon-less box; normal
/// drift healing goes through the daemon, which shares one mutate lock with
/// every other privileged task (a separate process cannot).
pub fn cli(cfg_path: Option<String>) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!(
            "greendotctl reconcile applies everything in-process and must run as \
             root (the web reconciles through the daemon instead)"
        );
    }
    let cfg = Config::load(cfg_path)?;
    let ctx = standalone_ctx();
    let mut sink = StdoutSink;
    let mut task = Task::new(&mut sink);
    run(&cfg, &ctx, &mut task)?;
    let ok = task.aggregate() != SubStatus::Failed;
    task.complete()?;
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// A `Ctx` for the standalone subcommand. Reconcile issues no auth requests, so
/// the PAM/admin-group fields are unused defaults; only `mutate_lock` matters.
fn standalone_ctx() -> Ctx {
    Ctx {
        auth: pam::AuthConfig {
            pam_service: "greendotrdma".into(),
            admin_group: "greendot-admin".into(),
        },
        auth_limiter: std::sync::Mutex::new(pam::RateLimiter::new(
            5,
            30.0,
            std::time::Instant::now(),
        )),
        mutate_lock: std::sync::Mutex::new(()),
    }
}

/// Reconciles desired → actual wholly in this (root) process, streaming each
/// area as its own subtask on `task` — applied when drifted, a grey `Skipped`
/// subtask when already satisfied, so a run that only touched one area shows
/// the rest greyed rather than silently absent. Requests still route through
/// `dispatch::plan`, keeping the allowlist identical to the socket path, and
/// the whole pass holds the mutate lock so no other task interleaves. Domain
/// failures fold into the task aggregate as failed subtasks; `Err` is only a
/// sink error (the client hung up). Read-only on the config TOML.
pub fn run(cfg: &Config, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
    let _guard = ctx.mutate_lock.lock().unwrap();
    let desired = match greendot_reconcile::state::read_desired(&cfg.state_path) {
        Ok(d) => d,
        Err(e) => {
            task.begin_subtask("Read desired state")
                .fail(format!("{e:#}"));
            return Ok(());
        }
    };
    let pci_addrs = greendot_reconcile::actual::nic::pci_addrs();
    let nvmet_desired = render_nvmet(&desired.nvme_exports, desired.listen, &pci_addrs);
    let lio_desired = render_lio(&desired.iscsi_exports, desired.listen, &pci_addrs);
    let nfs_desired = render_nfs(&desired.nfs_exports, NFS_RDMA_PORT);
    let nvmet_ok = nvmet_satisfied(
        &nvmet_desired,
        &greendot_reconcile::actual::nvmet::read(&cfg.nvmet_root),
    );
    let lio_ok = lio_satisfied(
        &lio_desired,
        &greendot_reconcile::actual::lio::read(&cfg.lio_root),
    );
    let nfs_ok = nfs_satisfied(&nfs_desired, &nfs_actual());
    tracing::info!(
        nvme = desired.nvme_exports.len(),
        iscsi = desired.iscsi_exports.len(),
        nfs = desired.nfs_exports.len(),
        nvmet_ok,
        lio_ok,
        nfs_ok,
        "reconcile pass"
    );

    let mut modules = nvme_modules(&desired.nvme_exports);
    modules.extend(iscsi_modules(&desired.iscsi_exports));
    modules.extend(nfs_modules(&desired.nfs_exports));
    if modules.is_empty() {
        task.skipped_subtask("Load kernel modules");
    } else {
        step(
            ctx,
            task,
            Request::EnsureModules { modules },
            "Load kernel modules",
        )?;
    }

    if nvmet_ok {
        task.skipped_subtask("Apply NVMe-oF configuration");
    } else {
        let req = Request::NvmetApply {
            desired: nvmet_desired,
        };
        step(ctx, task, req, "Apply NVMe-oF configuration")?;
    }

    if lio_ok {
        task.skipped_subtask("Apply iSCSI configuration");
    } else {
        let req = Request::LioApply {
            desired: lio_desired,
        };
        step(ctx, task, req, "Apply iSCSI configuration")?;
    }

    if nfs_ok {
        task.skipped_subtask("Apply NFS configuration");
    } else {
        let req = Request::NfsApply {
            desired: nfs_desired,
        };
        step(ctx, task, req, "Apply NFS configuration")?;
    }

    Ok(())
}

/// Runs one apply request as a labelled subtask: opens the subtask, applies
/// into it, and completes with the applied status.
fn step(ctx: &Ctx, task: &mut Task, req: Request, label: &str) -> io::Result<()> {
    let mut sub = task.begin_subtask(label);
    let status = apply(ctx, req, &mut sub)?;
    sub.complete(status);
    Ok(())
}

/// Applies one reconcile request into the caller-opened subtask, routed through
/// `dispatch::plan` so the allowlist/validation is identical to the daemon's
/// socket requests. The driver only ever issues `EnsureModules`/`NvmetApply`/
/// `LioApply`/`NfsApply`; [`run`] already holds the mutate lock.
fn apply(ctx: &Ctx, req: Request, sub: &mut SubTask) -> io::Result<SubStatus> {
    match dispatch::plan(ctx, req) {
        // Empty EnsureModules — nothing to load.
        Dispatch::OneShot(Response::Ok) => Ok(SubStatus::Success),
        // EnsureModules (modprobe) and LioApply (targetctl) are commands.
        Dispatch::Task(spec) => cmd::run_into(sub, &spec),
        Dispatch::NvmetApply(desired) => nvmet::apply(&desired, Path::new(nvmet::NVMET_ROOT), sub),
        Dispatch::NfsApply(desired) => nfs::apply(
            &desired,
            Path::new(nfs::NFS_EXPORTS_FILE),
            Path::new(nfs::NFSD_PORTLIST),
            sub,
        ),
        _ => unreachable!("reconcile issues only module/nvmet/lio/nfs applies"),
    }
}

/// Reads the NFS actual state in-process (we are root): `report_into` streams
/// the report into a throwaway capture task and the payload is parsed. A failed
/// read parses as the empty state, which registers as drift and re-applies NFS.
fn nfs_actual() -> ActualNfs {
    let mut cap = CaptureSink::default();
    {
        let mut task = Task::new(&mut cap);
        let mut sub = task.begin_subtask("Read NFS exports");
        let _ = nfs::report_into(
            Path::new(nfs::NFSD_PORTLIST),
            Path::new(nfs::NFS_EXPORTS_FILE),
            &mut sub,
        );
    }
    from_report(&cap.stdout)
}

/// Collects streamed stdout (dropping the rest) to capture the `NfsReport`
/// payload for parsing.
#[derive(Default)]
struct CaptureSink {
    stdout: String,
}

impl EventSink for CaptureSink {
    fn emit(&mut self, ev: TaskEvent) -> io::Result<()> {
        if let TaskEvent::Stdout { data } = &ev {
            self.stdout.push_str(data);
        }
        Ok(())
    }
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
