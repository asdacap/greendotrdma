//! The `greendotctl reconcile [config.toml]` subcommand. It applies the desired
//! state either in-process as root (no daemon needed — the standalone case an
//! alternative frontend drives) or over the helper's socket (the path the
//! unprivileged web-spawned invocation takes). The shared driver in
//! `greendot-reconcile` does the render/diff; this module supplies the executor.

use crate::cmd::EventSink;
use crate::dispatch::{self, Ctx, Dispatch};
use crate::{cmd, nfs, nvmet, pam};
use anyhow::Result;
use greendot_proto::{Request, Response, SubStatus, SubTask, Task, TaskEvent};
use greendot_reconcile::actual::nfs::{ActualNfs, from_report};
use greendot_reconcile::reconcile::{Executor, JsonlSink, SocketExecutor};
use std::io;
use std::path::Path;

/// Runs a reconcile and exits with status 1 if any apply step failed (so the
/// web, which records this as a task, sees the failure). Config/transport errors
/// propagate as `Err`.
pub fn run(cfg_path: Option<String>) -> Result<()> {
    let cfg = greendot_reconcile::config::Config::load(cfg_path)?;
    let mut sink = JsonlSink;
    let mut task = Task::new(&mut sink);

    // Prefer the running daemon whenever its socket is reachable: that is the
    // path the unprivileged, web-spawned invocation takes, and it keeps a single
    // privileged process holding the helper's mutate_lock. Fall back to an
    // in-process apply only when no daemon is up and we are root — the
    // standalone, daemon-less case (an alternative frontend, or recovery).
    let ok = if std::os::unix::net::UnixStream::connect(&cfg.helper_socket).is_ok() {
        let exec = SocketExecutor::new(cfg.helper_socket.clone());
        greendot_reconcile::reconcile::run(&cfg, &exec, &mut task)?
    } else if nix::unistd::geteuid().is_root() {
        let ctx = reconcile_ctx();
        let exec = InProcessExecutor { ctx: &ctx };
        greendot_reconcile::reconcile::run(&cfg, &exec, &mut task)?
    } else {
        anyhow::bail!(
            "no helper daemon at {} and not running as root — start the daemon \
             (greendotctl serve) or run `greendotctl reconcile` as root",
            cfg.helper_socket.display()
        );
    };
    task.complete()?;
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// A `Ctx` for the in-process apply path. Reconcile issues no auth requests, so
/// the PAM/admin-group fields are unused defaults; only `mutate_lock` matters.
fn reconcile_ctx() -> Ctx {
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

/// Applies reconcile Requests in-process with root privileges, routing each
/// through `dispatch::plan` so the allowlist/validation is identical to the
/// daemon. The reconcile driver only ever issues `EnsureModules`/`NvmetApply`/
/// `LioApply`/`NfsApply` applies plus `NfsReport`.
struct InProcessExecutor<'a> {
    ctx: &'a Ctx,
}

impl Executor for InProcessExecutor<'_> {
    /// Applies into the caller-opened `sub` (reconcile's `step()` owns it) and
    /// returns the status directly — no framing to unwrap, unlike the socket path.
    fn apply(&self, req: Request, sub: &mut SubTask) -> io::Result<SubStatus> {
        match dispatch::plan(self.ctx, req) {
            // Empty EnsureModules — nothing to load.
            Dispatch::OneShot(Response::Ok) => Ok(SubStatus::Success),
            // EnsureModules (modprobe) and LioApply (targetctl) are commands.
            Dispatch::Task(spec) => {
                let _guard = self.ctx.mutate_lock.lock().unwrap();
                cmd::run_into(sub, &spec)
            }
            Dispatch::NvmetApply(desired) => {
                let _guard = self.ctx.mutate_lock.lock().unwrap();
                nvmet::apply(&desired, Path::new(nvmet::NVMET_ROOT), sub)
            }
            Dispatch::NfsApply(desired) => {
                let _guard = self.ctx.mutate_lock.lock().unwrap();
                nfs::apply(
                    &desired,
                    Path::new(nfs::NFS_EXPORTS_FILE),
                    Path::new(nfs::NFSD_PORTLIST),
                    sub,
                )
            }
            _ => unreachable!("reconcile issues only module/nvmet/lio/nfs applies"),
        }
    }

    fn nfs_report(&self) -> ActualNfs {
        // A throwaway task/subtask just to satisfy `report_into`'s handle API;
        // the `CaptureSink` keeps the streamed report payload for parsing.
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
