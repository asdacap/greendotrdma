//! `greendotctl`: the GreenDotRDMA root daemon and standalone reconcile tool.
//!
//! `greendotctl serve` (the default, no subcommand) runs the gRPC daemon that
//! executes allowlisted privileged operations on behalf of greendot-web; only
//! the configured uid may connect (SO_PEERCRED, enforced on each accepted Unix
//! socket). `greendotctl reconcile` heals drift through a running daemon (any
//! uid with socket access), or applies inline as root when given a config or
//! when no daemon is up; the web reconciles through the daemon's
//! `Request::Reconcile`, which reads the daemon's own `--config` — never a
//! peer-supplied path (see [`reconcile`]).
//!
//! Transport is gRPC (tonic) over the Unix socket. Every incoming `pb::Request`
//! is converted to the validated domain [`greendot_proto::Request`] via
//! `TryFrom`, which re-runs the validators — the daemon's second line of
//! defense (prost does not validate on decode the way serde did).

mod cmd;
mod dispatch;
mod fs;
mod hardware;
mod install;
mod lio;
mod lvm;
mod modules;
mod nfs;
mod nvmet;
mod pam;
mod partition;
mod reconcile;
mod smart;
mod zfs;

use anyhow::{Context, Result, bail};
use cmd::EventSink;
use dispatch::{Ctx, Dispatch};
use greendot_proto::pb::helper_server::{Helper, HelperServer};
use greendot_proto::{
    ErrKind, Request as GdRequest, Response as GdResponse, SubStatus, Task, TaskEvent, pb,
};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};
use tracing::{info, warn};

/// Ceiling on in-flight requests per gRPC connection. Mutations are further
/// serialized by `Ctx::mutate_lock`; this just bounds concurrent reads/spawns.
const MAX_CONNECTIONS: usize = 8;

/// Upper bound on a single decoded request, mirroring the old NDJSON `MAX_LINE`.
const MAX_MESSAGE: usize = 256 * 1024;

struct Opts {
    socket: PathBuf,
    allow_user: String,
    allow_uid: Option<u32>,
    pam_service: String,
    admin_group: String,
    /// Config TOML for `Request::Reconcile` (`None` = built-in defaults).
    config: Option<String>,
}

impl Opts {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let mut opts = Opts {
            socket: "/run/greendotrdma/helper.sock".into(),
            allow_user: "greendot".into(),
            allow_uid: None,
            pam_service: "greendotrdma".into(),
            admin_group: "greendot-admin".into(),
            config: None,
        };
        while let Some(flag) = args.next() {
            let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--socket" => opts.socket = value()?.into(),
                "--allow-user" => opts.allow_user = value()?,
                "--allow-uid" => opts.allow_uid = Some(value()?.parse()?),
                "--pam-service" => opts.pam_service = value()?,
                "--admin-group" => opts.admin_group = value()?,
                "--config" => opts.config = Some(value()?),
                other => bail!("unknown flag {other}"),
            }
        }
        Ok(opts)
    }

    /// (uid allowed to connect, gid to own the socket — None with --allow-uid,
    /// where the connecting test process owns the socket file anyway).
    fn resolve_allowed_ids(&self) -> Result<(u32, Option<nix::unistd::Gid>)> {
        match self.allow_uid {
            Some(uid) => Ok((uid, None)),
            None => {
                let user = nix::unistd::User::from_name(&self.allow_user)?
                    .with_context(|| format!("user {:?} does not exist", self.allow_user))?;
                Ok((user.uid.as_raw(), Some(user.gid)))
            }
        }
    }
}

fn main() -> Result<()> {
    // Tracing goes to stderr so it never mixes with `greendotctl reconcile`'s
    // task output on stdout. (The daemon's stderr is captured by systemd.)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    // Subcommands: `reconcile [config]` runs the one-shot reconcile; `serve` (or
    // no subcommand, for back-compat with the flags-only invocation) runs the
    // daemon. `reconcile` is fully synchronous — everything applies in-process —
    // so only `serve` spins up the async runtime.
    let mut args = std::env::args().skip(1).peekable();
    match args.peek().map(String::as_str) {
        Some("reconcile") => {
            args.next();
            return reconcile::cli(args.next());
        }
        Some("serve") => {
            args.next();
        }
        _ => {}
    }
    let opts = Opts::parse(args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve_forever(opts))
}

async fn serve_forever(opts: Opts) -> Result<()> {
    let (allowed_uid, socket_gid) = opts.resolve_allowed_ids()?;

    if let Some(dir) = opts.socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&opts.socket);
    let listener = tokio::net::UnixListener::bind(&opts.socket)
        .with_context(|| format!("binding {}", opts.socket.display()))?;
    std::fs::set_permissions(&opts.socket, std::fs::Permissions::from_mode(0o660))?;
    if socket_gid.is_some() {
        // The web service connects via group permission on the socket file.
        nix::unistd::chown(&opts.socket, None, socket_gid)?;
    }
    info!(socket = %opts.socket.display(), allowed_uid, "listening");

    let ctx = Arc::new(dispatch::Ctx {
        auth: pam::AuthConfig {
            pam_service: opts.pam_service,
            admin_group: opts.admin_group,
        },
        auth_limiter: std::sync::Mutex::new(pam::RateLimiter::new(
            5,
            30.0,
            std::time::Instant::now(),
        )),
        mutate_lock: std::sync::Mutex::new(()),
        reconcile_config: opts.config,
    });

    // SO_PEERCRED authorization: only the configured uid may connect. Rejected
    // and errored connections are dropped so the daemon keeps serving (mirrors
    // the old accept loop's `continue`).
    let incoming = UnixListenerStream::new(listener).filter_map(move |conn| match conn {
        Ok(stream) => match peer_uid(&stream) {
            Ok(uid) if uid == allowed_uid => Some(Ok::<_, io::Error>(stream)),
            Ok(uid) => {
                warn!(uid, "rejecting connection from unauthorized uid");
                None
            }
            Err(e) => {
                warn!(error = %e, "could not read peer credentials");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "accept failed");
            None
        }
    });

    let svc = HelperServer::new(HelperSvc { ctx })
        .max_decoding_message_size(MAX_MESSAGE)
        .max_encoding_message_size(MAX_MESSAGE);

    tonic::transport::Server::builder()
        .concurrency_limit_per_connection(MAX_CONNECTIONS)
        .add_service(svc)
        .serve_with_incoming(incoming)
        .await
        .context("gRPC server terminated")
}

/// The connecting peer's uid, via SO_PEERCRED. This is the whole authorization
/// model: only the configured uid may drive the root helper. Linux-only (the
/// daemon only ever runs there); the fallback lets non-Linux dev hosts build.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> nix::Result<u32> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(creds.uid())
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> nix::Result<u32> {
    Err(nix::errno::Errno::ENOSYS)
}

/// The gRPC service. Holds the shared dispatch context; each call converts the
/// incoming protobuf request to the validated domain model and runs it.
struct HelperSvc {
    ctx: Arc<Ctx>,
}

/// An [`EventSink`] that forwards task events into the gRPC response stream.
/// `blocking_send` is safe here because the sink only ever runs inside
/// `spawn_blocking`. A send failure means the client hung up — surfaced as an
/// `io::Error` so the streaming apply/command code stops (as it did when a
/// socket write failed).
struct ChannelSink(mpsc::Sender<std::result::Result<pb::TaskEvent, Status>>);

impl EventSink for ChannelSink {
    fn emit(&mut self, ev: TaskEvent) -> io::Result<()> {
        self.0
            .blocking_send(Ok(pb::TaskEvent::from(ev)))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client disconnected"))
    }
}

#[tonic::async_trait]
impl Helper for HelperSvc {
    async fn call(
        &self,
        request: TonicRequest<pb::Request>,
    ) -> std::result::Result<TonicResponse<pb::Response>, Status> {
        let domain = match GdRequest::try_from(request.into_inner()) {
            Ok(r) => r,
            Err(e) => {
                return Ok(TonicResponse::new(
                    GdResponse::err(ErrKind::Validation, e.to_string()).into(),
                ));
            }
        };
        let ctx = Arc::clone(&self.ctx);
        // `Authenticate` runs PAM, which can block; do it off the reactor.
        let resp = tokio::task::spawn_blocking(move || match dispatch::plan(&ctx, domain) {
            Dispatch::OneShot(resp) => resp,
            _ => GdResponse::err(
                ErrKind::Validation,
                "Call expects a one-shot request (Ping/Authenticate); use RunTask",
            ),
        })
        .await
        .map_err(|e| Status::internal(format!("worker panicked: {e}")))?;
        Ok(TonicResponse::new(resp.into()))
    }

    type RunTaskStream = ReceiverStream<std::result::Result<pb::TaskEvent, Status>>;

    async fn run_task(
        &self,
        request: TonicRequest<pb::Request>,
    ) -> std::result::Result<TonicResponse<Self::RunTaskStream>, Status> {
        let (tx, rx) = mpsc::channel::<std::result::Result<pb::TaskEvent, Status>>(128);
        let pbreq = request.into_inner();
        let ctx = Arc::clone(&self.ctx);
        // All privileged work (commands, configfs, /proc writes) is blocking;
        // run it on a blocking thread and stream its events back via the sink.
        let worker_tx = tx.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let mut sink = ChannelSink(worker_tx);
            let domain = match GdRequest::try_from(pbreq) {
                Ok(r) => r,
                Err(e) => {
                    // A rejected request still surfaces as a failed task so its
                    // reason reaches the UI (the web records the stream).
                    let _ = emit_reject(&mut sink, format!("invalid request: {e}"));
                    return;
                }
            };
            let _ = run_dispatch(&ctx, domain, &mut sink);
        });
        // A worker panic would otherwise just drop the stream, and the web
        // could only record "task ended without a result" while the cause sat
        // in our journal. Fold the panic message into the recorded task.
        tokio::spawn(async move {
            if let Err(e) = worker.await
                && let Ok(panic) = e.try_into_panic()
            {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic payload".into());
                let ev = TaskEvent::Finished {
                    status: SubStatus::Failed,
                    error: Some(format!("helper worker panicked: {msg}")),
                };
                let _ = tx.send(Ok(pb::TaskEvent::from(ev))).await;
            }
        });
        Ok(TonicResponse::new(ReceiverStream::new(rx)))
    }
}

/// Executes a planned request, streaming its output to `sink`. This is the old
/// synchronous `serve` match body, unchanged except that a one-shot response is
/// translated into terminal task events (RunTask always yields a stream).
fn run_dispatch(ctx: &Ctx, req: GdRequest, sink: &mut dyn EventSink) -> io::Result<()> {
    let mut task = Task::new(sink);
    match dispatch::plan(ctx, req) {
        Dispatch::OneShot(resp) => emit_oneshot(&mut task, resp),
        Dispatch::Task(spec) => {
            let _guard = ctx.mutate_lock.lock().unwrap();
            cmd::run(&mut task, spec.command.clone(), &spec)?;
        }
        Dispatch::NvmetApply(desired) => {
            let _guard = ctx.mutate_lock.lock().unwrap();
            let mut sub = task.begin_subtask("Apply NVMe-oF configuration");
            let status = nvmet::apply(&desired, Path::new(nvmet::NVMET_ROOT), &mut sub)?;
            sub.complete(status);
        }
        Dispatch::NfsApply(desired) => {
            let _guard = ctx.mutate_lock.lock().unwrap();
            let mut sub = task.begin_subtask("Apply NFS configuration");
            let status = nfs::apply(
                &desired,
                Path::new(nfs::NFS_EXPORTS_FILE),
                Path::new(nfs::NFSD_PORTLIST),
                &mut sub,
            )?;
            sub.complete(status);
        }
        // The driver loads the config and takes the mutate lock itself, for
        // the whole pass.
        Dispatch::Reconcile => {
            reconcile::run(ctx.reconcile_config.clone(), &ctx.mutate_lock, &mut task)?
        }
        // Reads: no mutate_lock (they stream like the old serve loop).
        Dispatch::NfsReport => {
            let mut sub = task.begin_subtask("Read NFS state");
            let status = nfs::report_into(
                Path::new(nfs::NFSD_PORTLIST),
                Path::new(nfs::NFS_EXPORTS_FILE),
                &mut sub,
            )?;
            sub.complete(status);
        }
        Dispatch::RoceCapableNics => {
            let mut sub = task.begin_subtask("Read RoCE-capable NICs");
            let status = hardware::report_capable_into(Path::new(hardware::NET_ROOT), &mut sub)?;
            sub.complete(status);
        }
        Dispatch::SmartHealth(devices) => {
            let mut sub = task.begin_subtask("Read SMART health");
            let status = smart::report_health_into(&devices, &mut sub)?;
            sub.complete(status);
        }
        Dispatch::NicRdmaAdvice => {
            let mut sub = task.begin_subtask("Read NIC RDMA advice");
            let status = hardware::report_nic_advice_into(Path::new(hardware::NET_ROOT), &mut sub)?;
            sub.complete(status);
        }
        Dispatch::EnableRoce(netdev) => {
            let _guard = ctx.mutate_lock.lock().unwrap();
            let mut sub = task.begin_subtask(format!("Enable RoCE on {netdev}"));
            let status = hardware::enable_into(Path::new(hardware::NET_ROOT), &netdev, &mut sub)?;
            sub.complete(status);
        }
        Dispatch::FailedTask(msg) => {
            // A refused operation (e.g. install on an unsupported distro)
            // recorded as a failed subtask carrying its reason.
            task.begin_subtask("install").fail(msg);
        }
    }
    task.complete()
}

/// Translate a one-shot response into the one-subtask task RunTask must still
/// emit (e.g. `EnsureModules` when every module is already loaded).
fn emit_oneshot(task: &mut Task, resp: GdResponse) {
    let sub = task.begin_subtask("Apply");
    match resp {
        GdResponse::Ok | GdResponse::OkAuth { .. } => sub.complete(SubStatus::Success),
        GdResponse::Err { message, .. } => sub.fail(message),
    }
}

/// Emit a rejected (unvalidatable) request as a failed task.
fn emit_reject(sink: &mut dyn EventSink, msg: String) -> io::Result<()> {
    let mut task = Task::new(sink);
    task.begin_subtask("Validate request").fail(msg);
    task.complete()
}
