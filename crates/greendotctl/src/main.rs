//! `greendotctl`: the GreenDotRDMA root daemon and standalone reconcile tool.
//!
//! `greendotctl serve` (the default, no subcommand) runs the gRPC daemon that
//! executes allowlisted privileged operations on behalf of greendot-web; only
//! the configured uid, or a member of the allowed group, may connect
//! (SO_PEERCRED + group lookup, enforced on each accepted Unix socket).
//! `greendotctl reconcile` heals drift through a running daemon (any uid with
//! socket access), or applies inline as root when given a config or when no
//! daemon is up; the web reconciles through the daemon's `Reconcile` rpc,
//! which reads the daemon's own `--config` — never a peer-supplied path (see
//! [`reconcile`]). `greendotctl pipe` relays stdio to the daemon socket — the
//! SSH forced command the Kubernetes CSI controller drives the daemon through
//! (see [`pipe`]).
//!
//! Transport is gRPC (tonic), one rpc per operation. Every incoming protobuf
//! request is converted to its validated domain op (`ops::X`) via `TryFrom` —
//! required by bound in the generic middleware ([`HelperSvc::spawn_task`] /
//! [`HelperSvc::read_op`]), so no method can skip the validation choke point
//! (prost does not validate on decode the way serde did).

mod actual;
mod cmd;
mod exec;
mod fs;
mod hardware;
mod install;
mod lio;
mod lvm;
mod modules;
mod net;
mod nfs;
mod nvmet;
mod pam;
mod partition;
mod pipe;
mod pipe_keys;
mod reconcile;
mod render;
mod smart;
mod util;
mod zfs;

use anyhow::{Context, Result, bail};
use cmd::EventSink;
use exec::{Ctx, ReadOp, TaskOp};
use greendot_proto::pb::helper_server::{Helper, HelperServer};
use greendot_proto::{AuthResult, ErrKind, SubStatus, Task, TaskEvent, ops, pb};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::Status;
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
    /// Config TOML for the `Reconcile` rpc (`None` = built-in defaults).
    config: Option<String>,
    /// nvmet configfs root for the CSI ops (test-only override, like
    /// `--allow-uid`; production always uses the kernel path).
    nvmet_root: Option<PathBuf>,
    /// The SSH login whose `authorized_keys` the `PipeKey*` ops manage.
    pipe_user: String,
    /// Home of that user (test-only override; production NSS-resolves it).
    pipe_home: Option<PathBuf>,
    /// The binary the forced command runs (test-only override; production
    /// resolves our own `current_exe`).
    pipe_command: Option<PathBuf>,
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
            nvmet_root: None,
            pipe_user: pipe_keys::SSH_USER.into(),
            pipe_home: None,
            pipe_command: None,
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
                "--nvmet-root" => opts.nvmet_root = Some(value()?.into()),
                "--pipe-user" => opts.pipe_user = value()?,
                "--pipe-home" => opts.pipe_home = Some(value()?.into()),
                "--pipe-command" => opts.pipe_command = Some(value()?.into()),
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
        Some("pipe") => {
            args.next();
            return pipe::run(args.next().map(Into::into));
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

    // Resolved once; a config edit needs a daemon restart, like every other
    // startup-resolved knob. An unreadable config still serves (reconcile
    // reports it per-pass) and keeps the default.
    let autoload_modules = greendot_proto::config::Config::load(opts.config.clone())
        .map(|cfg| cfg.autoload_modules)
        .unwrap_or_else(|e| {
            warn!(error = %format!("{e:#}"), "config unreadable; module autoload keeps its default");
            greendot_proto::config::Config::default().autoload_modules
        });

    let ctx = Arc::new(Ctx {
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
        nvmet_root: opts.nvmet_root.unwrap_or_else(|| nvmet::NVMET_ROOT.into()),
        pipe_keys: pipe_keys::PipeKeyConfig {
            user: opts.pipe_user,
            // A pipe key is only useful if its login is also admitted at this
            // socket, which is exactly `allow_user`'s group.
            socket_group: opts.allow_user,
            pipe_bin: opts
                .pipe_command
                .unwrap_or_else(pipe_keys::resolve_pipe_bin),
            home_override: opts.pipe_home,
        },
        autoload_modules,
    });

    if ctx.autoload_modules {
        load_startup_modules();
    }

    // SO_PEERCRED authorization: the configured uid, or a member of the
    // allowed group (see [`peer_allowed`]). Rejected and errored connections
    // are dropped so the daemon keeps serving (mirrors the old accept loop's
    // `continue`).
    let incoming = UnixListenerStream::new(listener).filter_map(move |conn| match conn {
        Ok(stream) => match peer_uid(&stream) {
            Ok(uid) if peer_allowed(uid, allowed_uid, socket_gid, user_groups) => {
                Some(Ok::<_, io::Error>(stream))
            }
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

/// The connecting peer's uid, via SO_PEERCRED. Together with [`peer_allowed`]
/// this is the whole authorization model for the root helper. Linux-only (the
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

/// Whether a connecting peer may drive the helper: the allowed uid itself
/// (greendot-web), or any user in the allowed group — supplementary groups
/// included, since SO_PEERCRED carries only the uid and the CSI controller's
/// SSH user is granted via `usermod -aG greendot`. `groups_of` resolves a
/// uid's full group list (injected so the table test needs no real users);
/// a failed resolution denies. `--allow-uid` test mode passes no group, so
/// it stays uid-only.
fn peer_allowed(
    uid: u32,
    allowed_uid: u32,
    allowed_gid: Option<nix::unistd::Gid>,
    groups_of: impl Fn(u32) -> Option<Vec<nix::unistd::Gid>>,
) -> bool {
    uid == allowed_uid
        || allowed_gid.is_some_and(|gid| groups_of(uid).is_some_and(|groups| groups.contains(&gid)))
}

/// The production `groups_of`: NSS lookup of the uid's user, then its full
/// group list (primary + supplementary). Local passwd/group lookups — the
/// accept path can afford them.
fn user_groups(uid: u32) -> Option<Vec<nix::unistd::Gid>> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    let name = std::ffi::CString::new(user.name).ok()?;
    nix::unistd::getgrouplist(&name, user.gid).ok()
}

/// The service. Every generated rpc method is one `task_rpc!`/`read_rpc!` line
/// delegating to the two generic middleware paths below, so the pipeline —
/// validation, blocking-thread execution, the mutate lock, task framing, panic
/// folding — is written once and cannot be skipped per method.
struct HelperSvc {
    ctx: Arc<Ctx>,
}

/// An [`EventSink`] that forwards task events into the gRPC response stream.
/// Sending only ever runs inside `spawn_blocking`. A closed channel means the
/// client hung up; a channel that stays full past [`SEND_STALL_LIMIT`] means a
/// connected client stopped reading. Both surface as an `io::Error` so the
/// streaming apply/command code stops — otherwise a stalled client would pin
/// the worker (and with it `Ctx::mutate_lock`) forever.
struct ChannelSink(mpsc::Sender<std::result::Result<pb::TaskEvent, Status>>);

/// How long a full event channel may stall a worker before the client is
/// declared dead.
const SEND_STALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// `modprobe -a` for [`modules::STARTUP_MODULES`] plus the recognized NICs'
/// RDMA drivers, run once before the daemon serves.
///
/// Deliberately *not* a Task: there is no client to stream subtask events to at
/// startup, so modprobe's stdout/stderr are inherited straight into the
/// daemon's own — journald records them. A module the kernel doesn't ship makes
/// `modprobe -a` exit non-zero after loading the rest; that is a warning, not a
/// reason to refuse to serve.
fn load_startup_modules() {
    let nics = hardware::rdma_driver_modules(Path::new(hardware::NET_ROOT));
    let Some(spec) = modules::ensure(modules::STARTUP_MODULES, &nics) else {
        return;
    };
    info!(args = ?spec.args, "autoloading kernel modules");
    match std::process::Command::new(&spec.command)
        .args(&spec.args)
        .status()
    {
        Ok(status) if status.success() => info!("kernel modules loaded"),
        Ok(status) => warn!(
            code = status.code(),
            "modprobe reported failures; some transports may be unavailable"
        ),
        Err(e) => warn!(error = %e, "modprobe could not run"),
    }
}

impl EventSink for ChannelSink {
    fn emit(&mut self, ev: TaskEvent) -> io::Result<()> {
        let mut ev = Ok(pb::TaskEvent::from(ev));
        let deadline = std::time::Instant::now() + SEND_STALL_LIMIT;
        loop {
            match self.0.try_send(ev) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "client disconnected",
                    ));
                }
                Err(mpsc::error::TrySendError::Full(unsent)) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "client stopped reading task events",
                        ));
                    }
                    ev = unsent;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
}

/// The reply type of every task rpc.
type TaskStream = ReceiverStream<std::result::Result<pb::TaskEvent, Status>>;

/// Runs a validated op as one framed task: mutate lock per `O::MUTATES`, one
/// terminal `Finished`. `Err` only when the sink fails (the client is gone).
fn run_op<O: TaskOp>(ctx: &Ctx, op: O, sink: &mut dyn EventSink) -> io::Result<()> {
    let mut task = Task::new(sink);
    let _guard = O::MUTATES.then(|| ctx.mutate_lock.lock().unwrap());
    op.exec(ctx, &mut task)?;
    task.complete()
}

/// Emit a rejected (unvalidatable) request as a failed task.
fn emit_reject(sink: &mut dyn EventSink, msg: String) -> io::Result<()> {
    let mut task = Task::new(sink);
    task.begin_subtask("Validate request").fail(msg);
    task.complete()
}

impl HelperSvc {
    /// The task middleware: validate (the `TryFrom` bound on [`TaskOp`]), run
    /// on a blocking thread streaming events back, and fold a worker panic
    /// into the recorded task — otherwise the web could only record "task
    /// ended without a result" while the cause sat in our journal.
    fn spawn_task<O: TaskOp>(&self, wire: O::Wire) -> TaskStream {
        let (tx, rx) = mpsc::channel::<std::result::Result<pb::TaskEvent, Status>>(128);
        let ctx = Arc::clone(&self.ctx);
        let worker_tx = tx.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let mut sink = ChannelSink(worker_tx);
            // A rejected request still surfaces as a failed task so its
            // reason reaches the UI (the web records the stream).
            match O::try_from(wire) {
                Ok(op) => {
                    let _ = run_op(&ctx, op, &mut sink);
                }
                Err(e) => {
                    let _ = emit_reject(&mut sink, format!("invalid request: {e}"));
                }
            }
        });
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
        ReceiverStream::new(rx)
    }

    /// The typed-read middleware: validate, run the producer off the reactor
    /// (sysfs/configfs/tool reads are blocking), answer with the reply.
    async fn read_op<O: ReadOp>(
        &self,
        wire: O::Wire,
    ) -> std::result::Result<tonic::Response<O::Reply>, Status> {
        let op = O::try_from(wire).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let ctx = Arc::clone(&self.ctx);
        tokio::task::spawn_blocking(move || op.read(&ctx))
            .await
            .map(tonic::Response::new)
            .map_err(|e| Status::internal(format!("helper worker panicked: {e}")))
    }
}

/// Generates the whole `Helper` impl: the two one-shot methods plus one line
/// per rpc. The whole block is produced by one macro so `#[tonic::async_trait]`
/// sees fully-expanded methods (an unexpanded macro call inside the impl would
/// reach it too late). Adding an rpc is one line in the right section — the
/// middleware bound (`TaskOp`/`ReadOp`, and through them `TryFrom` validation)
/// applies automatically.
macro_rules! helper_impl {
    (
        tasks { $($method:ident, $stream:ident, $wire:ty, $op:ty;)* }
        reads { $($rmethod:ident, $rwire:ty, $rop:ty;)* }
    ) => {
        #[tonic::async_trait]
        impl Helper for HelperSvc {
            // One-shot ops (never recorded; auth must not land in a task log).
            async fn ping(
                &self,
                _request: tonic::Request<pb::Empty>,
            ) -> std::result::Result<tonic::Response<pb::Empty>, Status> {
                Ok(tonic::Response::new(pb::Empty {}))
            }

            async fn authenticate(
                &self,
                request: tonic::Request<pb::Authenticate>,
            ) -> std::result::Result<tonic::Response<pb::AuthReply>, Status> {
                let result = match ops::Authenticate::try_from(request.into_inner()) {
                    // PAM can block; do it off the reactor.
                    Ok(auth) => {
                        let ctx = Arc::clone(&self.ctx);
                        tokio::task::spawn_blocking(move || {
                            pam::authenticate(
                                &ctx.auth,
                                &ctx.auth_limiter,
                                &auth.username,
                                &auth.password,
                            )
                        })
                        .await
                        .unwrap_or_else(|e| {
                            AuthResult::err(ErrKind::Sys, format!("worker panicked: {e}"))
                        })
                    }
                    Err(e) => AuthResult::err(ErrKind::Validation, e.to_string()),
                };
                Ok(tonic::Response::new(result.into()))
            }

            // Task ops.
            $(
                type $stream = TaskStream;
                async fn $method(
                    &self,
                    request: tonic::Request<$wire>,
                ) -> std::result::Result<tonic::Response<Self::$stream>, Status> {
                    Ok(tonic::Response::new(
                        self.spawn_task::<$op>(request.into_inner()),
                    ))
                }
            )*

            // Typed reads.
            $(
                async fn $rmethod(
                    &self,
                    request: tonic::Request<$rwire>,
                ) -> std::result::Result<tonic::Response<<$rop as ReadOp>::Reply>, Status> {
                    self.read_op::<$rop>(request.into_inner()).await
                }
            )*
        }
    };
}

helper_impl! {
    tasks {
            zvol_create, ZvolCreateStream, pb::ZvolCreate, ops::ZvolCreate;
            zvol_delete, ZvolDeleteStream, pb::ZvolDelete, ops::ZvolDelete;
            zvol_resize, ZvolResizeStream, pb::ZvolResize, ops::ZvolResize;
            snapshot_create, SnapshotCreateStream, pb::SnapshotCreate, ops::SnapshotCreate;
            snapshot_destroy, SnapshotDestroyStream, pb::SnapshotDestroy, ops::SnapshotDestroy;
            zfs_fs_create, ZfsFsCreateStream, pb::ZfsFsCreate, ops::ZfsFsCreate;
            zfs_set_mountpoint, ZfsSetMountpointStream, pb::ZfsSetMountpoint, ops::ZfsSetMountpoint;
            zfs_mount, ZfsMountStream, pb::ZfsMount, ops::ZfsMount;
            zfs_unmount, ZfsUnmountStream, pb::ZfsUnmount, ops::ZfsUnmount;
            zfs_destroy, ZfsDestroyStream, pb::ZfsDestroy, ops::ZfsDestroy;
            pool_create, PoolCreateStream, pb::PoolCreate, ops::PoolCreate;
            pool_vdev_add, PoolVdevAddStream, pb::PoolVdevAdd, ops::PoolVdevAdd;
            pool_device_attach, PoolDeviceAttachStream, pb::PoolDeviceAttach, ops::PoolDeviceAttach;
            pool_device_remove, PoolDeviceRemoveStream, pb::PoolDeviceRemove, ops::PoolDeviceRemove;
            pool_device_detach, PoolDeviceDetachStream, pb::PoolDeviceDetach, ops::PoolDeviceDetach;
            pool_device_online, PoolDeviceOnlineStream, pb::PoolDeviceOnline, ops::PoolDeviceOnline;
            partition_table_create, PartitionTableCreateStream, pb::PartitionTableCreate, ops::PartitionTableCreate;
            partition_create, PartitionCreateStream, pb::PartitionCreate, ops::PartitionCreate;
            partition_delete, PartitionDeleteStream, pb::PartitionDelete, ops::PartitionDelete;
            partition_shrink, PartitionShrinkStream, pb::PartitionShrink, ops::PartitionShrink;
            lvm_report, LvmReportStream, pb::LvmReport, ops::LvmReport;
            vg_create, VgCreateStream, pb::VgCreate, ops::VgCreate;
            vg_extend, VgExtendStream, pb::VgExtend, ops::VgExtend;
            vg_reduce, VgReduceStream, pb::VgReduce, ops::VgReduce;
            vg_remove, VgRemoveStream, pb::VgRemove, ops::VgRemove;
            lv_create, LvCreateStream, pb::LvCreate, ops::LvCreate;
            thin_pool_create, ThinPoolCreateStream, pb::ThinPoolCreate, ops::ThinPoolCreate;
            thin_lv_create, ThinLvCreateStream, pb::ThinLvCreate, ops::ThinLvCreate;
            lv_resize, LvResizeStream, pb::LvResize, ops::LvResize;
            lv_shrink, LvShrinkStream, pb::LvShrink, ops::LvShrink;
            lv_rename, LvRenameStream, pb::LvRename, ops::LvRename;
            lv_delete, LvDeleteStream, pb::LvDelete, ops::LvDelete;
            zfs_clone, ZfsCloneStream, pb::ZfsClone, ops::ZfsClone;
            csi_nvme_apply, CsiNvmeApplyStream, pb::CsiNvmeApply, ops::CsiNvmeApply;
            csi_nvme_delete, CsiNvmeDeleteStream, pb::CsiNvmeDelete, ops::CsiNvmeDelete;
            csi_host_grant, CsiHostGrantStream, pb::CsiHostGrant, ops::CsiHostGrant;
            csi_host_revoke, CsiHostRevokeStream, pb::CsiHostRevoke, ops::CsiHostRevoke;
            csi_volume_expand, CsiVolumeExpandStream, pb::CsiVolumeExpand, ops::CsiVolumeExpand;
            pipe_key_add, PipeKeyAddStream, pb::PipeKeyAdd, ops::PipeKeyAdd;
            pipe_key_revoke, PipeKeyRevokeStream, pb::PipeKeyRevoke, ops::PipeKeyRevoke;
            reconcile, ReconcileStream, pb::Reconcile, ops::Reconcile;
            rxe_add, RxeAddStream, pb::RxeAdd, ops::RxeAdd;
            enable_roce, EnableRoceStream, pb::EnableRoce, ops::EnableRoce;
            set_mtu, SetMtuStream, pb::SetMtu, ops::SetMtu;
            install_packages, InstallPackagesStream, pb::InstallPackages, ops::InstallPackages;
            smart_report, SmartReportStream, pb::SmartReport, ops::SmartReport;
            rdma_resources, RdmaResourcesStream, pb::Empty, ops::RdmaResources;
    }
    reads {
            nfs_report, pb::Empty, ops::NfsReport;
            nvmet_report, pb::Empty, ops::NvmetReport;
            lio_report, pb::Empty, ops::LioReport;
            lio_sessions, pb::Empty, ops::LioSessions;
            rdma_devices, pb::Empty, ops::RdmaDevices;
            nic_pci_addrs, pb::Empty, ops::NicPciAddrs;
            nic_interfaces, pb::Empty, ops::NicInterfaces;
            nic_network, pb::Empty, ops::NicNetwork;
            roce_capable_nics, pb::Empty, ops::RoceCapableNics;
            nic_rdma_advice, pb::Empty, ops::NicRdmaAdvice;
            smart_health, pb::SmartHealth, ops::SmartHealth;
            reconcile_dry_run, pb::Empty, ops::ReconcileDryRun;
            zvol_info, pb::ZvolInfo, ops::ZvolInfo;
            pipe_access_report, pb::Empty, ops::PipeAccessReport;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::Gid;
    use rstest::rstest;

    #[rstest]
    // The allowed uid connects regardless of groups (greendot-web).
    #[case::uid_match(1000, Some(2000), &[], true)]
    // A group member connects — primary or supplementary is the same here:
    // `groups_of` answers the full list (usermod -aG greendot).
    #[case::group_member(1001, Some(2000), &[999, 2000], true)]
    #[case::not_a_member(1001, Some(2000), &[999, 1001], false)]
    // Group lookup failure denies.
    #[case::lookup_failure(1001, Some(2000), &[u32::MAX], false)]
    // `--allow-uid` test mode carries no group: strictly uid-only.
    #[case::uid_only_mode(1001, None, &[2000], false)]
    fn peer_allowed_by_uid_or_group(
        #[case] uid: u32,
        #[case] allowed_gid: Option<u32>,
        #[case] peer_groups: &[u32],
        #[case] allowed: bool,
    ) {
        let groups_of = |_uid: u32| {
            if peer_groups.contains(&u32::MAX) {
                None // simulated NSS failure
            } else {
                Some(peer_groups.iter().map(|g| Gid::from_raw(*g)).collect())
            }
        };
        assert_eq!(
            peer_allowed(uid, 1000, allowed_gid.map(Gid::from_raw), groups_of),
            allowed
        );
    }
}
