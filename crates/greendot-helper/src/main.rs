//! Root helper daemon: executes allowlisted privileged operations on behalf
//! of greendot-web. Only the configured uid may connect (SO_PEERCRED).

mod cmd;
mod dispatch;
mod fs;
mod install;
mod lio;
mod lvm;
mod modules;
mod nvmet;
mod pam;
mod partition;
mod zfs;

use anyhow::{Context, Result, bail};
use cmd::EventSink;
use dispatch::Dispatch;
use greendot_proto::{ErrKind, Request, Response, TaskEvent, wire};
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{info, warn};

const MAX_CONNECTIONS: usize = 8;

struct Opts {
    socket: PathBuf,
    allow_user: String,
    allow_uid: Option<u32>,
    pam_service: String,
    admin_group: String,
}

impl Opts {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let mut opts = Opts {
            socket: "/run/greendotrdma/helper.sock".into(),
            allow_user: "greendot".into(),
            allow_uid: None,
            pam_service: "greendotrdma".into(),
            admin_group: "greendot-admin".into(),
        };
        while let Some(flag) = args.next() {
            let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--socket" => opts.socket = value()?.into(),
                "--allow-user" => opts.allow_user = value()?,
                "--allow-uid" => opts.allow_uid = Some(value()?.parse()?),
                "--pam-service" => opts.pam_service = value()?,
                "--admin-group" => opts.admin_group = value()?,
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
    tracing_subscriber::fmt().init();
    let opts = Opts::parse(std::env::args().skip(1))?;
    let (allowed_uid, socket_gid) = opts.resolve_allowed_ids()?;

    if let Some(dir) = opts.socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&opts.socket);
    let listener = UnixListener::bind(&opts.socket)
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
    });
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        match peer_uid(&stream) {
            Ok(uid) if uid == allowed_uid => {}
            Ok(uid) => {
                warn!(uid, "rejecting connection from unauthorized uid");
                continue;
            }
            Err(e) => {
                warn!(error = %e, "could not read peer credentials");
                continue;
            }
        }
        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            warn!("rejecting connection: too many concurrent connections");
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let active = Arc::clone(&active);
        let ctx = Arc::clone(&ctx);
        std::thread::spawn(move || {
            serve(&ctx, stream);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(creds.uid())
}

/// Writes each task event to the socket as a framed line.
struct SocketSink<'a>(&'a mut UnixStream);

impl EventSink for SocketSink<'_> {
    fn emit(&mut self, ev: TaskEvent) -> std::io::Result<()> {
        wire::write_msg(self.0, &ev)
    }
}

fn serve(ctx: &dispatch::Ctx, stream: UnixStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    loop {
        match wire::read_msg::<Request, _>(&mut reader) {
            Ok(Some(req)) => match dispatch::plan(ctx, req) {
                Dispatch::OneShot(resp) => {
                    if wire::write_msg(&mut writer, &resp).is_err() {
                        return;
                    }
                }
                Dispatch::Task(spec) => {
                    let _guard = ctx.mutate_lock.lock().unwrap();
                    let mut sink = SocketSink(&mut writer);
                    if cmd::run_task(&spec, &mut sink).is_err() {
                        return; // socket write failed; client gone
                    }
                }
                Dispatch::NvmetApply(desired) => {
                    let _guard = ctx.mutate_lock.lock().unwrap();
                    let mut sink = SocketSink(&mut writer);
                    let root = std::path::Path::new(nvmet::NVMET_ROOT);
                    if nvmet::apply(&desired, root, &mut sink).is_err() {
                        return; // socket write failed; client gone
                    }
                }
                Dispatch::FailedTask(msg) => {
                    // Record a refused operation as a failed task so its reason
                    // streams to the UI like any other task.
                    let mut sink = SocketSink(&mut writer);
                    let events = [
                        TaskEvent::Started {
                            command: "install".into(),
                            args: Vec::new(),
                            stdin: None,
                        },
                        TaskEvent::Stderr {
                            data: format!("{msg}\n"),
                        },
                        TaskEvent::Finished {
                            exit: 1,
                            ok: false,
                            error: Some(msg),
                        },
                    ];
                    for ev in events {
                        if sink.emit(ev).is_err() {
                            return;
                        }
                    }
                }
            },
            Ok(None) => return,
            Err(e) => {
                let resp = Response::err(ErrKind::Validation, format!("bad request: {e}"));
                let _ = wire::write_msg(&mut writer, &resp);
                return;
            }
        }
    }
}
