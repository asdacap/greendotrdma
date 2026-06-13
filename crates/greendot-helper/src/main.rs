//! Root helper daemon: executes allowlisted privileged operations on behalf
//! of greendot-web. Only the configured uid may connect (SO_PEERCRED).

mod cmd;
mod dispatch;
mod lio;
mod modules;
mod nvmet;
mod pam;
mod zfs;

use anyhow::{Context, Result, bail};
use greendot_proto::{ErrKind, Request, Response, wire};
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
    nvmet_root: PathBuf,
    lio_root: PathBuf,
}

impl Opts {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let mut opts = Opts {
            socket: "/run/greendotrdma/helper.sock".into(),
            allow_user: "greendot".into(),
            allow_uid: None,
            pam_service: "greendotrdma".into(),
            admin_group: "greendot-admin".into(),
            nvmet_root: "/sys/kernel/config/nvmet".into(),
            lio_root: "/sys/kernel/config/target".into(),
        };
        while let Some(flag) = args.next() {
            let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--socket" => opts.socket = value()?.into(),
                "--allow-user" => opts.allow_user = value()?,
                "--allow-uid" => opts.allow_uid = Some(value()?.parse()?),
                "--pam-service" => opts.pam_service = value()?,
                "--admin-group" => opts.admin_group = value()?,
                "--nvmet-root" => opts.nvmet_root = value()?.into(),
                "--lio-root" => opts.lio_root = value()?.into(),
                other => bail!("unknown flag {other}"),
            }
        }
        Ok(opts)
    }

    fn resolve_allowed_uid(&self) -> Result<u32> {
        match self.allow_uid {
            Some(uid) => Ok(uid),
            None => Ok(nix::unistd::User::from_name(&self.allow_user)?
                .with_context(|| format!("user {:?} does not exist", self.allow_user))?
                .uid
                .as_raw()),
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let opts = Opts::parse(std::env::args().skip(1))?;
    let allowed_uid = opts.resolve_allowed_uid()?;

    if let Some(dir) = opts.socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&opts.socket);
    let listener = UnixListener::bind(&opts.socket)
        .with_context(|| format!("binding {}", opts.socket.display()))?;
    std::fs::set_permissions(&opts.socket, std::fs::Permissions::from_mode(0o660))?;
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
        runner: Box::new(cmd::SystemRunner),
        nvmet_root: opts.nvmet_root,
        lio_root: opts.lio_root,
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

fn serve(ctx: &dispatch::Ctx, stream: UnixStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    loop {
        match wire::read_msg::<Request, _>(&mut reader) {
            Ok(Some(req)) => {
                let resp = dispatch::dispatch(ctx, req);
                if wire::write_msg(&mut writer, &resp).is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(e) => {
                let resp = Response::err(ErrKind::Validation, format!("bad request: {e}"));
                let _ = wire::write_msg(&mut writer, &resp);
                return;
            }
        }
    }
}
