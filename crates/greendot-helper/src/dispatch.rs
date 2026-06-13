//! The privileged-operation allowlist: every reachable operation is a
//! `Request` variant handled here.

use crate::cmd::Runner;
use crate::{pam, zfs};
use greendot_proto::{ErrKind, Request, Response};
use std::sync::Mutex;

pub struct Ctx {
    pub auth: pam::AuthConfig,
    pub auth_limiter: Mutex<pam::RateLimiter>,
    pub runner: Box<dyn Runner>,
    /// Serializes all mutating operations so configfs changes never interleave.
    pub mutate_lock: Mutex<()>,
}

pub fn dispatch(ctx: &Ctx, req: Request) -> Response {
    match req {
        Request::Ping => Response::Ok,
        Request::Authenticate { username, password } => {
            pam::authenticate(&ctx.auth, &ctx.auth_limiter, &username, &password)
        }
        mutation => {
            let _guard = ctx.mutate_lock.lock().unwrap();
            let runner = ctx.runner.as_ref();
            match mutation {
                Request::ZvolCreate {
                    dataset,
                    size,
                    volblocksize,
                    sparse,
                } => zfs::zvol_create(runner, &dataset, size, volblocksize, sparse),
                Request::ZvolDelete { dataset } => zfs::zvol_delete(runner, &dataset),
                Request::ZvolResize { dataset, new_size } => {
                    zfs::zvol_resize(runner, &dataset, new_size)
                }
                Request::SnapshotCreate { dataset, snap } => {
                    zfs::snapshot_create(runner, &dataset, &snap)
                }
                Request::SnapshotDestroy { dataset, snap } => {
                    zfs::snapshot_destroy(runner, &dataset, &snap)
                }
                other => Response::err(
                    ErrKind::Unsupported,
                    format!("not yet implemented: {other:?}"),
                ),
            }
        }
    }
}
