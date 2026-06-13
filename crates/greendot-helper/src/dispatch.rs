//! The privileged-operation allowlist: every reachable operation is a
//! `Request` variant handled here.

use crate::pam;
use greendot_proto::{ErrKind, Request, Response};
use std::sync::Mutex;

pub struct Ctx {
    pub auth: pam::AuthConfig,
    pub auth_limiter: Mutex<pam::RateLimiter>,
}

pub fn dispatch(ctx: &Ctx, req: Request) -> Response {
    match req {
        Request::Ping => Response::Ok,
        Request::Authenticate { username, password } => {
            pam::authenticate(&ctx.auth, &ctx.auth_limiter, &username, &password)
        }
        other => Response::err(
            ErrKind::Unsupported,
            format!("not yet implemented: {other:?}"),
        ),
    }
}
