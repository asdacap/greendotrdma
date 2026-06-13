//! The privileged-operation allowlist: every reachable operation is a
//! `Request` variant handled here.

use greendot_proto::{ErrKind, Request, Response};

pub fn dispatch(req: Request) -> Response {
    match req {
        Request::Ping => Response::Ok,
        other => Response::err(
            ErrKind::Unsupported,
            format!("not yet implemented: {other:?}"),
        ),
    }
}
