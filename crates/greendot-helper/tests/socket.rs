//! End-to-end test against the real helper binary over a unix socket.

use greendot_proto::{ErrKind, Nqn, Request, Response, wire};
use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

struct Helper {
    child: std::process::Child,
    socket: PathBuf,
}

impl Helper {
    fn start() -> Self {
        let dir =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("h{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let nvmet_root = dir.join("nvmet");
        let uid = nix::unistd::getuid().to_string();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_greendot-helper"))
            .args(["--socket", socket.to_str().unwrap(), "--allow-uid", &uid])
            .args(["--nvmet-root", nvmet_root.to_str().unwrap()])
            .args(["--lio-root", dir.join("lio").to_str().unwrap()])
            .spawn()
            .unwrap();
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Helper { child, socket }
    }

    fn connect(&self) -> (BufReader<UnixStream>, UnixStream) {
        let stream = UnixStream::connect(&self.socket).unwrap();
        (BufReader::new(stream.try_clone().unwrap()), stream)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn call(helper: &Helper, req: &Request) -> Response {
    let (mut r, mut w) = helper.connect();
    wire::write_msg(&mut w, req).unwrap();
    wire::read_msg(&mut r)
        .unwrap()
        .expect("helper closed connection without response")
}

#[test]
fn ping_unimplemented_op_and_garbage_handling() {
    let helper = Helper::start();

    // Ping answers Ok, twice on one connection (persistent connections work).
    let (mut r, mut w) = helper.connect();
    for _ in 0..2 {
        wire::write_msg(&mut w, &Request::Ping).unwrap();
        assert_eq!(
            wire::read_msg::<Response, _>(&mut r).unwrap(),
            Some(Response::Ok)
        );
    }

    // A real operation flows through dispatch to the (test-rooted) nvmet tree.
    let nqn = Nqn::new("nqn.2026-06.io.greendot:sockettest").unwrap();
    let resp = call(
        &helper,
        &Request::NvmetSubsysCreate {
            nqn: nqn.clone(),
            allow_any_host: true,
        },
    );
    assert_eq!(resp, Response::Ok);
    assert_eq!(
        call(&helper, &Request::NvmetSubsysDelete { nqn }),
        Response::Ok
    );

    // A not-yet-implemented operation gets a clean Unsupported error.
    let resp = call(
        &helper,
        &Request::PartitionTableCreate {
            disk: greendot_proto::BlockDev::new("fakedisk").unwrap(),
        },
    );
    assert!(
        matches!(
            resp,
            Response::Err {
                kind: ErrKind::Unsupported,
                ..
            }
        ),
        "{resp:?}"
    );

    // Garbage gets an error response and the connection is closed.
    let (mut r, mut w) = helper.connect();
    w.write_all(b"{\"op\":\"zvol_delete\",\"dataset\":\"../etc\"}\nnot json at all\n")
        .unwrap();
    let first: Response = wire::read_msg(&mut r).unwrap().unwrap();
    assert!(
        matches!(
            first,
            Response::Err {
                kind: ErrKind::Validation,
                ..
            }
        ),
        "{first:?}"
    );
    assert_eq!(
        wire::read_msg::<Response, _>(&mut r).unwrap(),
        None,
        "connection should be closed"
    );
}
