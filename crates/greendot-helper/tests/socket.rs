//! End-to-end test against the real helper binary over a unix socket.

use greendot_proto::{DatasetName, ErrKind, KernelModule, Request, Response, TaskEvent, wire};
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
        let uid = nix::unistd::getuid().to_string();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_greendot-helper"))
            .args(["--socket", socket.to_str().unwrap(), "--allow-uid", &uid])
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

/// Sends a task request and collects the streamed events up to Finished.
fn run_task(helper: &Helper, req: &Request) -> Vec<TaskEvent> {
    let (mut r, mut w) = helper.connect();
    wire::write_msg(&mut w, req).unwrap();
    let mut events = Vec::new();
    while let Some(ev) = wire::read_msg::<TaskEvent, _>(&mut r).unwrap() {
        let done = matches!(ev, TaskEvent::Finished { .. });
        events.push(ev);
        if done {
            break;
        }
    }
    events
}

#[test]
fn ping_streamed_task_and_garbage_handling() {
    let helper = Helper::start();

    // Ping is one-shot and works twice on one connection.
    let (mut r, mut w) = helper.connect();
    for _ in 0..2 {
        wire::write_msg(&mut w, &Request::Ping).unwrap();
        assert_eq!(
            wire::read_msg::<Response, _>(&mut r).unwrap(),
            Some(Response::Ok)
        );
    }

    // A task op streams Started..Finished. `zfs` is absent in the dev shell,
    // so this exercises the missing-binary install hint over the real socket.
    let events = run_task(
        &helper,
        &Request::ZvolDelete {
            dataset: DatasetName::new("tank/x").unwrap(),
        },
    );
    assert!(matches!(events.first(), Some(TaskEvent::Started { command, .. }) if command == "zfs"));
    match events.last() {
        Some(TaskEvent::Finished {
            ok: false,
            error: Some(msg),
            ..
        }) => {
            assert!(msg.contains("zfs is not installed"), "{msg}");
        }
        other => panic!("expected Finished with install hint, got {other:?}"),
    }

    // EnsureModules with an empty set is a one-shot Ok (no command to run).
    let (mut r, mut w) = helper.connect();
    wire::write_msg(
        &mut w,
        &Request::EnsureModules {
            modules: Vec::<KernelModule>::new(),
        },
    )
    .unwrap();
    assert_eq!(
        wire::read_msg::<Response, _>(&mut r).unwrap(),
        Some(Response::Ok)
    );

    // Garbage gets a validation error and the connection is closed.
    let (mut r, mut w) = helper.connect();
    w.write_all(b"{\"op\":\"zvol_delete\",\"dataset\":\"../etc\"}\nnot json\n")
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
