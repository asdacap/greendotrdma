//! End-to-end test against the real helper binary over gRPC on a unix socket.
//!
//! Linux-only: the daemon authorizes connections by SO_PEERCRED, which only
//! exists on Linux, so this spawns a real Linux binary and is skipped elsewhere.
#![cfg(target_os = "linux")]

use greendot_proto::pb;
use greendot_proto::pb::helper_client::HelperClient;
use greendot_proto::{DatasetName, KernelModule, Request, Response, SubStatus, TaskEvent};
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::Channel;

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
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_greendotctl"))
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

    fn client(&self) -> HelperClient<Channel> {
        greendot_proto::client::connect_uds(self.socket.clone()).unwrap()
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Sends a task request and collects the streamed events up to Finished.
async fn run_task(client: &mut HelperClient<Channel>, req: pb::Request) -> Vec<TaskEvent> {
    let mut stream = client.run_task(req).await.unwrap().into_inner();
    let mut events = Vec::new();
    while let Some(ev) = stream.message().await.unwrap() {
        events.push(TaskEvent::try_from(ev).unwrap());
    }
    events
}

#[tokio::test]
async fn ping_streamed_task_oneshot_and_validation() {
    let helper = Helper::start();
    let mut client = helper.client();

    // Ping is one-shot (unary Call) and works repeatedly on one channel.
    for _ in 0..2 {
        let resp = client
            .call(pb::Request::from(Request::Ping))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(Response::try_from(resp).unwrap(), Response::Ok);
    }

    // A task op streams Started..Finished. `zfs` is absent in the dev shell,
    // so this exercises the missing-binary install hint over the real socket.
    let events = run_task(
        &mut client,
        pb::Request::from(Request::ZvolDelete {
            dataset: DatasetName::new("tank/x").unwrap(),
        }),
    )
    .await;
    assert!(
        matches!(events.first(), Some(TaskEvent::SubtaskStarted { command: Some(cmd), .. }) if cmd == "zfs")
    );
    match events.last() {
        Some(TaskEvent::Finished {
            status: SubStatus::Failed,
            error: Some(msg),
        }) => assert!(msg.contains("zfs is not installed"), "{msg}"),
        other => panic!("expected Finished with install hint, got {other:?}"),
    }

    // EnsureModules with an empty set is a one-shot Ok: over RunTask it becomes a
    // one-subtask task ending in a successful Finished (no command to run).
    let events = run_task(
        &mut client,
        pb::Request::from(Request::EnsureModules {
            modules: Vec::<KernelModule>::new(),
        }),
    )
    .await;
    assert!(matches!(
        events.last(),
        Some(TaskEvent::Finished {
            status: SubStatus::Success,
            ..
        })
    ));

    // A request that fails validation at the proto->domain boundary is reported
    // as a failed task (the daemon re-validates every field on ingress). Build
    // the protobuf directly, since the domain type would refuse to construct it.
    let bad = pb::Request {
        op: Some(pb::request::Op::ZvolDelete(pb::ZvolDelete {
            dataset: "../etc".into(),
        })),
    };
    let events = run_task(&mut client, bad).await;
    match events.last() {
        Some(TaskEvent::Finished {
            status: SubStatus::Failed,
            error: Some(msg),
        }) => assert!(msg.contains("invalid request"), "{msg}"),
        other => panic!("expected rejected task, got {other:?}"),
    }
}
