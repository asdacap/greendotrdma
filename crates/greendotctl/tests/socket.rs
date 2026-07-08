//! End-to-end test against the real helper binary over gRPC on a unix socket.
//!
//! Linux-only: the daemon authorizes connections by SO_PEERCRED, which only
//! exists on Linux, so this spawns a real Linux binary and is skipped elsewhere.
#![cfg(target_os = "linux")]

use greendot_proto::pb;
use greendot_proto::pb::helper_client::HelperClient;
use greendot_proto::{
    CallRequest, DatasetName, KernelModule, Response, SubStatus, TaskEvent, TaskRequest,
};
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::Channel;

struct Helper {
    child: std::process::Child,
    socket: PathBuf,
}

/// A fresh scratch dir, unique per call: tests in this binary run in parallel
/// threads of one process, so a pid-only name would race two tests on one dir.
fn test_dir(prefix: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{prefix}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

impl Helper {
    fn start(extra_args: &[&str]) -> Self {
        let dir = test_dir("h");
        let socket = dir.join("helper.sock");
        let uid = nix::unistd::getuid().to_string();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_greendotctl"))
            .args(["--socket", socket.to_str().unwrap(), "--allow-uid", &uid])
            .args(extra_args)
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
async fn run_task(client: &mut HelperClient<Channel>, req: pb::TaskRequest) -> Vec<TaskEvent> {
    let mut stream = client.run_task(req).await.unwrap().into_inner();
    let mut events = Vec::new();
    while let Some(ev) = stream.message().await.unwrap() {
        events.push(TaskEvent::try_from(ev).unwrap());
    }
    events
}

#[tokio::test]
async fn ping_streamed_task_oneshot_and_validation() {
    let helper = Helper::start(&[]);
    let mut client = helper.client();

    // Ping is one-shot (unary Call) and works repeatedly on one channel.
    for _ in 0..2 {
        let resp = client
            .call(pb::CallRequest::from(CallRequest::Ping))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(Response::try_from(resp).unwrap(), Response::Ok);
    }

    // A task op streams Started..Finished. `zfs` is absent in the dev shell,
    // so this exercises the missing-binary install hint over the real socket.
    let events = run_task(
        &mut client,
        pb::TaskRequest::from(TaskRequest::ZvolDelete {
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
        pb::TaskRequest::from(TaskRequest::EnsureModules {
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
    let bad = pb::TaskRequest {
        op: Some(pb::task_request::Op::ZvolDelete(pb::ZvolDelete {
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

/// Reconcile runs inline in the daemon: it loads the daemon's own `--config`
/// (the request carries no path), reads the desired-state TOML, and streams
/// one subtask per area — applied or `Skipped` — ending in exactly one
/// terminal `Finished`. Unprivileged here, so applies against the real
/// configfs fail; the point is the framing: every area shows up and the
/// stream terminates (failure, not a hang).
#[tokio::test]
async fn reconcile_streams_one_subtask_per_area_and_terminates() {
    let dir = test_dir("rec");
    std::fs::write(
        dir.join("state.toml"),
        r#"
[[nvme_export]]
id = 1
name = "vm1"
device_path = "/dev/zvol/tank/vm1"
enabled = true
want_rdma = false
want_tcp = true
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("config.toml"),
        format!(
            "state_path = \"{state}\"\nnvmet_root = \"{root}\"\nlio_root = \"{root}\"\n",
            state = dir.join("state.toml").display(),
            root = dir.join("empty").display(),
        ),
    )
    .unwrap();
    let config = dir.join("config.toml");
    let helper = Helper::start(&["--config", config.to_str().unwrap()]);
    let mut client = helper.client();

    let events = tokio::time::timeout(
        Duration::from_secs(60),
        run_task(&mut client, pb::TaskRequest::from(TaskRequest::Reconcile)),
    )
    .await
    .expect("reconcile stream must terminate, not hang");

    let names: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            TaskEvent::SubtaskStarted { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        [
            "Load kernel modules",
            "Apply NVMe-oF configuration",
            "Apply iSCSI configuration",
            "Apply NFS configuration",
        ],
        "every area must appear as a subtask; events: {events:?}"
    );
    let finished = events
        .iter()
        .filter(|e| matches!(e, TaskEvent::Finished { .. }))
        .count();
    assert!(
        finished == 1 && matches!(events.last(), Some(TaskEvent::Finished { .. })),
        "exactly one terminal Finished; events: {events:?}"
    );
}
