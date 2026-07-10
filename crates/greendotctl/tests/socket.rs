//! End-to-end test against the real helper binary over gRPC on a unix socket.
//!
//! Linux-only: the daemon authorizes connections by SO_PEERCRED, which only
//! exists on Linux, so this spawns a real Linux binary and is skipped elsewhere.
#![cfg(target_os = "linux")]

use greendot_proto::pb;
use greendot_proto::pb::helper_client::HelperClient;
use greendot_proto::{AuthResult, CsiNqn, DatasetName, ErrKind, Nqn, SubStatus, TaskEvent, ops};
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

/// Drains a task rpc's stream up to its terminal event.
async fn drain(mut stream: tonic::Streaming<pb::TaskEvent>) -> Vec<TaskEvent> {
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

    // Ping is one-shot (unary) and works repeatedly on one channel.
    for _ in 0..2 {
        client.ping(pb::Empty {}).await.unwrap();
    }

    // A task op streams Started..Finished. `zfs` is absent in the dev shell,
    // so this exercises the missing-binary install hint over the real socket.
    let op = ops::ZvolDelete {
        dataset: DatasetName::new("tank/x").unwrap(),
    };
    let events = drain(
        client
            .zvol_delete(pb::ZvolDelete::from(op))
            .await
            .unwrap()
            .into_inner(),
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

    // InstallPackages with an empty set is a successful no-op task (one
    // subtask, no command to run).
    let events = drain(
        client
            .install_packages(pb::InstallPackages { packages: vec![] })
            .await
            .unwrap()
            .into_inner(),
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
    // the protobuf directly, since the domain op would refuse to construct it.
    let events = drain(
        client
            .zvol_delete(pb::ZvolDelete {
                dataset: "../etc".into(),
            })
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    match events.last() {
        Some(TaskEvent::Finished {
            status: SubStatus::Failed,
            error: Some(msg),
        }) => assert!(msg.contains("invalid request"), "{msg}"),
        other => panic!("expected rejected task, got {other:?}"),
    }

    // Authenticate validates its fields before PAM ever runs: an invalid
    // username comes back as a Validation error reply, not a task.
    let reply = client
        .authenticate(pb::Authenticate {
            username: "root; reboot".into(),
            password: "x".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        AuthResult::try_from(reply).unwrap(),
        AuthResult::Err {
            kind: ErrKind::Validation,
            ..
        }
    ));

    // A typed read answers with its reply message (no task stream). The drift
    // verdict itself depends on the host, so only the reply path is asserted.
    client
        .reconcile_dry_run(pb::Empty {})
        .await
        .expect("typed read must answer");
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

    let events = tokio::time::timeout(Duration::from_secs(60), async {
        drain(
            client
                .reconcile(pb::Reconcile {})
                .await
                .unwrap()
                .into_inner(),
        )
        .await
    })
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

fn task_status(events: &[TaskEvent]) -> SubStatus {
    match events.last() {
        Some(TaskEvent::Finished { status, .. }) => *status,
        other => panic!("task did not finish: {other:?}"),
    }
}

/// The CSI lifecycle over the real socket against a `--nvmet-root` tempdir:
/// apply → grant → revoke (the fence) → delete, plus ingress rejection of a
/// web-prefix NQN — the ownership boundary enforced at the choke point.
#[tokio::test]
async fn csi_ops_drive_the_nvmet_root_end_to_end() {
    let dir = test_dir("csi");
    let root = dir.join("nvmet");
    std::fs::create_dir_all(&root).unwrap();
    let helper = Helper::start(&["--nvmet-root", root.to_str().unwrap()]);
    let mut client = helper.client();

    let nqn = CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap();
    let host = Nqn::new("nqn.2014-08.org.nvmexpress:host1").unwrap();
    let apply = ops::CsiNvmeApply {
        nqn: nqn.clone(),
        // A device node that exists everywhere: the apply op waits for the
        // node before touching configfs (the zvol/udev race), and this test
        // has no real zvol.
        device_path: greendot_proto::DevicePath::new("/dev/null").unwrap(),
        device_uuid: greendot_proto::NsUuid::new("58668891-c3e4-45d0-b90e-824525c16080").unwrap(),
        traddr: "10.0.0.5".parse().unwrap(),
        trsvcid: 4421,
        transport: greendot_proto::Transport::Rdma,
    };

    let events = drain(
        client
            .csi_nvme_apply(pb::CsiNvmeApply::from(apply))
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success, "{events:?}");
    let subsys = root.join("subsystems/nqn.2026-06.io.greendot.csi:pvc-1");
    assert_eq!(
        std::fs::read_to_string(subsys.join("namespaces/1/device_uuid")).unwrap(),
        "58668891-c3e4-45d0-b90e-824525c16080"
    );

    let events = drain(
        client
            .csi_host_grant(pb::CsiHostGrant::from(ops::CsiHostGrant {
                nqn: nqn.clone(),
                hostnqn: host.clone(),
            }))
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success);

    let events = drain(
        client
            .csi_host_revoke(pb::CsiHostRevoke::from(ops::CsiHostRevoke {
                nqn: nqn.clone(),
                hostnqn: host,
            }))
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success);
    assert!(
        subsys
            .join("allowed_hosts/nqn.2014-08.org.nvmexpress:host1")
            .symlink_metadata()
            .is_err(),
        "fence removed the grant"
    );

    let events = drain(
        client
            .csi_nvme_delete(pb::CsiNvmeDelete::from(ops::CsiNvmeDelete { nqn }))
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success);
    assert!(!subsys.exists());

    // A web-prefix NQN cannot reach the CSI ops: rejected at ingress, surfaced
    // as a failed task.
    let events = drain(
        client
            .csi_nvme_delete(pb::CsiNvmeDelete {
                nqn: "nqn.2026-06.io.greendot:vm1".into(),
            })
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    match events.last() {
        Some(TaskEvent::Finished {
            status: SubStatus::Failed,
            error: Some(msg),
        }) => assert!(msg.contains("invalid request"), "{msg}"),
        other => panic!("expected rejected task, got {other:?}"),
    }
}

/// gRPC/h2 through a spawned `greendotctl pipe` child's stdio — exactly the
/// byte path the SSH forced command gives the CSI controller. Ping and a task
/// stream must both survive the relay.
#[tokio::test]
async fn pipe_relays_grpc_over_stdio() {
    let helper = Helper::start(&[]);
    // Wait for the daemon socket to accept (Helper::start only polls existence).
    let mut client = helper.client();
    client.ping(pb::Empty {}).await.unwrap();

    let socket = helper.socket.clone();
    let connector = tower::service_fn(move |_uri| {
        let socket = socket.clone();
        async move {
            let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_greendotctl"))
                .arg("pipe")
                .arg(&socket)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            let stdout = child.stdout.take().unwrap();
            let stdin = child.stdin.take().unwrap();
            // The child must outlive the connection; parking it in a task tied
            // to nothing keeps kill_on_drop from firing until the test ends.
            tokio::spawn(async move { child.wait().await });
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tokio::io::join(stdout, stdin)))
        }
    });
    let channel = tonic::transport::Endpoint::try_from("http://[::1]:50051")
        .unwrap()
        .connect_with_connector_lazy(connector);
    let mut piped = HelperClient::new(channel);

    piped.ping(pb::Empty {}).await.expect("ping over the pipe");
    let events = drain(
        piped
            .install_packages(pb::InstallPackages { packages: vec![] })
            .await
            .expect("task rpc over the pipe")
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success, "{events:?}");
}

/// The pipe-key ops over the real socket: the daemon writes the file, the
/// options are the daemon's own forced command (the request cannot name one),
/// and a hostile paste is rejected by the ingress middleware — prost does not
/// validate, so this is the choke point that matters.
#[tokio::test]
async fn pipe_key_ops_write_authorized_keys_and_reject_hostile_pastes() {
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 admin@laptop";
    const FP: &str = "SHA256:NEU/y0JmR4RY7ck8XRGElQSKmEzy2SirhXgqbFWxZ00";

    let dir = test_dir("pipekeys");
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    // A real executable, so the report's forced-command criterion holds.
    let pipe_bin = std::env::current_exe().unwrap();
    let helper = Helper::start(&[
        "--pipe-home",
        home.to_str().unwrap(),
        "--pipe-command",
        pipe_bin.to_str().unwrap(),
    ]);
    let mut client = helper.client();
    let authorized_keys = home.join(".ssh/authorized_keys");
    let forced = format!("command=\"{} pipe\",restrict", pipe_bin.display());

    // A paste that would smuggle a second, shell-granting line. The wire type
    // carries it happily; the daemon's TryFrom must not.
    let hostile = format!("{KEY}\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 evil");
    let events = drain(
        client
            .pipe_key_add(pb::PipeKeyAdd {
                public_key: hostile,
            })
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    match events.last() {
        Some(TaskEvent::Finished {
            status: SubStatus::Failed,
            error: Some(msg),
        }) => assert!(msg.contains("invalid request"), "{msg}"),
        other => panic!("expected rejected task, got {other:?}"),
    }
    assert!(!authorized_keys.exists(), "nothing was written");

    // The happy path: one line, carrying the daemon's own forced command.
    let events = drain(
        client
            .pipe_key_add(pb::PipeKeyAdd {
                public_key: KEY.into(),
            })
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success, "{events:?}");
    assert_eq!(
        std::fs::read_to_string(&authorized_keys).unwrap(),
        format!("{forced} {KEY}\n")
    );

    // The report is what the page and its diagnostic render.
    let report = client
        .pipe_access_report(pb::Empty {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(report.forced_command, forced);
    assert!(report.forced_command_bin_ok);
    assert_eq!(report.keys.len(), 1);
    assert_eq!(report.keys[0].fingerprint, FP);
    assert!(report.keys[0].forced_command_ok);
    assert_eq!(report.unparsable_lines, 0);

    // Revoke by fingerprint; a malformed one is rejected on ingress and the
    // file is left exactly as it was.
    let events = drain(
        client
            .pipe_key_revoke(pb::PipeKeyRevoke {
                fingerprint: "../../etc/shadow".into(),
            })
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Failed, "{events:?}");
    assert_eq!(
        std::fs::read_to_string(&authorized_keys).unwrap(),
        format!("{forced} {KEY}\n")
    );

    let events = drain(
        client
            .pipe_key_revoke(pb::PipeKeyRevoke {
                fingerprint: FP.into(),
            })
            .await
            .unwrap()
            .into_inner(),
    )
    .await;
    assert_eq!(task_status(&events), SubStatus::Success, "{events:?}");
    assert_eq!(std::fs::read_to_string(&authorized_keys).unwrap(), "");
}
