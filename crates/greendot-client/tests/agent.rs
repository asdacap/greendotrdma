//! End-to-end test against the real agent binary over its unix socket.
//! Linux-only: the agent authorizes by SO_PEERCRED.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Agent {
    child: std::process::Child,
    socket: PathBuf,
    root: PathBuf,
}

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

impl Agent {
    fn start(allow_self: bool) -> Self {
        let root = test_dir("a");
        std::fs::create_dir_all(root.join("sys/class/nvme")).unwrap();
        let socket = root.join("agent.sock");
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_greendot-client"));
        cmd.args([
            "--socket",
            socket.to_str().unwrap(),
            "--config-dir",
            root.join("etc").to_str().unwrap(),
            "--sys-root",
            root.to_str().unwrap(),
            "agent",
            // A group we are certainly not in, so allow-uid is the only grant.
            "--group",
            "gd-client-no-such-group",
        ]);
        if allow_self {
            cmd.args(["--allow-uid", &nix::unistd::getuid().to_string()]);
        }
        let child = cmd.spawn().unwrap();
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Agent {
            child,
            socket,
            root,
        }
    }

    fn call(&self, request: &str) -> Option<serde_json::Value> {
        let mut stream = UnixStream::connect(&self.socket).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        writeln!(stream, "{request}").ok()?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).ok()?;
        (!line.is_empty()).then(|| serde_json::from_str(&line).unwrap())
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ok(v: &serde_json::Value) -> bool {
    v["ok"].as_bool() == Some(true)
}

#[test]
fn agent_ops_and_gating() {
    let agent = Agent::start(true);

    // Ping.
    let v = agent.call(r#"{"op":"ping"}"#).expect("reply");
    assert!(ok(&v), "{v}");

    // Bad request line: an error reply, and the agent stays up.
    let v = agent.call(r#"{"op":"launch_missiles"}"#).expect("reply");
    assert!(!ok(&v));
    assert!(v["error"].as_str().unwrap().contains("bad request"), "{v}");

    // A comma smuggled into an nqn is rejected by the validator on decode.
    let v = agent
        .call(r#"{"op":"disconnect_nvme","nqn":"nqn.x,evil=1"}"#)
        .expect("reply");
    assert!(!ok(&v), "{v}");

    // EnsureHostnqn generates once under the sys root, then reuses.
    let v = agent.call(r#"{"op":"ensure_hostnqn"}"#).expect("reply");
    assert!(ok(&v), "{v}");
    let nqn = v["hostnqn"].as_str().unwrap().to_owned();
    assert!(nqn.starts_with("nqn.2014-08.org.nvmexpress:uuid:"), "{nqn}");
    let again = agent.call(r#"{"op":"ensure_hostnqn"}"#).expect("reply");
    assert_eq!(again["hostnqn"].as_str().unwrap(), nqn);
    let on_disk = std::fs::read_to_string(agent.root.join("etc/nvme/hostnqn")).unwrap();
    assert_eq!(on_disk.trim(), nqn);

    // Disconnect with nothing connected: ok, zero controllers deleted.
    let v = agent
        .call(r#"{"op":"disconnect_nvme","nqn":"nqn.2026-06.io.greendot:vm1"}"#)
        .expect("reply");
    assert!(ok(&v));
    assert_eq!(v["deleted"].as_u64(), Some(0));

    // Target store writes go through the agent: add, duplicate rejected,
    // remove; the file lands under the agent's --config-dir, mode 0640.
    let add = r#"{"op":"add_target","entry":{"name":"nas1","host":"10.0.0.5:8443","token":"gdt_x","cert_sha256":null}}"#;
    let v = agent.call(add).expect("reply");
    assert!(ok(&v), "{v}");
    let v = agent.call(add).expect("reply");
    assert!(!ok(&v) && v["error"].as_str().unwrap().contains("already exists"));
    let mode = std::os::unix::fs::MetadataExt::mode(
        &std::fs::metadata(agent.root.join("etc/targets.toml")).unwrap(),
    );
    assert_eq!(mode & 0o777, 0o640);
    let v = agent
        .call(r#"{"op":"remove_target","name":"nas1"}"#)
        .expect("reply");
    assert!(ok(&v));
    assert_eq!(v["host"].as_str(), Some("10.0.0.5:8443"));

    // Mount validation runs before any exec: traversal/whitespace rejected.
    let v = agent
        .call(r#"{"op":"mount_nfs","host":"10.0.0.5","path":"/tank/../etc","mountpoint":"/mnt/x","rdma":true,"port":20049}"#)
        .expect("reply");
    assert!(
        !ok(&v) && v["error"].as_str().unwrap().contains("unsafe path"),
        "{v}"
    );
    let v = agent
        .call(r#"{"op":"unmount_nfs","mountpoint":"/mnt/has space"}"#)
        .expect("reply");
    assert!(!ok(&v), "{v}");
}

#[test]
fn agent_rejects_ungranted_peer() {
    // No --allow-uid and a nonexistent group: our (non-root) uid must be
    // rejected — the connection is dropped without a reply.
    if nix::unistd::getuid().is_root() {
        eprintln!("running as root — gating cannot be exercised, skipping");
        return;
    }
    let agent = Agent::start(false);
    assert!(
        agent.call(r#"{"op":"ping"}"#).is_none(),
        "ungranted peer must get no reply"
    );
    // The agent survives the rejection (a granted sibling still works — start
    // a second agent with the grant to prove the binary itself is fine).
    drop(agent);
    let granted = Agent::start(true);
    assert!(ok(&granted.call(r#"{"op":"ping"}"#).expect("reply")));
}

/// The CLI broker falls back with a helpful error when there is no agent and
/// we are not root.
#[test]
fn cli_hints_when_agent_missing() {
    if nix::unistd::getuid().is_root() {
        return;
    }
    let dir = test_dir("c");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_greendot-client"))
        .args([
            "--socket",
            dir.join("nope.sock").to_str().unwrap(),
            "--config-dir",
            dir.to_str().unwrap(),
            "disconnect",
            "t",
            "vm1",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent is not running") && stderr.contains("sudo"),
        "{stderr}"
    );
}

/// `list` renders local status from fixture /sys and /proc trees without any
/// reachable target (the target rows show unreachable, exports empty).
#[test]
fn list_works_offline_with_fixtures() {
    let root = test_dir("l");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(
        root.join("etc/targets.toml"),
        "[[target]]\nname = \"nas1\"\nhost = \"127.0.0.1:1\"\ntoken = \"gdt_x\"\n",
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_greendot-client"))
        .args([
            "--json",
            "--config-dir",
            root.join("etc").to_str().unwrap(),
            "--sys-root",
            root.to_str().unwrap(),
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    let t = &v["targets"][0];
    assert_eq!(t["name"], "nas1");
    assert_eq!(t["reachable"], false);
    assert!(
        t["error"].as_str().unwrap().contains("could not reach"),
        "{t}"
    );
}
