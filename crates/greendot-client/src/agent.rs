//! The root agent and the broker that reaches it. `greendot-client agent`
//! serves newline-delimited JSON over a Unix socket (0660, group
//! `greendot-client`), gated per connection by SO_PEERCRED — uid 0 or a
//! member of the group. One request line in, one reply line out. The agent
//! never touches the network: it only runs the [`crate::privops`] primitives
//! and owns writes to targets.toml.
//!
//! The CLI side ([`Broker`]) prefers the agent socket, falls back to running
//! the op in-process when it is already root, and otherwise errors with a
//! how-to-fix hint.

use crate::config::TargetEntry;
use crate::privops::{self, PrivPaths};
use anyhow::{Context, Result, bail};
use greendot_proto::{Nqn, Transport};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

pub const DEFAULT_SOCKET: &str = "/run/greendot-client/agent.sock";
pub const DEFAULT_GROUP: &str = "greendot-client";
/// Ceiling on one request/reply line (mirrors the daemon's MAX_MESSAGE).
const MAX_LINE: usize = 256 * 1024;

/// The agent's entire allowlist. Validated newtypes and typed values do the
/// same job as in greendotctl: deserializing a request re-runs the
/// validators, so no field can smuggle a comma into the fabrics string or an
/// option into an argv.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentOp {
    Ping,
    EnsureHostnqn,
    ConnectNvme {
        nqn: Nqn,
        transport: Transport,
        traddr: IpAddr,
        trsvcid: u16,
        hostnqn: Nqn,
    },
    DisconnectNvme {
        nqn: Nqn,
    },
    MountNfs {
        host: String,
        path: String,
        mountpoint: String,
        rdma: bool,
        port: u16,
    },
    UnmountNfs {
        mountpoint: String,
    },
    AddTarget {
        entry: TargetEntry,
    },
    RemoveTarget {
        name: String,
    },
}

/// Executes one op against the real system. Shared verbatim by the agent
/// loop and the run-as-root fallback.
pub fn execute(op: &AgentOp, paths: &PrivPaths, config_dir: &Path) -> Result<Value> {
    match op {
        AgentOp::Ping => Ok(json!({})),
        AgentOp::EnsureHostnqn => {
            let hostnqn = privops::ensure_hostnqn(&paths.etc_nvme)?;
            Ok(json!({ "hostnqn": hostnqn }))
        }
        AgentOp::ConnectNvme {
            nqn,
            transport,
            traddr,
            trsvcid,
            hostnqn,
        } => {
            let device = privops::connect_nvme(paths, nqn, *transport, *traddr, *trsvcid, hostnqn)?;
            Ok(json!({ "device": device }))
        }
        AgentOp::DisconnectNvme { nqn } => {
            let deleted = privops::disconnect_nvme(&paths.sys.sys_class_nvme, nqn)?;
            Ok(json!({ "deleted": deleted }))
        }
        AgentOp::MountNfs {
            host,
            path,
            mountpoint,
            rdma,
            port,
        } => {
            privops::mount_nfs(host, path, mountpoint, *rdma, *port)?;
            Ok(json!({ "mountpoint": mountpoint }))
        }
        AgentOp::UnmountNfs { mountpoint } => {
            privops::unmount_nfs(mountpoint)?;
            Ok(json!({}))
        }
        AgentOp::AddTarget { entry } => {
            crate::config::Targets::load(config_dir)?.add(entry.clone())?;
            Ok(json!({ "name": entry.name }))
        }
        AgentOp::RemoveTarget { name } => {
            let removed = crate::config::Targets::load(config_dir)?.remove(name)?;
            Ok(json!({ "name": removed.name, "host": removed.host }))
        }
    }
}

// ---- the agent server ----

pub struct AgentOpts {
    pub socket: PathBuf,
    pub group: String,
    pub config_dir: PathBuf,
    pub paths: PrivPaths,
    /// Test mode: also allow this uid (like greendotctl --allow-uid).
    pub allow_uid: Option<u32>,
}

pub fn serve(opts: &AgentOpts) -> Result<()> {
    if let Some(dir) = opts.socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&opts.socket);
    let listener = UnixListener::bind(&opts.socket)
        .with_context(|| format!("binding {}", opts.socket.display()))?;
    std::fs::set_permissions(
        &opts.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    )?;
    let gid = nix::unistd::Group::from_name(&opts.group)?.map(|g| g.gid);
    if let Some(gid) = gid {
        nix::unistd::chown(&opts.socket, None, Some(gid))?;
    } else if opts.allow_uid.is_none() {
        eprintln!(
            "warning: group {:?} does not exist — only root can connect",
            opts.group
        );
    }
    eprintln!(
        "greendot-client agent listening on {}",
        opts.socket.display()
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        match peer_uid(&stream) {
            Ok(uid) if peer_allowed(uid, opts.allow_uid, gid, user_groups) => {}
            Ok(uid) => {
                eprintln!("rejecting connection from unauthorized uid {uid}");
                continue;
            }
            Err(e) => {
                eprintln!("could not read peer credentials: {e}");
                continue;
            }
        }
        if let Err(e) = handle(stream, &opts.paths, &opts.config_dir) {
            eprintln!("request failed: {e:#}");
        }
    }
    Ok(())
}

/// One request line, one reply line. Ops run synchronously — connects/mounts
/// are seconds-long and the CLI waits anyway; a wedged NFS server can stall
/// the agent for other callers, which is acceptable for a per-host tool.
fn handle(stream: UnixStream, paths: &PrivPaths, config_dir: &Path) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_LINE as u64);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let reply = match serde_json::from_str::<AgentOp>(&line) {
        Ok(op) => match execute(&op, paths, config_dir) {
            Ok(value) => ok_reply(value),
            Err(e) => json!({ "ok": false, "error": format!("{e:#}") }),
        },
        Err(e) => json!({ "ok": false, "error": format!("bad request: {e}") }),
    };
    let mut stream = stream;
    writeln!(stream, "{reply}")?;
    Ok(())
}

fn ok_reply(mut value: Value) -> Value {
    value
        .as_object_mut()
        .expect("execute returns objects")
        .insert("ok".into(), Value::Bool(true));
    value
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> nix::Result<u32> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(creds.uid())
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> nix::Result<u32> {
    Err(nix::errno::Errno::ENOSYS)
}

/// Root always; the test uid when given; otherwise members of the socket
/// group (supplementary groups included — SO_PEERCRED only carries the uid).
fn peer_allowed(
    uid: u32,
    allow_uid: Option<u32>,
    gid: Option<nix::unistd::Gid>,
    groups_of: impl Fn(u32) -> Option<Vec<nix::unistd::Gid>>,
) -> bool {
    uid == 0
        || allow_uid == Some(uid)
        || gid.is_some_and(|gid| groups_of(uid).is_some_and(|groups| groups.contains(&gid)))
}

fn user_groups(uid: u32) -> Option<Vec<nix::unistd::Gid>> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    let name = std::ffi::CString::new(user.name).ok()?;
    nix::unistd::getgrouplist(&name, user.gid).ok()
}

// ---- the CLI-side broker ----

/// How a privileged op will run: through the agent socket, or in-process
/// because we are already root.
pub enum Broker {
    Agent(PathBuf),
    Direct {
        paths: PrivPaths,
        config_dir: PathBuf,
    },
}

impl Broker {
    /// Agent socket if connectable → else direct if euid 0 → else a hint.
    pub fn locate(socket: &Path, paths: PrivPaths, config_dir: &Path) -> Result<Broker> {
        if UnixStream::connect(socket).is_ok() {
            return Ok(Broker::Agent(socket.to_owned()));
        }
        if nix::unistd::geteuid().is_root() {
            return Ok(Broker::Direct {
                paths,
                config_dir: config_dir.to_owned(),
            });
        }
        bail!(
            "the greendot-client agent is not running at {} and you are not root — \
             `systemctl start greendot-client-agent`, or re-run under sudo",
            socket.display()
        )
    }

    pub fn call(&self, op: &AgentOp) -> Result<Value> {
        match self {
            Broker::Direct { paths, config_dir } => execute(op, paths, config_dir),
            Broker::Agent(socket) => {
                let mut stream = UnixStream::connect(socket)
                    .with_context(|| format!("connecting {}", socket.display()))?;
                writeln!(stream, "{}", serde_json::to_string(op)?)?;
                let mut reader = BufReader::new(stream).take(MAX_LINE as u64);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                let reply: Value =
                    serde_json::from_str(&line).context("agent sent a malformed reply")?;
                if reply["ok"].as_bool() != Some(true) {
                    bail!(
                        "agent: {}",
                        reply["error"].as_str().unwrap_or("unknown error")
                    );
                }
                Ok(reply)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Ops round-trip through serde with their validators re-run on decode.
    #[test]
    fn agent_op_serde_revalidates() {
        let op = AgentOp::ConnectNvme {
            nqn: Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap(),
            transport: Transport::Rdma,
            traddr: "10.0.0.5".parse().unwrap(),
            trsvcid: 4420,
            hostnqn: Nqn::new("nqn.2014-08.org.nvmexpress:uuid:h1").unwrap(),
        };
        let wire = serde_json::to_string(&op).unwrap();
        assert!(wire.contains(r#""op":"connect_nvme""#), "{wire}");
        let back: AgentOp = serde_json::from_str(&wire).unwrap();
        assert!(matches!(back, AgentOp::ConnectNvme { .. }));

        // A comma smuggled into the nqn is rejected at decode — the validator
        // runs inside Deserialize, so `execute` can never see it.
        let evil = wire.replace("greendot:vm1", "greendot:vm1,transport=tcp");
        assert!(serde_json::from_str::<AgentOp>(&evil).is_err());
        // Same for a non-IP traddr.
        let evil = wire.replace("10.0.0.5", "evil,host");
        assert!(serde_json::from_str::<AgentOp>(&evil).is_err());
    }

    #[rstest]
    #[case(0, None, false, true)] // root always
    #[case(1000, Some(1000), false, true)] // test uid
    #[case(1000, None, true, true)] // group member
    #[case(1000, None, false, false)] // plain user
    #[case(1001, Some(1000), false, false)] // different uid, not in group
    fn peer_gating(
        #[case] uid: u32,
        #[case] allow_uid: Option<u32>,
        #[case] in_group: bool,
        #[case] expect: bool,
    ) {
        let gid = nix::unistd::Gid::from_raw(4242);
        let groups_of = |_uid: u32| Some(if in_group { vec![gid] } else { vec![] });
        assert_eq!(
            peer_allowed(uid, allow_uid, Some(gid), groups_of),
            expect,
            "uid={uid} allow={allow_uid:?} in_group={in_group}"
        );
    }
}
