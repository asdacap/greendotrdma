//! `greendot-client`: the initiator-side companion of a GreenDotRDMA target.
//! Paste a connection string from the target's Client access page (`add`),
//! then `list` its exports and `connect`/`mount` them — the client registers
//! itself (host NQN for NVMe-oF, its IP for NFS) through the target's JSON
//! API, so no manual ACL editing is needed on either side.
//!
//! Privileged steps (fabrics writes, mounts, targets.toml) go through the
//! root agent (`greendot-client agent`, a small systemd service) when its
//! socket is up, or run in-process under sudo. Output is human text, or
//! stable JSON with `--json` (the desktop GUI drives the CLI this way).

mod agent;
mod api;
mod config;
mod diagnose;
mod pairing;
mod privops;
mod status;

use agent::{AgentOp, Broker};
use anyhow::{Context, Result, bail};
use config::Targets;
use greendot_proto::{Nqn, OUR_NQN_PREFIX, Transport};
use serde_json::json;
use std::net::IpAddr;
use std::path::PathBuf;

struct Global {
    json: bool,
    config_dir: PathBuf,
    socket: PathBuf,
    /// Root for /dev, /sys, /proc, /etc/nvme (tests use fixture trees).
    sys_root: PathBuf,
}

impl Global {
    fn broker(&self) -> Result<Broker> {
        Broker::locate(
            &self.socket,
            privops::PrivPaths::at(&self.sys_root),
            &self.config_dir,
        )
    }

    fn sys(&self) -> status::SysRoots {
        status::SysRoots::at(&self.sys_root)
    }
}

const USAGE: &str =
    "usage: greendot-client [--json] [--config-dir <dir>] [--socket <path>] <command>

commands:
  add <connection-string> [--name <alias>]     pair with a target (string from
                                               its web UI's Client access page)
  remove <target>                              forget a target
  list                                         targets, exports, and their dots
  connect <target> <export> [--transport rdma|tcp]
                                               register + connect a block export
  disconnect <target> <export>                 disconnect a block export
  mount <target> <export> [<mountpoint>] [--tcp]
                                               register + mount an NFS export
  unmount <target> <export>                    unmount an NFS export
  diagnose [<target> [<export>]]               why isn't my dot green?
  agent [--group <name>] [--allow-uid <uid>]   run the root agent (systemd)
";

fn main() {
    let mut global = Global {
        json: false,
        config_dir: config::DEFAULT_CONFIG_DIR.into(),
        socket: agent::DEFAULT_SOCKET.into(),
        sys_root: "/".into(),
    };
    // Global flags may appear anywhere; everything else is cmd + its args.
    let mut rest = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |global_field: &mut PathBuf| match args.next() {
            Some(v) => {
                *global_field = v.into();
                true
            }
            None => false,
        };
        match arg.as_str() {
            "--json" => global.json = true,
            "--config-dir" => {
                if !value(&mut global.config_dir) {
                    return usage_exit();
                }
            }
            "--socket" => {
                if !value(&mut global.socket) {
                    return usage_exit();
                }
            }
            "--sys-root" => {
                if !value(&mut global.sys_root) {
                    return usage_exit();
                }
            }
            _ => rest.push(arg),
        }
    }
    let mut args = rest.into_iter();
    let Some(cmd) = args.next() else {
        return usage_exit();
    };
    let result = match cmd.as_str() {
        "add" => cmd_add(&global, &mut args),
        "remove" => cmd_remove(&global, &mut args),
        "list" => cmd_list(&global, &mut args),
        "connect" => cmd_connect(&global, &mut args),
        "disconnect" => cmd_disconnect(&global, &mut args),
        "mount" => cmd_mount(&global, &mut args),
        "unmount" => cmd_unmount(&global, &mut args),
        "diagnose" => cmd_diagnose(&global, &mut args),
        "agent" => cmd_agent(&global, &mut args),
        _ => {
            eprintln!("unknown command {cmd:?}\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        if global.json {
            println!("{}", json!({ "ok": false, "error": format!("{e:#}") }));
        } else {
            eprintln!("error: {e:#}");
        }
        std::process::exit(1);
    }
}

fn usage_exit() {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

/// The one flag-style option the paired-argument commands take.
fn opt_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<Option<String>> {
    match args.next() {
        None => Ok(None),
        Some(f) if f == flag => Ok(Some(
            args.next()
                .with_context(|| format!("{flag} needs a value"))?,
        )),
        Some(other) => bail!("unknown argument {other:?}"),
    }
}

/// The host part of a pairing's `host[:port]` (IPv6 brackets kept for mount,
/// stripped by [`resolve_traddr`]).
fn host_only(host: &str) -> &str {
    if let Some(end) = host.strip_prefix('[').and_then(|_| host.find(']')) {
        return &host[..=end];
    }
    host.rsplit_once(':')
        .map(|(h, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                host
            }
        })
        .unwrap_or(host)
}

/// A concrete IP to write into the fabrics connect string when the target
/// listens on the unspecified address: the pairing host itself (resolved when
/// it is a hostname).
fn resolve_traddr(host: &str) -> Result<IpAddr> {
    let bare = host_only(host).trim_matches(['[', ']']);
    if let Ok(ip) = bare.parse() {
        return Ok(ip);
    }
    // Resolve via the OS (port irrelevant, required by the API).
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(bare, 4420))
        .with_context(|| format!("resolving {bare:?}"))?
        .next()
        .with_context(|| format!("{bare:?} resolves to no address"))?;
    Ok(addr.ip())
}

fn cmd_add(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let string = args.next().context("add needs a connection string")?;
    let name = opt_value(args, "--name")?;
    let pairing: pairing::Pairing = string.parse()?;

    // Reach the target first — this validates host, fingerprint, and token in
    // one round-trip and yields the default alias.
    let api = api::TargetApi::connect(&pairing)?;
    let info = api.target()?;
    let name = name.unwrap_or_else(|| {
        if info.name.is_empty() {
            pairing.host.clone()
        } else {
            info.name.clone()
        }
    });

    global.broker()?.call(&AgentOp::AddTarget {
        entry: config::TargetEntry {
            name: name.clone(),
            host: pairing.host.clone(),
            token: pairing.token.clone(),
            cert_sha256: pairing.fingerprint.clone(),
        },
    })?;
    if global.json {
        println!(
            "{}",
            json!({ "ok": true, "name": name, "host": pairing.host, "hostname": info.name })
        );
    } else {
        println!("added target {name} ({})", pairing.host);
    }
    Ok(())
}

fn cmd_remove(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let key = args.next().context("remove needs a target name or host")?;
    let reply = global
        .broker()?
        .call(&AgentOp::RemoveTarget { name: key })?;
    if global.json {
        println!("{}", json!({ "ok": true, "name": reply["name"] }));
    } else {
        println!(
            "removed target {} ({})",
            reply["name"].as_str().unwrap_or(""),
            reply["host"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

/// This machine's NVMe host NQN, when one exists and is readable.
fn read_hostnqn(global: &Global) -> Option<String> {
    let s = std::fs::read_to_string(global.sys_root.join("etc/nvme/hostnqn")).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

fn cmd_list(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    if let Some(extra) = args.next() {
        bail!("unknown argument {extra:?}");
    }
    let targets = Targets::load(&global.config_dir)?;
    let hostnqn = read_hostnqn(global);
    let sys = global.sys();
    let ctrls = status::nvme_controllers(&sys.sys_class_nvme);
    let mounts = status::nfs_mounts(&sys.proc_mounts);
    let mut out = Vec::new();
    for t in targets.list() {
        let fetched = api::TargetApi::connect(&t.pairing())
            .and_then(|api| Ok((api.target()?, api.exports(hostnqn.as_deref())?)));
        let (reachable, error, hostname, exports) = match fetched {
            Ok((info, exports)) => (true, None, info.name, Some(exports)),
            Err(e) => (false, Some(format!("{e:#}")), String::new(), None),
        };
        let mut rows = Vec::new();
        if let Some(exports) = &exports {
            for e in &exports.nvme {
                let (dot, reason, ctrl) = status::nvme_dot(&e.nqn, &ctrls);
                rows.push(json!({
                    "kind": "nvme",
                    "id": e.id,
                    "name": e.name,
                    "nqn": e.nqn,
                    "enabled": e.enabled,
                    "authorized": e.authorized,
                    "dot": dot.as_str(),
                    "reason": reason,
                    "transport": ctrl.filter(|c| c.state == "live").map(|c| c.transport.clone()),
                    "device": ctrl.and_then(|c| c.namespaces.first().cloned()),
                }));
            }
            for e in &exports.nfs {
                let (dot, reason, m) = status::nfs_dot(host_only(&t.host), &e.path, &mounts);
                rows.push(json!({
                    "kind": "nfs",
                    "id": e.id,
                    "name": e.path,
                    "path": e.path,
                    "enabled": e.enabled,
                    "authorized": e.authorized,
                    "rdma": e.rdma,
                    "port": e.port,
                    "dot": dot.as_str(),
                    "reason": reason,
                    "transport": m.map(|m| if m.rdma { "rdma" } else { "tcp" }),
                    "mountpoint": m.map(|m| m.mountpoint.clone()),
                }));
            }
        }
        out.push(json!({
            "name": t.name,
            "host": t.host,
            "hostname": hostname,
            "reachable": reachable,
            "error": error,
            "exports": rows,
        }));
    }
    if global.json {
        println!(
            "{}",
            json!({ "ok": true, "hostnqn": hostnqn, "targets": out })
        );
        return Ok(());
    }
    if out.is_empty() {
        println!("no targets — add one with: greendot-client add <connection-string>");
        return Ok(());
    }
    for t in &out {
        let unreachable = if t["reachable"].as_bool() == Some(true) {
            String::new()
        } else {
            format!(" — UNREACHABLE: {}", t["error"].as_str().unwrap_or(""))
        };
        println!(
            "{} ({}){}",
            t["name"].as_str().unwrap_or(""),
            t["host"].as_str().unwrap_or(""),
            unreachable
        );
        for e in t["exports"].as_array().into_iter().flatten() {
            let place = e["device"]
                .as_str()
                .or(e["mountpoint"].as_str())
                .unwrap_or("");
            println!(
                "  {} {:4} {:24} {} {}",
                match e["dot"].as_str() {
                    Some("green") => "🟢",
                    Some("yellow") => "🟡",
                    _ => "🔴",
                },
                e["kind"].as_str().unwrap_or(""),
                e["name"].as_str().unwrap_or(""),
                e["reason"].as_str().unwrap_or(""),
                place,
            );
        }
    }
    Ok(())
}

/// Registers this host on the export and waits for the target's reconcile to
/// land, so the ACL is really in the kernel before the fabrics connect.
fn register_nvme(api: &api::TargetApi, id: i64, hostnqn: &str) -> Result<()> {
    let reply = api.register_nvme(id, hostnqn)?;
    if let Some(task) = reply.task_id {
        api.wait_task(task)?;
    }
    Ok(())
}

fn cmd_connect(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let target = args.next().context("connect needs a target")?;
    let export = args.next().context("connect needs an export name")?;
    let forced = match opt_value(args, "--transport")?.as_deref() {
        None => None,
        Some("rdma") => Some("rdma"),
        Some("tcp") => Some("tcp"),
        Some(other) => bail!("unknown transport {other:?} (rdma or tcp)"),
    };

    let targets = Targets::load(&global.config_dir)?;
    let t = targets.find(&target)?;
    let api = api::TargetApi::connect(&t.pairing())?;
    let exports = api.exports(None)?;
    let e = exports
        .nvme
        .iter()
        .find(|e| e.name == export || e.nqn == export)
        .with_context(|| format!("target has no NVMe export {export:?}"))?;
    if !e.enabled {
        bail!("export {export:?} is disabled on the target");
    }
    if e.listeners.is_empty() {
        bail!("export {export:?} has no network listeners");
    }

    let broker = global.broker()?;
    let reply = broker.call(&AgentOp::EnsureHostnqn)?;
    let hostnqn = reply["hostnqn"]
        .as_str()
        .context("agent hostnqn")?
        .to_owned();
    register_nvme(&api, e.id, &hostnqn)?;

    let nqn = Nqn::new(e.nqn.clone()).context("target sent an invalid nqn")?;
    let hostnqn = Nqn::new(hostnqn).context("invalid local hostnqn")?;
    // RDMA first (unless forced), TCP as the explained fallback.
    let mut plan: Vec<&api::Listener> = e
        .listeners
        .iter()
        .filter(|l| forced.is_none_or(|f| l.trtype == f))
        .collect();
    plan.sort_by_key(|l| l.trtype != "rdma");
    if plan.is_empty() {
        bail!(
            "export {export:?} offers no {} listener",
            forced.unwrap_or("?")
        );
    }
    let mut fallback_reason = None;
    let mut last_err = None;
    for l in plan {
        let transport = match l.trtype.as_str() {
            "rdma" => Transport::Rdma,
            "tcp" => Transport::Tcp,
            other => {
                last_err = Some(anyhow::anyhow!("unsupported transport {other:?}"));
                continue;
            }
        };
        let traddr = match l.traddr {
            Some(ip) => ip,
            None => resolve_traddr(&t.host)?,
        };
        match broker.call(&AgentOp::ConnectNvme {
            nqn: nqn.clone(),
            transport,
            traddr,
            trsvcid: l.trsvcid,
            hostnqn: hostnqn.clone(),
        }) {
            Ok(reply) => {
                let device = reply["device"].as_str().unwrap_or("").to_owned();
                if global.json {
                    println!(
                        "{}",
                        json!({ "ok": true, "transport": l.trtype, "device": device,
                                "fallback_reason": fallback_reason })
                    );
                } else {
                    println!("connected {export} over {} at {device}", l.trtype);
                    if let Some(reason) = fallback_reason {
                        println!("  (fell back from RDMA: {reason})");
                    }
                }
                return Ok(());
            }
            Err(e) => {
                if transport == Transport::Rdma {
                    fallback_reason = Some(format!("{e:#}"));
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no usable listener")))
}

/// The export's NQN, derived locally so disconnect works with the target
/// unreachable (web-managed exports always derive it from the name).
fn export_nqn(export: &str) -> Result<Nqn> {
    if export.starts_with("nqn.") {
        return Nqn::new(export.to_owned()).map_err(Into::into);
    }
    Nqn::new(format!("{OUR_NQN_PREFIX}{export}")).map_err(Into::into)
}

fn cmd_disconnect(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let _target = args.next().context("disconnect needs a target")?;
    let export = args.next().context("disconnect needs an export name")?;
    let nqn = export_nqn(&export)?;
    let reply = global.broker()?.call(&AgentOp::DisconnectNvme { nqn })?;
    let deleted = reply["deleted"].as_u64().unwrap_or(0);
    if global.json {
        println!("{}", json!({ "ok": true, "deleted": deleted }));
    } else if deleted == 0 {
        println!("{export} was not connected");
    } else {
        println!("disconnected {export} ({deleted} controller(s))");
    }
    Ok(())
}

/// `/tank/share` → `tank-share`, the default mountpoint leaf.
fn path_slug(path: &str) -> String {
    path.trim_matches('/').replace('/', "-")
}

fn cmd_mount(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let target = args.next().context("mount needs a target")?;
    let export = args.next().context("mount needs an export path")?;
    let mut mountpoint = None;
    let mut force_tcp = false;
    for arg in args {
        match arg.as_str() {
            "--tcp" => force_tcp = true,
            other if mountpoint.is_none() && other.starts_with('/') => {
                mountpoint = Some(other.to_owned());
            }
            other => bail!("unknown argument {other:?}"),
        }
    }

    let targets = Targets::load(&global.config_dir)?;
    let t = targets.find(&target)?;
    let api = api::TargetApi::connect(&t.pairing())?;
    let exports = api.exports(None)?;
    let e = exports
        .nfs
        .iter()
        .find(|e| e.path == export || path_slug(&e.path) == export)
        .with_context(|| format!("target has no NFS export {export:?}"))?;
    if !e.enabled {
        bail!("export {export:?} is disabled on the target");
    }

    let reply = api.register_nfs(e.id, true)?;
    if let Some(task) = reply.task_id {
        api.wait_task(task)?;
    }

    let broker = global.broker()?;
    let host = host_only(&t.host).to_owned();
    let mountpoint =
        mountpoint.unwrap_or_else(|| format!("/mnt/greendot/{}/{}", t.name, path_slug(&e.path)));
    // RDMA when the target listener is up (and not forced off); a failed RDMA
    // mount falls back to TCP with the reason kept.
    let op = |rdma: bool| AgentOp::MountNfs {
        host: host.clone(),
        path: e.path.clone(),
        mountpoint: mountpoint.clone(),
        rdma,
        port: e.port,
    };
    let mut fallback_reason = None;
    if !force_tcp {
        if !e.rdma {
            fallback_reason = Some("target has no NFS RDMA listener".to_owned());
        } else {
            match broker.call(&op(true)) {
                Ok(_) => {
                    print_mounted(global, "rdma", &mountpoint, None);
                    return Ok(());
                }
                Err(err) => fallback_reason = Some(format!("{err:#}")),
            }
        }
    }
    broker.call(&op(false))?;
    print_mounted(global, "tcp", &mountpoint, fallback_reason);
    Ok(())
}

fn print_mounted(global: &Global, transport: &str, mountpoint: &str, fallback: Option<String>) {
    if global.json {
        println!(
            "{}",
            json!({ "ok": true, "transport": transport, "mountpoint": mountpoint,
                    "fallback_reason": fallback })
        );
    } else {
        println!("mounted at {mountpoint} over {transport}");
        if let Some(reason) = fallback {
            println!("  (fell back from RDMA: {reason})");
        }
    }
}

fn cmd_unmount(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let target = args.next().context("unmount needs a target")?;
    let export = args.next().context("unmount needs an export path")?;
    let targets = Targets::load(&global.config_dir)?;
    let t = targets.find(&target)?;
    let mounts = status::nfs_mounts(&global.sys().proc_mounts);
    let (_, _, m) = status::nfs_dot(host_only(&t.host), &export, &mounts);
    let m = m.with_context(|| format!("{export:?} is not mounted from {}", t.name))?;
    global.broker()?.call(&AgentOp::UnmountNfs {
        mountpoint: m.mountpoint.clone(),
    })?;
    if global.json {
        println!("{}", json!({ "ok": true, "mountpoint": m.mountpoint }));
    } else {
        println!("unmounted {}", m.mountpoint);
    }
    Ok(())
}

/// The diagnose checklist. With no argument: local plumbing only. With a
/// target: plus reachability/token. With an export: plus the export's own
/// registration and live-connection state.
fn cmd_diagnose(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let target = args.next();
    let export = args.next();
    if let Some(extra) = args.next() {
        bail!("unknown argument {extra:?}");
    }
    let sys = global.sys();
    let mut checks = Vec::new();

    // Privilege broker: agent socket answering ping, or already root.
    let broker_probe = global.broker().and_then(|b| {
        let direct = matches!(b, Broker::Direct { .. });
        b.call(&AgentOp::Ping).map(|_| direct)
    });
    checks.push(match broker_probe {
        Ok(true) => diagnose::check("privileged ops available", true, "running as root"),
        Ok(false) => diagnose::check("privileged ops available", true, "agent socket answers"),
        Err(e) => diagnose::check("privileged ops available", false, format!("{e:#}")),
    });

    checks.push(diagnose::check(
        "host NQN present",
        read_hostnqn(global).is_some(),
        match read_hostnqn(global) {
            Some(nqn) => nqn,
            None => "no /etc/nvme/hostnqn — `connect` creates it on first use".to_owned(),
        },
    ));

    // Which export kind are we diagnosing? Unknown → check both paths.
    let (t, found) = match &target {
        None => (None, None),
        Some(key) => {
            let targets = Targets::load(&global.config_dir)?;
            let t = targets.find(key)?.clone();
            checks.push(diagnose::dial_check(
                "target web port reachable",
                &t.host,
                if t.cert_sha256.is_some() { 443 } else { 80 },
            ));
            let api = api::TargetApi::connect(&t.pairing())?;
            let exports = match api.target() {
                Ok(info) => {
                    checks.push(diagnose::check(
                        "token accepted",
                        true,
                        format!("target {} (api v{})", info.name, info.api),
                    ));
                    Some(api.exports(read_hostnqn(global).as_deref())?)
                }
                Err(e) => {
                    checks.push(diagnose::check("token accepted", false, format!("{e:#}")));
                    None
                }
            };
            let found = match (&export, exports) {
                (Some(name), Some(exports)) => {
                    let nvme = exports
                        .nvme
                        .into_iter()
                        .find(|e| &e.name == name || &e.nqn == name);
                    let nfs = exports
                        .nfs
                        .into_iter()
                        .find(|e| &e.path == name || &path_slug(&e.path) == name);
                    if nvme.is_none() && nfs.is_none() {
                        bail!("target has no export {name:?}");
                    }
                    nvme.map(Ok).or(nfs.map(Err))
                }
                _ => None,
            };
            (Some(t), found)
        }
    };

    match &found {
        // NVMe export: plumbing, listener, registration, live state.
        Some(Ok(e)) => {
            checks.extend(diagnose::nvme_path_checks(&global.sys_root, &sys));
            checks.push(diagnose::check("export enabled on target", e.enabled, ""));
            let rdma_listener = e.listeners.iter().any(|l| l.trtype == "rdma");
            checks.push(diagnose::check(
                "export offers an RDMA listener",
                rdma_listener,
                if rdma_listener {
                    ""
                } else {
                    "target exports TCP only — enable RDMA on the export"
                },
            ));
            checks.push(diagnose::check(
                "this host registered",
                e.authorized,
                if e.authorized {
                    ""
                } else {
                    "run `greendot-client connect` — it registers this host's NQN first"
                },
            ));
            let ctrls = status::nvme_controllers(&sys.sys_class_nvme);
            let (_, reason, ctrl) = status::nvme_dot(&e.nqn, &ctrls);
            checks.push(diagnose::check(
                "controller live",
                ctrl.is_some_and(|c| c.state == "live"),
                match ctrl {
                    Some(c) if c.state == "connecting" => format!(
                        "stuck connecting — usually an ACL rejection (register first) or \
                         an unreachable traddr ({})",
                        c.address
                    ),
                    Some(c) => format!("{reason} ({})", c.address),
                    None => reason,
                },
            ));
        }
        // NFS export: plumbing, server RDMA listener, registration, mount.
        Some(Err(e)) => {
            checks.extend(diagnose::nfs_path_checks(&global.sys_root, &sys));
            checks.push(diagnose::check("export enabled on target", e.enabled, ""));
            checks.push(diagnose::check(
                "target NFS RDMA listener up",
                e.rdma,
                if e.rdma {
                    format!("port {}", e.port)
                } else {
                    "the target's nfsd has no RDMA listener — see its NFS diagnose page".into()
                },
            ));
            checks.push(diagnose::check(
                "this host's IP registered",
                e.authorized,
                if e.authorized {
                    ""
                } else {
                    "run `greendot-client mount` — it whitelists this host's IP first"
                },
            ));
            if let Some(t) = &t {
                let mounts = status::nfs_mounts(&sys.proc_mounts);
                let (_, reason, m) = status::nfs_dot(host_only(&t.host), &e.path, &mounts);
                checks.push(diagnose::check(
                    "mounted over RDMA",
                    m.is_some_and(|m| m.rdma),
                    match m {
                        Some(m) => format!("{reason} at {}", m.mountpoint),
                        None => reason,
                    },
                ));
            }
        }
        // No specific export: both local paths.
        None => {
            checks.extend(diagnose::nvme_path_checks(&global.sys_root, &sys));
            checks.extend(diagnose::nfs_path_checks(&global.sys_root, &sys));
        }
    }

    let all_ok = checks.iter().all(|c| c.ok);
    if global.json {
        println!(
            "{}",
            json!({ "ok": true, "all_ok": all_ok, "checks": checks })
        );
    } else {
        for c in &checks {
            let mark = if c.ok { "✓" } else { "✗" };
            if c.detail.is_empty() {
                println!("{mark} {}", c.label);
            } else {
                println!("{mark} {} — {}", c.label, c.detail);
            }
        }
    }
    Ok(())
}

fn cmd_agent(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    let mut opts = agent::AgentOpts {
        socket: global.socket.clone(),
        group: agent::DEFAULT_GROUP.into(),
        config_dir: global.config_dir.clone(),
        paths: privops::PrivPaths::at(&global.sys_root),
        allow_uid: None,
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--group" => opts.group = value()?,
            "--allow-uid" => opts.allow_uid = Some(value()?.parse()?),
            other => bail!("unknown flag {other}"),
        }
    }
    agent::serve(&opts)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    #[case("10.0.0.5:8443", "10.0.0.5")]
    #[case("10.0.0.5", "10.0.0.5")]
    #[case("nas1.local:8443", "nas1.local")]
    #[case("nas1.local", "nas1.local")]
    #[case("[fd00::1]:8443", "[fd00::1]")]
    fn host_only(#[case] host: &str, #[case] expect: &str) {
        assert_eq!(super::host_only(host), expect);
    }

    #[test]
    fn traddr_resolution_and_slugs() {
        assert_eq!(
            super::resolve_traddr("10.0.0.5:8443").unwrap(),
            "10.0.0.5".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            super::resolve_traddr("[fd00::1]:8443").unwrap(),
            "fd00::1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(super::path_slug("/tank/share"), "tank-share");
        assert_eq!(super::path_slug("/srv"), "srv");
        assert_eq!(
            super::export_nqn("vm1").unwrap().as_str(),
            "nqn.2026-06.io.greendot:vm1"
        );
        assert_eq!(
            super::export_nqn("nqn.2026-06.io.greendot:vm1")
                .unwrap()
                .as_str(),
            "nqn.2026-06.io.greendot:vm1"
        );
        assert!(super::export_nqn("bad name").is_err());
    }
}
