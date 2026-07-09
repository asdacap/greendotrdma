//! `greendot-client`: the initiator-side companion of a GreenDotRDMA target.
//! Paste a connection string from the target's Client access page (`add`),
//! then `list` its exports and `connect`/`mount` them — the client registers
//! itself (host NQN for NVMe-oF, its IP for NFS) through the target's JSON
//! API, so no manual ACL editing is needed on either side.
//!
//! Output is human text, or stable JSON with `--json` (the desktop GUI drives
//! the CLI this way).

mod api;
mod config;
mod pairing;

use anyhow::{Context, Result, bail};
use config::Targets;
use serde_json::json;
use std::path::PathBuf;

struct Global {
    json: bool,
    config_dir: PathBuf,
}

const USAGE: &str = "usage: greendot-client [--json] [--config-dir <dir>] <command>

commands:
  add <connection-string> [--name <alias>]   pair with a target (string from
                                             its web UI's Client access page)
  remove <target>                            forget a target
  list                                       targets and their exports
";

fn main() {
    let mut global = Global {
        json: false,
        config_dir: config::DEFAULT_CONFIG_DIR.into(),
    };
    // Global flags may appear anywhere; everything else is cmd + its args.
    let mut rest = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => global.json = true,
            "--config-dir" => match args.next() {
                Some(dir) => global.config_dir = dir.into(),
                None => return usage_exit(),
            },
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

    let mut targets = Targets::load(&global.config_dir)?;
    targets.add(config::TargetEntry {
        name: name.clone(),
        host: pairing.host.clone(),
        token: pairing.token.clone(),
        cert_sha256: pairing.fingerprint.clone(),
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
    let removed = Targets::load(&global.config_dir)?.remove(&key)?;
    if global.json {
        println!("{}", json!({ "ok": true, "name": removed.name }));
    } else {
        println!("removed target {} ({})", removed.name, removed.host);
    }
    Ok(())
}

/// This machine's NVMe host NQN, when one exists and is readable.
fn hostnqn() -> Option<String> {
    let s = std::fs::read_to_string("/etc/nvme/hostnqn").ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

fn cmd_list(global: &Global, args: &mut impl Iterator<Item = String>) -> Result<()> {
    if let Some(extra) = args.next() {
        bail!("unknown argument {extra:?}");
    }
    let targets = Targets::load(&global.config_dir)?;
    let hostnqn = hostnqn();
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
                rows.push(json!({
                    "kind": "nvme",
                    "id": e.id,
                    "name": e.name,
                    "nqn": e.nqn,
                    "enabled": e.enabled,
                    "authorized": e.authorized || e.allow_any_host,
                    "transports": e.listeners.iter().map(|l| l.trtype.as_str()).collect::<Vec<_>>(),
                }));
            }
            for e in &exports.nfs {
                rows.push(json!({
                    "kind": "nfs",
                    "id": e.id,
                    "name": e.path,
                    "path": e.path,
                    "enabled": e.enabled,
                    "authorized": e.authorized,
                    "rdma": e.rdma,
                    "port": e.port,
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
            let auth = if e["authorized"].as_bool() == Some(true) {
                "authorized"
            } else {
                "not registered"
            };
            println!(
                "  {:4} {:30} {}",
                e["kind"].as_str().unwrap_or(""),
                e["name"].as_str().unwrap_or(""),
                auth
            );
        }
    }
    Ok(())
}
