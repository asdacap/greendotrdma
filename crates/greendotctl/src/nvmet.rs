//! Applies the desired NVMe-oF state by writing the kernel's nvmet configfs
//! tree directly (no external `nvmetcli`). Reconciliation is scoped to our own
//! NQN prefix, so foreign (manually created) subsystems and port links are left
//! untouched. Creating a `ports/<id>/subsystems/<nqn>` symlink is what binds the
//! RDMA/TCP listener — its failure (e.g. no usable RDMA) surfaces as a task error.

use crate::cmd::EventSink;
use greendot_proto::{
    NvmetDesired, NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, OUR_NQN_PREFIX, TaskEvent, Transport,
};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;

pub const NVMET_ROOT: &str = "/sys/kernel/config/nvmet";

/// Reconciles configfs under `root` to `desired`, streaming progress as task
/// events. Returns `Err` only when the sink itself fails (the client is gone);
/// configfs failures are reported via a `Finished { ok: false }` event.
pub fn apply(desired: &NvmetDesired, root: &Path, sink: &mut dyn EventSink) -> io::Result<()> {
    sink.emit(TaskEvent::Started {
        command: "configfs".into(),
        args: vec!["nvmet".into(), "apply".into()],
        stdin: None,
    })?;
    match reconcile(desired, root) {
        Ok(summary) => {
            sink.emit(TaskEvent::Stdout { data: summary })?;
            sink.emit(TaskEvent::Finished {
                exit: 0,
                ok: true,
                error: None,
            })
        }
        Err(e) => {
            sink.emit(TaskEvent::Stderr {
                data: format!("{e}\n"),
            })?;
            sink.emit(TaskEvent::Finished {
                exit: 1,
                ok: false,
                error: Some(e.to_string()),
            })
        }
    }
}

/// The configfs work. Errors carry an actionable path/operation message.
fn reconcile(desired: &NvmetDesired, root: &Path) -> io::Result<String> {
    let subsystems_dir = root.join("subsystems");
    let ports_dir = root.join("ports");
    let desired_nqns: BTreeSet<&str> = desired.subsystems.iter().map(|s| s.nqn.as_str()).collect();

    // A. Drop our stale port links so a stale subsystem ends up unlinked (and so
    //    a moved subsystem leaves its old port). Foreign links stay; remember the
    //    ports we touched, to reap the ones we emptied in phase E.
    let mut emptied_candidates: Vec<String> = Vec::new();
    for port in dir_entries(&ports_dir) {
        let links = ports_dir.join(&port).join("subsystems");
        let want = desired_links(desired, &port);
        let mut removed = false;
        for link in dir_entries(&links) {
            if link.starts_with(OUR_NQN_PREFIX) && !want.contains(link.as_str()) {
                remove_file_ok(&links.join(&link))?;
                removed = true;
            }
        }
        if removed {
            emptied_candidates.push(port);
        }
    }

    // B. Delete our subsystems that are no longer desired.
    for nqn in dir_entries(&subsystems_dir) {
        if nqn.starts_with(OUR_NQN_PREFIX) && !desired_nqns.contains(nqn.as_str()) {
            delete_subsystem(&subsystems_dir.join(&nqn))?;
        }
    }

    // C. Create / update desired subsystems before any port links them.
    for s in &desired.subsystems {
        apply_subsystem(root, s)?;
    }

    // D. Create / update desired ports, then bind their subsystems.
    for p in &desired.ports {
        apply_port(root, p)?;
    }

    // E. Reap ports we emptied that are no longer desired (skip if a foreign
    //    link still holds the port open).
    for port in &emptied_candidates {
        let undesired = desired.ports.iter().all(|p| p.id.to_string() != *port);
        if undesired && dir_entries(&ports_dir.join(port).join("subsystems")).is_empty() {
            remove_object_dir(&ports_dir.join(port))?;
        }
    }

    Ok(format!(
        "reconciled nvmet: {} subsystem(s), {} port(s)\n",
        desired.subsystems.len(),
        desired.ports.len()
    ))
}

/// The desired subsystem links for a given port id (as a configfs dir name).
fn desired_links<'a>(desired: &'a NvmetDesired, port: &str) -> BTreeSet<&'a str> {
    desired
        .ports
        .iter()
        .filter(|p| p.id.to_string() == port)
        .flat_map(|p| p.subsystems.iter().map(|n| n.as_str()))
        .collect()
}

fn delete_subsystem(dir: &Path) -> io::Result<()> {
    for ns in dir_entries(&dir.join("namespaces")) {
        remove_object_dir(&dir.join("namespaces").join(ns))?;
    }
    for host in dir_entries(&dir.join("allowed_hosts")) {
        remove_file_ok(&dir.join("allowed_hosts").join(host))?;
    }
    remove_object_dir(dir)
}

fn apply_subsystem(root: &Path, s: &NvmetSubsysSpec) -> io::Result<()> {
    let dir = root.join("subsystems").join(s.nqn.as_str());
    create_dir_all_ok(&dir)?;

    let ns_dir = dir.join("namespaces");
    for ns in &s.namespaces {
        apply_namespace(&ns_dir, ns)?;
    }
    let want_ns: BTreeSet<String> = s.namespaces.iter().map(|n| n.nsid.to_string()).collect();
    for ns in dir_entries(&ns_dir) {
        if !want_ns.contains(&ns) {
            remove_object_dir(&ns_dir.join(ns))?;
        }
    }

    let allowed = dir.join("allowed_hosts");
    let attr = dir.join("attr_allow_any_host");
    if s.allow_any_host {
        // The kernel rejects allow_any_host=1 while any host is listed.
        for host in dir_entries(&allowed) {
            remove_file_ok(&allowed.join(host))?;
        }
        write_attr(&attr, "1")?;
    } else {
        write_attr(&attr, "0")?;
        create_dir_all_ok(&allowed)?;
        let want: BTreeSet<&str> = s.allowed_hosts.iter().map(|h| h.as_str()).collect();
        for host in &s.allowed_hosts {
            create_dir_all_ok(&root.join("hosts").join(host.as_str()))?;
            let link = allowed.join(host.as_str());
            if link.symlink_metadata().is_err() {
                symlink_ok(&root.join("hosts").join(host.as_str()), &link)?;
            }
        }
        for host in dir_entries(&allowed) {
            if !want.contains(host.as_str()) {
                remove_file_ok(&allowed.join(host))?;
            }
        }
    }
    Ok(())
}

fn apply_namespace(ns_root: &Path, ns: &NvmetNsSpec) -> io::Result<()> {
    let dir = ns_root.join(ns.nsid.to_string());
    create_dir_all_ok(&dir)?;
    let device_path = dir.join("device_path");
    let enable = dir.join("enable");
    if read_trim(&device_path) != ns.device_path.as_str() || read_trim(&enable) != "1" {
        // device_path is read-only while enabled, so disable first if needed.
        if read_trim(&enable) == "1" {
            write_attr(&enable, "0")?;
        }
        write_attr(&device_path, ns.device_path.as_str())?;
        write_attr(&enable, "1")?;
    }
    Ok(())
}

fn apply_port(root: &Path, p: &NvmetPortSpec) -> io::Result<()> {
    let dir = root.join("ports").join(p.id.to_string());
    let links = dir.join("subsystems");
    create_dir_all_ok(&dir)?;

    // Loop ports carry only a trtype; rdma/tcp carry the full address.
    let addr: Vec<(&str, String)> = match p.trtype {
        Transport::Loop => vec![("addr_trtype", p.trtype.as_str().to_string())],
        _ => vec![
            (
                "addr_adrfam",
                if p.traddr.is_ipv6() { "ipv6" } else { "ipv4" }.into(),
            ),
            ("addr_traddr", p.traddr.to_string()),
            ("addr_trsvcid", p.trsvcid.to_string()),
            ("addr_trtype", p.trtype.as_str().to_string()),
        ],
    };
    // addr_* are read-only (EBUSY) once a subsystem is linked, so only rewrite on
    // drift, dropping our links first to free them.
    if addr.iter().any(|(k, v)| read_trim(&dir.join(k)) != *v) {
        for link in dir_entries(&links) {
            if link.starts_with(OUR_NQN_PREFIX) {
                remove_file_ok(&links.join(&link))?;
            }
        }
        for (k, v) in &addr {
            write_attr(&dir.join(k), v.as_str())?;
        }
    }

    // Bind the desired subsystems — the symlink is the listener bind.
    create_dir_all_ok(&links)?;
    for nqn in &p.subsystems {
        let link = links.join(nqn.as_str());
        if link.symlink_metadata().is_err() {
            let target = root.join("subsystems").join(nqn.as_str());
            std::os::unix::fs::symlink(&target, &link).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "binding {nqn} to port {} ({}): {e}",
                        p.id,
                        p.trtype.as_str()
                    ),
                )
            })?;
        }
    }
    Ok(())
}

fn read_trim(path: &Path) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn write_attr(path: &Path, value: &str) -> io::Result<()> {
    std::fs::write(path, value)
        .map_err(|e| io::Error::new(e.kind(), format!("writing {}: {e}", path.display())))
}

fn create_dir_all_ok(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| io::Error::new(e.kind(), format!("creating {}: {e}", dir.display())))
}

fn symlink_ok(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|e| io::Error::new(e.kind(), format!("linking {}: {e}", link.display())))
}

/// `remove_file` that treats an already-absent path as success.
fn remove_file_ok(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io::Error::new(
            e.kind(),
            format!("removing {}: {e}", path.display()),
        )),
        _ => Ok(()),
    }
}

/// Removes a configfs object directory. configfs reaps the object's own
/// attribute files and default subdirs on `rmdir`, so a bare `rmdir` always
/// succeeds there; a plain directory (the unit test's tmpfs) still holds those
/// files, so fall back to a recursive delete when the bare `rmdir` won't take.
fn remove_object_dir(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => std::fs::remove_dir_all(path).or_else(|e| match e.kind() {
            io::ErrorKind::NotFound => Ok(()),
            _ => Err(io::Error::new(
                e.kind(),
                format!("removing {}: {e}", path.display()),
            )),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greendot_proto::{DevicePath, Nqn};

    #[derive(Default)]
    struct Sink {
        events: Vec<TaskEvent>,
    }
    impl EventSink for Sink {
        fn emit(&mut self, ev: TaskEvent) -> io::Result<()> {
            self.events.push(ev);
            Ok(())
        }
    }
    impl Sink {
        fn ok(&self) -> bool {
            matches!(
                self.events.last(),
                Some(TaskEvent::Finished { ok: true, .. })
            )
        }
    }

    fn run(desired: &NvmetDesired, root: &Path) -> Sink {
        let mut sink = Sink::default();
        apply(desired, root, &mut sink).unwrap();
        sink
    }

    fn nqn(s: &str) -> Nqn {
        Nqn::new(s).unwrap()
    }

    fn subsys(name: &str, dev: &str, allow_any: bool, hosts: &[&str]) -> NvmetSubsysSpec {
        NvmetSubsysSpec {
            nqn: nqn(&format!("nqn.2026-06.io.greendot:{name}")),
            allow_any_host: allow_any,
            allowed_hosts: hosts.iter().map(|h| nqn(h)).collect(),
            namespaces: vec![NvmetNsSpec {
                nsid: 1,
                device_path: DevicePath::new(dev).unwrap(),
            }],
        }
    }

    fn port(id: u16, trtype: Transport, subs: &[&str]) -> NvmetPortSpec {
        NvmetPortSpec {
            id,
            trtype,
            traddr: "10.0.0.5".parse().unwrap(),
            trsvcid: 4420,
            subsystems: subs
                .iter()
                .map(|n| nqn(&format!("nqn.2026-06.io.greendot:{n}")))
                .collect(),
        }
    }

    fn is_symlink(p: &Path) -> bool {
        p.symlink_metadata()
            .map(|m| m.is_symlink())
            .unwrap_or(false)
    }

    #[test]
    fn applies_scoped_reconcile_preserving_foreign_objects() {
        let tmp = std::env::temp_dir().join(format!("gd-nvmet-apply{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let host = "nqn.2014-08.org.nvmexpress:host1";

        // --- First apply: vm1 on RDMA (port 1) + TCP (port 2), one allowed host.
        let first = NvmetDesired {
            subsystems: vec![subsys("vm1", "/dev/zvol/tank/vm1", false, &[host])],
            ports: vec![
                port(1, Transport::Rdma, &["vm1"]),
                port(2, Transport::Tcp, &["vm1"]),
            ],
        };
        assert!(run(&first, &tmp).ok());

        let vm1 = tmp.join("subsystems/nqn.2026-06.io.greendot:vm1");
        assert_eq!(read_trim(&vm1.join("attr_allow_any_host")), "0");
        assert_eq!(
            read_trim(&vm1.join("namespaces/1/device_path")),
            "/dev/zvol/tank/vm1"
        );
        assert_eq!(read_trim(&vm1.join("namespaces/1/enable")), "1");
        assert!(is_symlink(&vm1.join("allowed_hosts").join(host)));
        assert!(tmp.join("hosts").join(host).is_dir());
        assert_eq!(read_trim(&tmp.join("ports/1/addr_trtype")), "rdma");
        assert_eq!(read_trim(&tmp.join("ports/1/addr_adrfam")), "ipv4");
        assert_eq!(read_trim(&tmp.join("ports/1/addr_traddr")), "10.0.0.5");
        assert_eq!(read_trim(&tmp.join("ports/1/addr_trsvcid")), "4420");
        assert!(is_symlink(
            &tmp.join("ports/1/subsystems/nqn.2026-06.io.greendot:vm1")
        ));
        assert_eq!(read_trim(&tmp.join("ports/2/addr_trtype")), "tcp");

        // Seed a foreign subsystem and a foreign link into our RDMA port.
        let foreign = "nqn.2000-01.com.example:manual";
        std::fs::create_dir_all(tmp.join("subsystems").join(foreign)).unwrap();
        std::os::unix::fs::symlink(
            tmp.join("subsystems").join(foreign),
            tmp.join("ports/1/subsystems").join(foreign),
        )
        .unwrap();

        // --- Second apply: vm1 now LOOP-only, new device, allow-any-host; vm2 added.
        let second = NvmetDesired {
            subsystems: vec![
                subsys("vm1", "/dev/zvol/tank/vm1b", true, &[]),
                subsys("vm2", "/dev/zvol/tank/vm2", false, &[host]),
            ],
            ports: vec![port(3, Transport::Loop, &["vm1", "vm2"])],
        };
        assert!(run(&second, &tmp).ok());

        // vm1 reconciled: path changed (disable→re-enable), host dropped, allow-any set.
        assert_eq!(
            read_trim(&vm1.join("namespaces/1/device_path")),
            "/dev/zvol/tank/vm1b"
        );
        assert_eq!(read_trim(&vm1.join("namespaces/1/enable")), "1");
        assert_eq!(read_trim(&vm1.join("attr_allow_any_host")), "1");
        assert!(!is_symlink(&vm1.join("allowed_hosts").join(host)));
        // vm2 created and on the loop port.
        assert!(tmp.join("subsystems/nqn.2026-06.io.greendot:vm2").is_dir());
        assert_eq!(read_trim(&tmp.join("ports/3/addr_trtype")), "loop");
        assert!(
            !tmp.join("ports/3/addr_traddr").exists(),
            "loop port has no address"
        );
        assert!(is_symlink(
            &tmp.join("ports/3/subsystems/nqn.2026-06.io.greendot:vm1")
        ));
        assert!(is_symlink(
            &tmp.join("ports/3/subsystems/nqn.2026-06.io.greendot:vm2")
        ));

        // Scoping: our now-empty TCP port is reaped; the foreign subsystem and the
        // foreign link in port 1 survive (port 1 therefore is not reaped either).
        assert!(!tmp.join("ports/2").exists(), "emptied managed port reaped");
        assert!(!is_symlink(
            &tmp.join("ports/1/subsystems/nqn.2026-06.io.greendot:vm1")
        ));
        assert!(
            tmp.join("subsystems").join(foreign).is_dir(),
            "foreign subsystem preserved"
        );
        assert!(
            is_symlink(&tmp.join("ports/1/subsystems").join(foreign)),
            "foreign link preserved"
        );

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
