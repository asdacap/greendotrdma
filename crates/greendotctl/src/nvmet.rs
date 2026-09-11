//! Applies the desired NVMe-oF state by writing the kernel's nvmet configfs
//! tree directly (no external `nvmetcli`). Reconciliation is scoped to our own
//! NQN prefix, so foreign (manually created) subsystems and port links are left
//! untouched. Creating a `ports/<id>/subsystems/<nqn>` symlink is what binds the
//! RDMA/TCP listener — its failure (e.g. no usable RDMA) surfaces as a task error.

use crate::util::read_trim;
use greendot_proto::{
    CSI_NQN_PREFIX, CSI_PORT_ID, CsiNqn, DatasetName, Nqn, NsUuid, NvmetDesired, NvmetNsSpec,
    NvmetPortSpec, NvmetSubsysSpec, OUR_NQN_PREFIX, SubStatus, SubTask, Task, Transport, ops,
};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const NVMET_ROOT: &str = "/sys/kernel/config/nvmet";

/// Reconciles configfs under `root` to `desired`, streaming progress into the
/// caller-opened subtask. Returns the subtask status (`Failed` on a configfs
/// error, whose message is recorded on the subtask); `Err` only when the sink
/// itself fails (the client is gone).
pub fn apply(desired: &NvmetDesired, root: &Path, sub: &mut SubTask) -> io::Result<SubStatus> {
    match reconcile(desired, root) {
        Ok(summary) => {
            write!(sub.stdout(), "{summary}")?;
            Ok(SubStatus::Success)
        }
        Err(e) => {
            writeln!(sub.stderr(), "{e}")?;
            sub.set_result(1, Some(e.to_string()));
            Ok(SubStatus::Failed)
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
        apply_port(root, p, OUR_NQN_PREFIX)?;
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
        apply_namespace(&ns_dir, ns, None)?;
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

/// `uuid` pins the namespace's `device_uuid` (CSI: the initiator resolves the
/// volume via `/dev/disk/by-id/nvme-uuid.<uuid>`, so it must not be
/// kernel-generated); `None` (reconcile) leaves it to the kernel.
fn apply_namespace(ns_root: &Path, ns: &NvmetNsSpec, uuid: Option<&NsUuid>) -> io::Result<()> {
    let dir = ns_root.join(ns.nsid.to_string());
    create_dir_all_ok(&dir)?;
    let device_path = dir.join("device_path");
    let enable = dir.join("enable");
    let uuid_drift = uuid.is_some_and(|u| read_trim(&dir.join("device_uuid")) != u.as_str());
    if read_trim(&device_path) != ns.device_path.as_str() || uuid_drift || read_trim(&enable) != "1"
    {
        // device_path and device_uuid are read-only while enabled, so disable
        // first if needed; the uuid must be written before enable.
        if read_trim(&enable) == "1" {
            write_attr(&enable, "0")?;
        }
        write_attr(&device_path, ns.device_path.as_str())?;
        if let Some(u) = uuid {
            write_attr(&dir.join("device_uuid"), u.as_str())?;
        }
        write_attr(&enable, "1")?;
    }
    Ok(())
}

/// `managed_prefix` scopes which existing links may be dropped to free the
/// port's `addr_*` on drift: the web prefix for reconcile, the CSI prefix for
/// the CSI port. A link outside the prefix surfaces as EBUSY on the write.
fn apply_port(root: &Path, p: &NvmetPortSpec, managed_prefix: &str) -> io::Result<()> {
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
            if link.starts_with(managed_prefix) {
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

// ---- CSI exports ----
//
// Imperative ops for the Kubernetes CSI controller. CSI subsystems live under
// CSI_NQN_PREFIX — a sibling of (not nested under) OUR_NQN_PREFIX — so the
// reconcile above classifies them as foreign and never prunes or relinks them,
// and they bind to the dedicated CSI port (never a render-managed one, whose
// addr rewrites drop only web-prefix links and would EBUSY against a CSI
// link). All ops run under the daemon's mutate lock like any other task, so
// they can never interleave with a reconcile pass.

/// `ports/<CSI_PORT_ID>/subsystems` under `root`.
fn csi_port_links(root: &Path) -> PathBuf {
    root.join("ports")
        .join(CSI_PORT_ID.to_string())
        .join("subsystems")
}

/// Runs one CSI step as a named subtask: the closure's status completes it,
/// an `Err` records the message and fails it. `Err` from this fn is only a
/// sink failure (the client is gone).
fn step(
    task: &mut Task,
    name: String,
    f: impl FnOnce() -> io::Result<SubStatus>,
) -> io::Result<SubStatus> {
    let mut sub = task.begin_subtask(name);
    match f() {
        Ok(status) => {
            sub.complete(status);
            Ok(status)
        }
        Err(e) => {
            writeln!(sub.stderr(), "{e}")?;
            sub.set_result(1, Some(e.to_string()));
            sub.complete(SubStatus::Failed);
            Ok(SubStatus::Failed)
        }
    }
}

/// The `CsiNvmeApply` op: idempotent upsert of one CSI export. The subsystem
/// is created closed (`allow_any_host=0`, empty ACL — nobody can attach until
/// a `CsiHostGrant`) with namespace 1 pinned to `device_uuid`; existing
/// `allowed_hosts` are deliberately untouched, so grants survive re-apply
/// (CSI controllers retry `CreateVolume`). The CSI port is then ensured and
/// the subsystem linked — the link is the listener bind.
pub fn csi_apply(root: &Path, op: &ops::CsiNvmeApply, task: &mut Task) -> io::Result<()> {
    csi_apply_checked(root, op, task).map(|_| ())
}

pub fn csi_apply_checked(
    root: &Path,
    op: &ops::CsiNvmeApply,
    task: &mut Task,
) -> io::Result<SubStatus> {
    let done = step(task, format!("Ensure subsystem {}", op.nqn), || {
        let dir = root.join("subsystems").join(op.nqn.as_str());
        create_dir_all_ok(&dir)?;
        write_attr(&dir.join("attr_allow_any_host"), "0")?;
        create_dir_all_ok(&dir.join("allowed_hosts"))?;
        apply_namespace(
            &dir.join("namespaces"),
            &NvmetNsSpec {
                nsid: 1,
                device_path: op.device_path.clone(),
            },
            Some(&op.device_uuid),
        )?;
        Ok(SubStatus::Success)
    })?;
    if done == SubStatus::Failed {
        return Ok(SubStatus::Failed);
    }
    step(task, format!("Bind to CSI port {CSI_PORT_ID}"), || {
        let port = NvmetPortSpec {
            id: CSI_PORT_ID,
            trtype: op.transport,
            traddr: op.traddr,
            trsvcid: op.trsvcid,
            subsystems: vec![Nqn::new(op.nqn.as_str()).expect("a CsiNqn is a valid Nqn")],
        };
        apply_port(root, &port, CSI_NQN_PREFIX)?;
        Ok(SubStatus::Success)
    })
}

/// The `CsiNvmeDelete` op: absent-tolerant teardown (unlink, delete, then reap
/// the CSI port once its last link is gone — an empty port's id would
/// otherwise be reclaimable by the web's renderer).
pub fn csi_delete(root: &Path, nqn: &CsiNqn, task: &mut Task) -> io::Result<()> {
    csi_delete_checked(root, nqn, task).map(|_| ())
}

pub fn csi_delete_checked(root: &Path, nqn: &CsiNqn, task: &mut Task) -> io::Result<SubStatus> {
    if step(task, format!("Unbind {nqn} from CSI port"), || {
        let link = csi_port_links(root).join(nqn.as_str());
        if link.symlink_metadata().is_err() {
            return Ok(SubStatus::Skipped);
        }
        remove_file_ok(&link)?;
        Ok(SubStatus::Success)
    })? == SubStatus::Failed
    {
        return Ok(SubStatus::Failed);
    }
    if step(task, format!("Delete subsystem {nqn}"), || {
        let dir = root.join("subsystems").join(nqn.as_str());
        if !dir.is_dir() {
            return Ok(SubStatus::Skipped);
        }
        delete_subsystem(&dir)?;
        Ok(SubStatus::Success)
    })? == SubStatus::Failed
    {
        return Ok(SubStatus::Failed);
    }
    step(task, "Reap empty CSI port".into(), || {
        let port = root.join("ports").join(CSI_PORT_ID.to_string());
        if !port.is_dir() || !dir_entries(&port.join("subsystems")).is_empty() {
            return Ok(SubStatus::Skipped);
        }
        remove_object_dir(&port)?;
        Ok(SubStatus::Success)
    })
}

/// The `CsiHostGrant` op: add one initiator NQN to the subsystem's
/// `allowed_hosts` — the per-node attach ACL `ControllerPublishVolume` drives.
pub fn csi_host_grant(root: &Path, nqn: &CsiNqn, host: &Nqn, task: &mut Task) -> io::Result<()> {
    step(task, format!("Grant {host}"), || {
        let subsys = root.join("subsystems").join(nqn.as_str());
        if !subsys.is_dir() {
            return Err(io::Error::other(format!("subsystem {nqn} does not exist")));
        }
        if std::fs::read_dir(subsys.join("allowed_hosts"))?.any(|entry| {
            entry
                .map(|entry| entry.file_name() != host.as_str())
                .unwrap_or(true)
        }) {
            return Err(io::Error::other(
                "attachment conflict: export grants another host",
            ));
        }
        let link = subsys.join("allowed_hosts").join(host.as_str());
        if link.symlink_metadata().is_ok() {
            return Ok(SubStatus::Skipped);
        }
        create_dir_all_ok(&root.join("hosts").join(host.as_str()))?;
        symlink_ok(&root.join("hosts").join(host.as_str()), &link)?;
        Ok(SubStatus::Success)
    })?;
    Ok(())
}

/// The `CsiHostRevoke` op — the fence, three steps in strict order:
///
/// 1. **Revoke ACL** — dropping the `allowed_hosts` link only stops new
///    connects (the kernel checks `nvmet_host_allowed` at connect time, never
///    in the I/O path), so on its own it would leave a live controller
///    writing.
/// 2. **Sever port** — unlinking the subsystem from the port is the one
///    configfs operation that deletes live controllers
///    (`nvmet_port_del_ctrls`). The fenced host's reconnect is then rejected
///    with `CONNECT_INVALID_HOST | DNR`, on which its initiator deletes its
///    own controller instead of retrying.
/// 3. **Relink port** — reopen the listener for still-granted hosts (their
///    controllers were severed too; they reconnect within their retry loop).
///
/// The ACL edit strictly precedes the relink so the fenced host cannot slip
/// back in through the reopened port. An absent ACL entry still fences: the
/// revoke may be a retry after a partial run.
pub fn csi_host_revoke(root: &Path, nqn: &CsiNqn, host: &Nqn, task: &mut Task) -> io::Result<()> {
    let subsys = root.join("subsystems").join(nqn.as_str());
    step(task, "Revoke ACL".into(), || {
        let link = subsys.join("allowed_hosts").join(host.as_str());
        if link.symlink_metadata().is_err() {
            return Ok(SubStatus::Skipped);
        }
        remove_file_ok(&link)?;
        Ok(SubStatus::Success)
    })?;
    step(task, "Sever port".into(), || {
        let link = csi_port_links(root).join(nqn.as_str());
        if link.symlink_metadata().is_err() {
            return Ok(SubStatus::Skipped);
        }
        remove_file_ok(&link)?;
        Ok(SubStatus::Success)
    })?;
    step(task, "Relink port".into(), || {
        let link = csi_port_links(root).join(nqn.as_str());
        if !subsys.is_dir() || !link.parent().is_some_and(Path::is_dir) {
            return Ok(SubStatus::Skipped);
        }
        symlink_ok(&subsys, &link)?;
        Ok(SubStatus::Success)
    })?;
    Ok(())
}

/// Grow the managed zvol even when detached, then revalidate any live export.
/// The daemon mutation lock covers both the size read and the grow, so retries
/// (including older requests) never shrink a volume.
pub fn csi_expand(root: &Path, nqn: &CsiNqn, new_size: u64, task: &mut Task) -> io::Result<()> {
    expand_volume(
        root,
        nqn,
        new_size,
        task,
        |task, dataset| {
            let mut sub = task.begin_subtask(format!("Read capacity {dataset}"));
            let command = crate::cmd::TaskSpec::new(
                "zfs",
                vec![
                    "get".into(),
                    "-Hp".into(),
                    "-o".into(),
                    "value".into(),
                    "volsize".into(),
                    dataset.to_string(),
                ],
            );
            let output = crate::cmd::capture_into(&mut sub, &command)?;
            match output
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
            {
                Some(size) if size > 0 => {
                    sub.complete(SubStatus::Success);
                    Ok(Some(size))
                }
                _ => {
                    sub.fail("cannot read backing zvol capacity");
                    Ok(None)
                }
            }
        },
        |task, dataset, size| {
            crate::cmd::run(
                task,
                format!("Resize zvol {dataset}"),
                &crate::zfs::zvol_resize(dataset, size),
            )
        },
    )
}

fn expand_volume(
    root: &Path,
    nqn: &CsiNqn,
    new_size: u64,
    task: &mut Task,
    mut read_size: impl FnMut(&mut Task, &DatasetName) -> io::Result<Option<u64>>,
    mut resize: impl FnMut(&mut Task, &DatasetName, u64) -> io::Result<SubStatus>,
) -> io::Result<()> {
    let ns = root
        .join("subsystems")
        .join(nqn.as_str())
        .join("namespaces/1");
    let device = read_trim(&ns.join("device_path"));
    let token = nqn
        .as_str()
        .strip_prefix(CSI_NQN_PREFIX)
        .unwrap_or_default();
    // Older clients used bare leaf NQNs; preserve their export-backed lookup.
    // Current managed IDs encode the full path, without a separate arbitrary
    // dataset argument that could escape the NQN authorization scope.
    let dataset = if token.contains(':') && !token.starts_with("imp1-") {
        DatasetName::new(token.replace(':', "/")).ok()
    } else if !token.starts_with("imp1-") {
        device
            .strip_prefix("/dev/zvol/")
            .and_then(|name| DatasetName::new(name).ok())
    } else {
        None
    };
    let Some(dataset) =
        dataset.filter(|dataset| !ns.exists() || device == format!("/dev/zvol/{dataset}"))
    else {
        task.begin_subtask("Resolve backing zvol")
            .fail("namespace is not backed by the managed zvol");
        return Ok(());
    };
    let Some(current_size) = read_size(task, &dataset)? else {
        return Ok(());
    };
    if new_size > current_size && resize(task, &dataset, new_size)? != SubStatus::Success {
        return Ok(());
    }
    // A retry after successful ZFS growth must still repair a failed revalidate.
    // Disabled namespaces pick up capacity when enabled; detached volumes have
    // no namespace and must not acquire an export as a side effect of growth.
    if !ns.exists() || read_trim(&ns.join("enable")) != "1" {
        return Ok(());
    }
    step(task, "Revalidate namespace size".into(), || {
        let attr = ns.join("revalidate_size");
        if !attr.exists() {
            return Err(io::Error::other(
                "kernel lacks namespaces/<nsid>/revalidate_size (needs v5.15+); \
                 disable and re-enable the export to pick up the new size",
            ));
        }
        write_attr(&attr, "1")?;
        Ok(SubStatus::Success)
    })?;
    Ok(())
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
    use crate::cmd::test::Collector;
    use greendot_proto::{DevicePath, Nqn, Task};

    /// Applies `desired` through a one-subtask task and returns whether it
    /// reconciled successfully.
    fn run(desired: &NvmetDesired, root: &Path) -> bool {
        let mut c = Collector::default();
        let mut task = Task::new(&mut c);
        let mut sub = task.begin_subtask("Apply NVMe-oF configuration");
        let status = apply(desired, root, &mut sub).unwrap();
        sub.complete(status);
        task.complete().unwrap();
        status == SubStatus::Success
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
        assert!(run(&first, &tmp));

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
        assert!(run(&second, &tmp));

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

    // ---- CSI ----

    use greendot_proto::TaskEvent;

    fn csi_op(name: &str, dev: &str) -> ops::CsiNvmeApply {
        ops::CsiNvmeApply {
            nqn: CsiNqn::new(format!("nqn.2026-06.io.greendot.csi:{name}")).unwrap(),
            device_path: DevicePath::new(dev).unwrap(),
            device_uuid: NsUuid::new("58668891-c3e4-45d0-b90e-824525c16080").unwrap(),
            traddr: "10.0.0.5".parse().unwrap(),
            trsvcid: 4421,
            transport: Transport::Rdma,
        }
    }

    /// Runs a CSI op through a fresh task, returning the collected events.
    fn run_csi(root: &Path, f: impl FnOnce(&Path, &mut Task) -> io::Result<()>) -> Vec<TaskEvent> {
        let mut c = Collector::default();
        let mut task = Task::new(&mut c);
        f(root, &mut task).unwrap();
        task.complete().unwrap();
        c.events
    }

    fn subtask_names(events: &[TaskEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                TaskEvent::SubtaskStarted { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    fn task_status(events: &[TaskEvent]) -> SubStatus {
        match events.last().unwrap() {
            TaskEvent::Finished { status, .. } => *status,
            other => panic!("task did not finish: {other:?}"),
        }
    }

    /// The whole CSI lifecycle against one tempdir tree: idempotent apply with
    /// a pinned uuid, grant/regrant, the ordered fence, delete + port reap,
    /// and absent-tolerant re-delete — one flow, as it runs in production.
    #[test]
    fn csi_lifecycle_applies_grants_fences_and_deletes() {
        let tmp = std::env::temp_dir().join(format!("gd-nvmet-csi{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let op = csi_op("pvc-1", "/dev/zvol/tank/csi/pvc-1");
        let nqn = op.nqn.clone();
        let host = nqn_of("nqn.2014-08.org.nvmexpress:host1");
        let subsys = tmp.join("subsystems/nqn.2026-06.io.greendot.csi:pvc-1");
        let port_link = tmp.join(format!(
            "ports/{CSI_PORT_ID}/subsystems/nqn.2026-06.io.greendot.csi:pvc-1"
        ));

        // Apply: closed subsystem, pinned uuid, CSI port bound.
        assert_eq!(
            task_status(&run_csi(&tmp, |r, t| csi_apply(r, &op, t))),
            SubStatus::Success
        );
        assert_eq!(read_trim(&subsys.join("attr_allow_any_host")), "0");
        assert_eq!(
            read_trim(&subsys.join("namespaces/1/device_path")),
            "/dev/zvol/tank/csi/pvc-1"
        );
        assert_eq!(
            read_trim(&subsys.join("namespaces/1/device_uuid")),
            "58668891-c3e4-45d0-b90e-824525c16080"
        );
        assert_eq!(read_trim(&subsys.join("namespaces/1/enable")), "1");
        let port = tmp.join(format!("ports/{CSI_PORT_ID}"));
        assert_eq!(read_trim(&port.join("addr_trtype")), "rdma");
        assert_eq!(read_trim(&port.join("addr_traddr")), "10.0.0.5");
        assert_eq!(read_trim(&port.join("addr_trsvcid")), "4421");
        assert!(is_symlink(&port_link));

        // Grant, then re-apply: the grant must survive (allowed_hosts is never
        // touched by apply), the uuid stays pinned, and namespace 1 stays
        // enabled (no disable/enable churn under a live initiator).
        assert_eq!(
            task_status(&run_csi(&tmp, |r, t| csi_host_grant(r, &nqn, &host, t))),
            SubStatus::Success
        );
        assert!(is_symlink(
            &subsys.join("allowed_hosts").join(host.as_str())
        ));
        assert_eq!(
            task_status(&run_csi(&tmp, |r, t| csi_apply(r, &op, t))),
            SubStatus::Success
        );
        assert!(is_symlink(
            &subsys.join("allowed_hosts").join(host.as_str())
        ));
        assert_eq!(
            read_trim(&subsys.join("namespaces/1/device_uuid")),
            "58668891-c3e4-45d0-b90e-824525c16080"
        );
        assert_eq!(read_trim(&subsys.join("namespaces/1/enable")), "1");
        // A repeated grant is a visible no-op, not an error.
        let regrant = run_csi(&tmp, |r, t| csi_host_grant(r, &nqn, &host, t));
        assert_eq!(task_status(&regrant), SubStatus::Skipped);

        // The fence: exactly ACL → sever → relink, in that order; afterwards
        // the ACL entry is gone but the port link is restored.
        let fence = run_csi(&tmp, |r, t| csi_host_revoke(r, &nqn, &host, t));
        assert_eq!(
            subtask_names(&fence),
            ["Revoke ACL", "Sever port", "Relink port"]
        );
        assert_eq!(task_status(&fence), SubStatus::Success);
        assert!(!is_symlink(
            &subsys.join("allowed_hosts").join(host.as_str())
        ));
        assert!(is_symlink(&port_link), "port relinked for remaining hosts");
        // Revoking an already-absent host still severs + relinks (fence on
        // retry after a partial run).
        let refence = run_csi(&tmp, |r, t| csi_host_revoke(r, &nqn, &host, t));
        assert_eq!(
            subtask_names(&refence),
            ["Revoke ACL", "Sever port", "Relink port"]
        );
        assert_eq!(task_status(&refence), SubStatus::Success);
        assert!(is_symlink(&port_link));

        // Delete: unlink, subsystem gone, empty CSI port reaped; a second
        // delete is all-skipped, not an error.
        assert_eq!(
            task_status(&run_csi(&tmp, |r, t| csi_delete(r, &nqn, t))),
            SubStatus::Success
        );
        assert!(!subsys.exists());
        assert!(!port.exists(), "empty CSI port reaped");
        assert_eq!(
            task_status(&run_csi(&tmp, |r, t| csi_delete(r, &nqn, t))),
            SubStatus::Skipped
        );

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    fn nqn_of(s: &str) -> Nqn {
        Nqn::new(s).unwrap()
    }

    /// Seeds a CSI subsystem + port, then runs the web's reconcile apply over
    /// the same tree: the CSI objects must be untouched (they are foreign to
    /// the web prefix), pinning the two-owner split the CSI design rests on.
    #[test]
    fn web_reconcile_ignores_csi_subsystems() {
        let tmp = std::env::temp_dir().join(format!("gd-nvmet-csiweb{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let op = csi_op("pvc-9", "/dev/zvol/tank/csi/pvc-9");
        run_csi(&tmp, |r, t| csi_apply(r, &op, t));
        let host = nqn_of("nqn.2014-08.org.nvmexpress:host1");
        run_csi(&tmp, |r, t| csi_host_grant(r, &op.nqn, &host, t));

        // A web reconcile that wants its own export and (later) nothing at all.
        let desired = NvmetDesired {
            subsystems: vec![subsys("vm1", "/dev/zvol/tank/vm1", true, &[])],
            ports: vec![port(1, Transport::Tcp, &["vm1"])],
        };
        assert!(run(&desired, &tmp));
        assert!(run(&NvmetDesired::default(), &tmp));

        // The CSI subsystem, its grant, and its port survived both passes.
        let subsys = tmp.join("subsystems/nqn.2026-06.io.greendot.csi:pvc-9");
        assert!(subsys.is_dir(), "CSI subsystem preserved");
        assert!(is_symlink(
            &subsys.join("allowed_hosts").join(host.as_str())
        ));
        assert_eq!(
            read_trim(&tmp.join(format!("ports/{CSI_PORT_ID}/addr_trsvcid"))),
            "4421"
        );
        assert!(is_symlink(&tmp.join(format!(
            "ports/{CSI_PORT_ID}/subsystems/nqn.2026-06.io.greendot.csi:pvc-9"
        ))));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn csi_expand_detached_and_partial_failure_retries() {
        for (name, attached, current, fail_resize, revalidate) in [
            ("fresh", false, 10, false, false),
            ("detached-after-use", false, 20, false, false),
            ("attached", true, 10, false, true),
            ("already-grown", true, 20, false, true),
            ("older-request", true, 30, false, true),
            ("resize-failed", true, 10, true, true),
            ("revalidate-failed", true, 10, false, false),
        ] {
            let tmp = std::env::temp_dir().join(format!("gd-expand-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp).unwrap();
            let op = csi_op("tank:csi:pvc-1", "/dev/zvol/tank/csi/pvc-1");
            let ns = tmp
                .join("subsystems")
                .join(op.nqn.as_str())
                .join("namespaces/1");
            if attached {
                run_csi(&tmp, |root, task| csi_apply(root, &op, task));
                if revalidate {
                    std::fs::write(ns.join("revalidate_size"), "0").unwrap();
                }
            }
            let mut size = current;
            let events = run_csi(&tmp, |root, task| {
                expand_volume(
                    root,
                    &op.nqn,
                    20,
                    task,
                    |_, dataset| {
                        assert_eq!(dataset.as_str(), "tank/csi/pvc-1");
                        Ok(Some(current))
                    },
                    |task, _, requested| {
                        assert!(requested > size);
                        if fail_resize {
                            task.begin_subtask("Resize").fail("injected resize failure");
                            Ok(SubStatus::Failed)
                        } else {
                            size = requested;
                            Ok(SubStatus::Success)
                        }
                    },
                )
            });
            assert_eq!(
                task_status(&events),
                if fail_resize || attached && !revalidate {
                    SubStatus::Failed
                } else {
                    SubStatus::Success
                },
                "{name}"
            );
            assert_eq!(
                size,
                if fail_resize {
                    current
                } else {
                    current.max(20)
                },
                "{name}"
            );
            if attached && revalidate {
                assert_eq!(
                    read_trim(&ns.join("revalidate_size")),
                    if fail_resize { "0" } else { "1" }
                );
            }
            if attached && !revalidate {
                // Grow succeeded; repair the interrupted revalidate without
                // issuing a second grow, even though ZFS already has the size.
                std::fs::write(ns.join("revalidate_size"), "0").unwrap();
                let retry = run_csi(&tmp, |root, task| {
                    expand_volume(
                        root,
                        &op.nqn,
                        20,
                        task,
                        |_, _| Ok(Some(size)),
                        |_, _, _| panic!("retry must not resize"),
                    )
                });
                assert_eq!(task_status(&retry), SubStatus::Success);
                assert_eq!(read_trim(&ns.join("revalidate_size")), "1");
            }
            if !attached {
                assert!(
                    !tmp.join("subsystems").exists(),
                    "detached grow must not export"
                );
            }
            std::fs::remove_dir_all(tmp).unwrap();
        }
    }

    /// Legacy leaf NQNs require a zvol-backed namespace, and a failed
    /// capacity read must not reach resize or revalidation.
    #[test]
    fn csi_expand_resolves_and_gates_on_the_zvol() {
        let tmp = std::env::temp_dir().join(format!("gd-nvmet-csiexp{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let nqn = CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap();

        // No subsystem at all → not zvol-backed, one failed subtask.
        let events = run_csi(&tmp, |r, t| csi_expand(r, &nqn, 1 << 30, t));
        assert_eq!(subtask_names(&events), ["Resolve backing zvol"]);
        assert_eq!(task_status(&events), SubStatus::Failed);

        // A zvol-backed namespace resolves, but its capacity read fails here
        // (no zfs / no such dataset); resize and revalidate must not run.
        let op = csi_op("pvc-1", "/dev/zvol/tank/csi/pvc-1");
        run_csi(&tmp, |r, t| csi_apply(r, &op, t));
        let events = run_csi(&tmp, |r, t| csi_expand(r, &nqn, 1 << 30, t));
        assert_eq!(
            subtask_names(&events),
            ["Read capacity tank/csi/pvc-1"],
            "stops after the failed resize"
        );
        assert_eq!(task_status(&events), SubStatus::Failed);

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
