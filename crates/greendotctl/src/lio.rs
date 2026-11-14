//! Applies the desired iSCSI/LIO state by writing the kernel's LIO configfs
//! tree directly, like [`crate::nvmet`]. Scoped to our IQN prefix and to the
//! backstores our targets map: foreign targets, and the live sessions of our
//! targets that did not change, are left alone (`targetctl restore` cleared
//! and rebuilt the whole tree on every apply).
//!
//! Layout: each backstore is `core/iblock_<n>/<name>` (one HBA per object, as
//! rtslib does); each target is `iscsi/<iqn>/tpgt_1`, holding
//! `lun/lun_<n>/<link>` to its backstore, `np/<addr:port>` portals, and
//! `acls/<initiator>/lun_<n>/<link>` mapping each LUN to an explicit initiator.

use crate::nvmet::{
    create_dir_all_ok, dir_entries, remove_file_ok, remove_object_dir, symlink_ok, write_attr,
};
use crate::render::fmt_addr;
use crate::util::read_trim;
use greendot_proto::{
    LioBackstoreSpec, LioDesired, LioTargetSpec, OUR_IQN_PREFIX, SubStatus, SubTask,
};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Our targets carry exactly one target portal group.
const TPG: &str = "tpgt_1";

/// Reconciles configfs under `root` to `desired`, streaming progress into the
/// caller-opened subtask. Returns `Failed` (message recorded on the subtask)
/// on a configfs error; `Err` only when the sink itself fails.
pub fn apply(desired: &LioDesired, root: &Path, sub: &mut SubTask) -> io::Result<SubStatus> {
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

fn reconcile(desired: &LioDesired, root: &Path) -> io::Result<String> {
    let iscsi = root.join("iscsi");
    let wanted: BTreeSet<&str> = desired.targets.iter().map(|t| t.iqn.as_str()).collect();

    // A. Delete our targets that are no longer desired, remembering the
    //    backstores they mapped so phase D can reap them.
    let mut released = BTreeSet::new();
    for iqn in dir_entries(&iscsi) {
        if iqn.starts_with(OUR_IQN_PREFIX) && !wanted.contains(iqn.as_str()) {
            released.extend(delete_target(&iscsi.join(&iqn))?);
        }
    }

    // B. Create the desired backstores. One whose device changed is unmapped
    //    from our LUNs and recreated; phase C maps it again.
    for b in &desired.backstores {
        match find_backstore(root, b.name.as_str()) {
            Some(dir) if read_trim(&dir.join("udev_path")) == b.device_path.as_str() => {}
            Some(dir) => {
                unmap_backstore(root, b.name.as_str())?;
                delete_backstore(&dir)?;
                create_backstore(root, b)?;
            }
            None => create_backstore(root, b)?,
        }
    }

    // C. Create / update the desired targets in place.
    for t in &desired.targets {
        released.extend(apply_target(root, t)?);
    }

    // D. Reap the released backstores that nothing maps any more.
    let mapped = mapped_backstores(root);
    for name in released {
        let desired_bs = desired.backstores.iter().any(|b| b.name.as_str() == name);
        if !desired_bs
            && !mapped.contains(&name)
            && let Some(dir) = find_backstore(root, &name)
        {
            delete_backstore(&dir)?;
        }
    }

    Ok(format!(
        "reconciled LIO: {} backstore(s), {} target(s)\n",
        desired.backstores.len(),
        desired.targets.len()
    ))
}

// ---- backstores ----

/// `core/iblock_<n>/<name>`, whichever HBA holds it.
fn find_backstore(root: &Path, name: &str) -> Option<PathBuf> {
    let core = root.join("core");
    dir_entries(&core)
        .into_iter()
        .filter(|hba| hba.starts_with("iblock_"))
        .map(|hba| core.join(hba).join(name))
        .find(|dir| dir.is_dir())
}

/// Creates the backstore in a fresh HBA whose index no plugin's HBA uses.
fn create_backstore(root: &Path, b: &LioBackstoreSpec) -> io::Result<()> {
    let core = root.join("core");
    let used: BTreeSet<u32> = dir_entries(&core)
        .iter()
        .filter_map(|hba| hba.rsplit_once('_')?.1.parse().ok())
        .collect();
    let index = (0..).find(|i| !used.contains(i)).expect("a free HBA index");
    let dir = core.join(format!("iblock_{index}")).join(b.name.as_str());
    create_dir_all_ok(&dir)?;
    // `control` is write-only; `udev_path` is what the reader re-reads.
    write_attr(
        &dir.join("control"),
        &format!("udev_path={}", b.device_path),
    )?;
    write_attr(&dir.join("udev_path"), b.device_path.as_str())?;
    write_attr(&dir.join("enable"), "1")?;
    // The unit serial initiators identify the LUN by (rtslib sets one too).
    // No `emulate_write_cache`: iblock reports the device's own write cache,
    // and the kernel rejects setting it.
    create_dir_all_ok(&dir.join("wwn"))?;
    write_attr(&dir.join("wwn/vpd_unit_serial"), &random_uuid()?)
}

/// Removes the backstore, and its HBA once that holds nothing else.
fn delete_backstore(dir: &Path) -> io::Result<()> {
    remove_object_dir(dir)?;
    let hba = dir.parent().expect("a backstore sits in an HBA");
    if dir_entries(hba).iter().all(|n| !hba.join(n).is_dir()) {
        remove_object_dir(hba)?;
    }
    Ok(())
}

/// Deletes every LUN of our targets that maps backstore `name`.
fn unmap_backstore(root: &Path, name: &str) -> io::Result<()> {
    let iscsi = root.join("iscsi");
    for iqn in dir_entries(&iscsi) {
        if !iqn.starts_with(OUR_IQN_PREFIX) {
            continue;
        }
        let tpg = iscsi.join(iqn).join(TPG);
        for lun in dir_entries(&tpg.join("lun")) {
            if link_targets(&tpg.join("lun").join(&lun))
                .iter()
                .any(|t| t == name)
            {
                delete_lun(&tpg, &lun)?;
            }
        }
    }
    Ok(())
}

/// Every backstore some LUN maps, on any fabric (`<fabric>/<wwn>/tpgt_<n>/lun`).
fn mapped_backstores(root: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for fabric in dir_entries(root).into_iter().filter(|f| f != "core") {
        for wwn in dir_entries(&root.join(&fabric)) {
            let wwn = root.join(&fabric).join(wwn);
            for tpg in dir_entries(&wwn)
                .into_iter()
                .filter(|t| t.starts_with("tpgt_"))
            {
                let luns = wwn.join(tpg).join("lun");
                for lun in dir_entries(&luns) {
                    names.extend(link_targets(&luns.join(lun)));
                }
            }
        }
    }
    names
}

// ---- targets ----

/// Deletes one of our targets; returns the backstores its LUNs mapped.
fn delete_target(target: &Path) -> io::Result<Vec<String>> {
    let mut released = Vec::new();
    for tpg in dir_entries(target) {
        if !tpg.starts_with("tpgt_") {
            continue;
        }
        let tpg = target.join(tpg);
        write_attr(&tpg.join("enable"), "0")?;
        for acl in dir_entries(&tpg.join("acls")) {
            delete_acl(&tpg.join("acls").join(acl))?;
        }
        for lun in dir_entries(&tpg.join("lun")) {
            released.extend(remove_links_and_dir(&tpg.join("lun").join(lun))?);
        }
        for portal in dir_entries(&tpg.join("np")) {
            remove_object_dir(&tpg.join("np").join(portal))?;
        }
        remove_object_dir(&tpg)?;
    }
    remove_object_dir(target)?;
    Ok(released)
}

/// Creates / updates one of our targets in place, touching only what differs
/// so its unchanged parts keep their sessions; returns the backstores its
/// dropped LUNs mapped.
fn apply_target(root: &Path, t: &LioTargetSpec) -> io::Result<Vec<String>> {
    let tpg = root.join("iscsi").join(t.iqn.as_str()).join(TPG);
    create_dir_all_ok(&tpg.join("attrib"))?;
    let demo = if t.demo_mode { "1" } else { "0" };
    for (attr, value) in [
        ("authentication", "0"),
        ("generate_node_acls", demo),
        ("cache_dynamic_acls", demo),
        ("demo_mode_write_protect", "0"),
    ] {
        set_attr(&tpg.join("attrib").join(attr), value)?;
    }

    // LUNs: drop the undesired or repointed ones, then map the missing.
    let lun_name = |lun: u32| format!("lun_{lun}");
    let mut released = Vec::new();
    for lun in dir_entries(&tpg.join("lun")) {
        let keep = t.luns.iter().any(|l| {
            lun_name(l.lun) == lun
                && link_targets(&tpg.join("lun").join(&lun)) == [l.backstore.to_string()]
        });
        if !keep {
            released.extend(delete_lun(&tpg, &lun)?);
        }
    }
    for l in &t.luns {
        let dir = tpg.join("lun").join(lun_name(l.lun));
        if dir.is_dir() {
            continue;
        }
        let backstore = find_backstore(root, l.backstore.as_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("backstore {} is missing", l.backstore),
            )
        })?;
        create_dir_all_ok(&dir)?;
        symlink_ok(&backstore, &dir.join(l.backstore.as_str()))?;
    }

    // Portals, keyed by their `addr:port` directory name.
    let np = tpg.join("np");
    let portals: Vec<(String, bool)> = t
        .portals
        .iter()
        .map(|p| (fmt_addr(p.addr, p.port), p.iser))
        .collect();
    for portal in dir_entries(&np) {
        if !portals.iter().any(|(addr, _)| *addr == portal) {
            remove_object_dir(&np.join(portal))?;
        }
    }
    for (addr, iser) in &portals {
        create_dir_all_ok(&np.join(addr))?;
        set_attr(&np.join(addr).join("iser"), if *iser { "1" } else { "0" })?;
    }

    // Explicit ACLs, none in demo mode; each maps every LUN at its own index.
    let acls = tpg.join("acls");
    let wanted: BTreeSet<String> = if t.demo_mode {
        BTreeSet::new()
    } else {
        t.acls.iter().map(ToString::to_string).collect()
    };
    for acl in dir_entries(&acls) {
        if !wanted.contains(&acl) {
            delete_acl(&acls.join(acl))?;
        }
    }
    for acl in &wanted {
        create_dir_all_ok(&acls.join(acl))?;
        for l in &t.luns {
            let mapped = acls.join(acl).join(lun_name(l.lun));
            if link_targets(&mapped).is_empty() {
                create_dir_all_ok(&mapped)?;
                symlink_ok(
                    &tpg.join("lun").join(lun_name(l.lun)),
                    &mapped.join(lun_name(l.lun)),
                )?;
            }
        }
    }

    set_attr(&tpg.join("enable"), if t.enabled { "1" } else { "0" })?;
    Ok(released)
}

/// Deletes a target LUN and the ACL mappings of it (ours map `lun_<n>` at the
/// same index); returns the backstores it mapped.
fn delete_lun(tpg: &Path, lun: &str) -> io::Result<Vec<String>> {
    for acl in dir_entries(&tpg.join("acls")) {
        let mapped = tpg.join("acls").join(acl).join(lun);
        if mapped.is_dir() {
            remove_links_and_dir(&mapped)?;
        }
    }
    remove_links_and_dir(&tpg.join("lun").join(lun))
}

fn delete_acl(acl: &Path) -> io::Result<()> {
    for mapped in dir_entries(acl) {
        if mapped.starts_with("lun_") {
            remove_links_and_dir(&acl.join(mapped))?;
        }
    }
    remove_object_dir(acl)
}

// ---- configfs plumbing ----

/// The basenames the symlinks in `dir` point at (a LUN's backstore).
fn link_targets(dir: &Path) -> Vec<String> {
    dir_entries(dir)
        .into_iter()
        .filter_map(|n| std::fs::read_link(dir.join(n)).ok())
        .filter_map(|t| Some(t.file_name()?.to_string_lossy().into_owned()))
        .collect()
}

/// Removes the symlinks in a configfs object dir, then the dir; returns what
/// they pointed at.
fn remove_links_and_dir(dir: &Path) -> io::Result<Vec<String>> {
    let targets = link_targets(dir);
    for n in dir_entries(dir) {
        if dir.join(&n).is_symlink() {
            remove_file_ok(&dir.join(n))?;
        }
    }
    remove_object_dir(dir)?;
    Ok(targets)
}

/// Writes an attribute only when it differs, leaving unchanged targets be.
fn set_attr(path: &Path, value: &str) -> io::Result<()> {
    if read_trim(path) == value {
        Ok(())
    } else {
        write_attr(path, value)
    }
}

fn random_uuid() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/uuid")?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Collector;
    use crate::render::lio_satisfied;
    use greendot_proto::{
        BackstoreName, DevicePath, Iqn, LioBackstoreSpec, LioLunSpec, LioPortalSpec, Task,
    };

    fn run(desired: &LioDesired, root: &Path) -> bool {
        let mut c = Collector::default();
        let mut task = Task::new(&mut c);
        let mut sub = task.begin_subtask("Apply iSCSI configuration");
        let status = apply(desired, root, &mut sub).unwrap();
        sub.complete(status);
        task.complete().unwrap();
        status == SubStatus::Success
    }

    fn export(name: &str, dev: &str, demo_mode: bool) -> (LioBackstoreSpec, LioTargetSpec) {
        let backstore = BackstoreName::new(name).unwrap();
        (
            LioBackstoreSpec {
                name: backstore.clone(),
                device_path: DevicePath::new(dev).unwrap(),
            },
            LioTargetSpec {
                iqn: Iqn::new(format!("iqn.2026-06.io.greendot:{name}")).unwrap(),
                enabled: true,
                demo_mode,
                luns: vec![LioLunSpec { lun: 0, backstore }],
                portals: vec![LioPortalSpec {
                    addr: "10.0.0.5".parse().unwrap(),
                    port: 3260,
                    iser: true,
                }],
                acls: vec![Iqn::new("iqn.1993-08.org.debian:01:abc").unwrap()],
            },
        )
    }

    fn desired(exports: &[(LioBackstoreSpec, LioTargetSpec)]) -> LioDesired {
        LioDesired {
            backstores: exports.iter().map(|(b, _)| b.clone()).collect(),
            targets: exports.iter().map(|(_, t)| t.clone()).collect(),
        }
    }

    #[test]
    fn applies_in_place_and_leaves_foreign_objects() {
        let tmp = std::env::temp_dir().join(format!("gd-lio-apply{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // A foreign target mapping a foreign backstore in HBA 0.
        let foreign_bs = tmp.join("core/iblock_0/foreign");
        let foreign_lun = tmp.join("iscsi/iqn.2003-01.org.example:foreign/tpgt_1/lun/lun_0");
        std::fs::create_dir_all(&foreign_bs).unwrap();
        std::fs::create_dir_all(&foreign_lun).unwrap();
        std::os::unix::fs::symlink(&foreign_bs, foreign_lun.join("x")).unwrap();
        let satisfied = |d: &LioDesired| lio_satisfied(d, &crate::actual::lio::read(&tmp));

        // Two exports: each backstore gets a fresh HBA, and the reader agrees.
        let (vm1, vm2) = (
            export("vm1", "/dev/zvol/tank/vm1", false),
            export("vm2", "/dev/zvol/tank/vm2", false),
        );
        let both = desired(&[vm1.clone(), vm2.clone()]);
        assert!(run(&both, &tmp));
        assert!(satisfied(&both));
        let tpg = |name: &str| tmp.join(format!("iscsi/iqn.2026-06.io.greendot:{name}/tpgt_1"));
        assert_eq!(
            read_trim(&tmp.join("core/iblock_1/vm1/udev_path")),
            "/dev/zvol/tank/vm1"
        );
        assert_eq!(read_trim(&tmp.join("core/iblock_2/vm2/enable")), "1");
        assert_eq!(read_trim(&tpg("vm1").join("np/10.0.0.5:3260/iser")), "1");
        assert_eq!(
            link_targets(&tpg("vm1").join("acls/iqn.1993-08.org.debian:01:abc/lun_0")),
            ["lun_0"]
        );
        assert!(run(&both, &tmp), "re-applying a satisfied tree is a no-op");

        // vm1 switches to demo mode and a new device; vm2 is untouched.
        let vm2_lun = std::fs::symlink_metadata(tpg("vm2").join("lun/lun_0/vm2")).unwrap();
        let vm1_moved = export("vm1", "/dev/zvol/tank/vm1b", true);
        let changed = desired(&[vm1_moved, vm2.clone()]);
        assert!(run(&changed, &tmp));
        assert!(satisfied(&changed));
        assert!(dir_entries(&tpg("vm1").join("acls")).is_empty());
        let vm2_lun_after = std::fs::symlink_metadata(tpg("vm2").join("lun/lun_0/vm2")).unwrap();
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&vm2_lun),
            std::os::unix::fs::MetadataExt::ino(&vm2_lun_after),
            "vm2's LUN was rebuilt"
        );

        // Removing vm1 deletes its target and reaps its backstore and HBA.
        let only_vm2 = desired(&[vm2]);
        assert!(run(&only_vm2, &tmp));
        assert!(satisfied(&only_vm2));
        assert!(!tmp.join("iscsi/iqn.2026-06.io.greendot:vm1").exists());
        assert!(find_backstore(&tmp, "vm1").is_none());
        assert!(foreign_bs.is_dir() && foreign_lun.join("x").is_symlink());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
