//! ZFS mutations as `zfs` CLI tasks. Reads happen unprivileged in greendot-web.

use crate::cmd::{self, TaskSpec};
use crate::util::s;
use greendot_proto::{
    DatasetName, DevicePath, MountPoint, PoolName, SnapName, SubStatus, Task, VdevClass,
    VdevLayout, VdevTarget,
};
use std::io;
use std::path::Path;

fn spec(args: Vec<String>) -> TaskSpec {
    TaskSpec::new("zfs", args)
}

fn zpool_spec(args: Vec<String>) -> TaskSpec {
    TaskSpec::new("zpool", args)
}

pub fn zvol_create(
    dataset: &DatasetName,
    size: u64,
    volblocksize: Option<u32>,
    sparse: bool,
) -> TaskSpec {
    let mut args = s(&["create"]);
    if sparse {
        args.push("-s".into());
    }
    if let Some(vbs) = volblocksize {
        args.extend(s(&["-o", &format!("volblocksize={vbs}")]));
    }
    args.extend(s(&["-V", &size.to_string(), dataset.as_str()]));
    spec(args)
}

pub fn zvol_delete(dataset: &DatasetName) -> TaskSpec {
    spec(s(&["destroy", dataset.as_str()]))
}

pub fn zvol_resize(dataset: &DatasetName, new_size: u64) -> TaskSpec {
    spec(s(&[
        "set",
        &format!("volsize={new_size}"),
        dataset.as_str(),
    ]))
}

pub fn snapshot_create(dataset: &DatasetName, snap: &SnapName) -> TaskSpec {
    spec(s(&["snapshot", &format!("{dataset}@{snap}")]))
}

pub fn snapshot_destroy(dataset: &DatasetName, snap: &SnapName) -> TaskSpec {
    spec(s(&["destroy", &format!("{dataset}@{snap}")]))
}

/// `zfs clone <dataset>@<snap> <target>`.
pub fn zfs_clone(dataset: &DatasetName, snap: &SnapName, target: &DatasetName) -> TaskSpec {
    spec(s(&["clone", &format!("{dataset}@{snap}"), target.as_str()]))
}

/// `zfs clone` then the optional volsize bump as one task (a clone inherits
/// the origin's volsize, so creating a bigger volume from a snapshot is one
/// intent). The resize is skipped when the clone itself failed.
pub fn zfs_clone_and_resize(
    task: &mut Task,
    dataset: &DatasetName,
    snap: &SnapName,
    target: &DatasetName,
    new_size: Option<u64>,
) -> io::Result<()> {
    if cmd::run(
        task,
        format!("Clone {dataset}@{snap} to {target}"),
        &zfs_clone(dataset, snap, target),
    )? != SubStatus::Success
    {
        return Ok(());
    }
    if let Some(size) = new_size {
        cmd::run(task, format!("Resize {target}"), &zvol_resize(target, size))?;
    }
    Ok(())
}

/// Whether `/dev/zvol/<dataset>` exists and its size in bytes, via the udev
/// symlink and the block device's `size` attribute (512-byte sectors) — pure
/// filesystem reads, no `zfs` CLI. Roots are parameters for the tempdir tests.
pub fn zvol_info(dev_zvol: &Path, sys_block: &Path, dataset: &DatasetName) -> (bool, u64) {
    let Ok(target) = std::fs::canonicalize(dev_zvol.join(dataset.as_str())) else {
        return (false, 0);
    };
    let Some(name) = target.file_name().and_then(|n| n.to_str()) else {
        return (false, 0);
    };
    let sectors: u64 = crate::util::read_trim(&sys_block.join(name).join("size"))
        .parse()
        .unwrap_or(0);
    (true, sectors * 512)
}

/// `zpool create [-o ashift=N] <name> [mirror|raidzN] <dev>…`. A plain stripe
/// emits no vdev keyword.
pub fn pool_create(
    name: &PoolName,
    vdev: VdevLayout,
    devices: &[DevicePath],
    ashift: Option<u8>,
) -> TaskSpec {
    let mut args = s(&["create"]);
    if let Some(a) = ashift {
        args.extend(s(&["-o", &format!("ashift={a}")]));
    }
    args.push(name.to_string());
    if let Some(keyword) = vdev.keyword() {
        args.push(keyword.to_string());
    }
    args.extend(devices.iter().map(|d| d.to_string()));
    zpool_spec(args)
}

/// `zpool add <pool> [class] [layout] <dev>…` — one new top-level vdev. A data
/// vdev emits no class keyword and a plain stripe no layout keyword, matching
/// zpool's grammar (`zpool add tank special mirror a b`, `zpool add tank cache
/// x`). No `-f`: zpool refuses (and reports) a vdev that would reduce the
/// pool's redundancy, which is the desired behaviour.
pub fn pool_vdev_add(
    pool: &PoolName,
    class: VdevClass,
    layout: VdevLayout,
    devices: &[DevicePath],
) -> TaskSpec {
    let mut args = s(&["add", pool.as_str()]);
    if let Some(keyword) = class.keyword() {
        args.push(keyword.to_string());
    }
    if let Some(keyword) = layout.keyword() {
        args.push(keyword.to_string());
    }
    args.extend(devices.iter().map(|d| d.to_string()));
    zpool_spec(args)
}

/// `zpool attach <pool> <target> <device>` — grow a mirror (or make one from
/// a single disk), or expand a raidz vdev when the target is its name.
pub fn pool_device_attach(pool: &PoolName, target: &VdevTarget, device: &DevicePath) -> TaskSpec {
    zpool_spec(s(&[
        "attach",
        pool.as_str(),
        target.as_str(),
        device.as_str(),
    ]))
}

/// `zpool remove <pool> <target>` — a leaf device or a top-level vdev name.
pub fn pool_device_remove(pool: &PoolName, target: &VdevTarget) -> TaskSpec {
    zpool_spec(s(&["remove", pool.as_str(), target.as_str()]))
}

/// `zpool wait -t remove <pool>` — blocks until device evacuation completes.
pub fn pool_wait_remove(pool: &PoolName) -> TaskSpec {
    zpool_spec(s(&["wait", "-t", "remove", pool.as_str()]))
}

/// `zpool detach <pool> <device>` — take a leaf device out of its mirror.
pub fn pool_device_detach(pool: &PoolName, device: &DevicePath) -> TaskSpec {
    zpool_spec(s(&["detach", pool.as_str(), device.as_str()]))
}

/// `zpool online <pool> <device>` — bring a REMOVED/OFFLINE leaf device back
/// into service (zpool resilvers it to catch up on writes made while it was gone).
pub fn pool_device_online(pool: &PoolName, device: &DevicePath) -> TaskSpec {
    zpool_spec(s(&["online", pool.as_str(), device.as_str()]))
}

/// `zpool remove` then `zpool wait -t remove` as one task, so the task only
/// finishes when evacuation completes (instant for log/cache/spare devices).
/// The wait is skipped when the remove itself failed — it would otherwise
/// succeed vacuously and paint a green subtask after the failure.
pub fn pool_device_remove_and_wait(
    task: &mut Task,
    pool: &PoolName,
    target: &VdevTarget,
) -> io::Result<()> {
    if cmd::run(
        task,
        format!("Remove {target} from {pool}"),
        &pool_device_remove(pool, target),
    )? != SubStatus::Success
    {
        return Ok(());
    }
    cmd::run(
        task,
        format!("Wait for {pool} device evacuation"),
        &pool_wait_remove(pool),
    )?;
    Ok(())
}

/// `zfs create [-o mountpoint=<p>] <dataset>` — a filesystem dataset (no `-V`,
/// which is the zvol distinction).
pub fn zfs_fs_create(dataset: &DatasetName, mountpoint: Option<&MountPoint>) -> TaskSpec {
    let mut args = s(&["create"]);
    if let Some(mp) = mountpoint {
        args.extend(s(&["-o", &format!("mountpoint={mp}")]));
    }
    args.push(dataset.to_string());
    spec(args)
}

/// `zfs set mountpoint=<p> <dataset>`.
pub fn zfs_set_mountpoint(dataset: &DatasetName, mountpoint: &MountPoint) -> TaskSpec {
    spec(s(&[
        "set",
        &format!("mountpoint={mountpoint}"),
        dataset.as_str(),
    ]))
}

/// `zfs mount <dataset>`.
pub fn zfs_mount(dataset: &DatasetName) -> TaskSpec {
    spec(s(&["mount", dataset.as_str()]))
}

/// `zfs unmount <dataset>`.
pub fn zfs_unmount(dataset: &DatasetName) -> TaskSpec {
    spec(s(&["unmount", dataset.as_str()]))
}

/// `zfs destroy [-r] <dataset>` — destroys a filesystem dataset (recursively
/// when it has child datasets/snapshots). Distinct from [`zvol_delete`], which
/// never recurses.
pub fn zfs_destroy(dataset: &DatasetName, recursive: bool) -> TaskSpec {
    let mut args = s(&["destroy"]);
    if recursive {
        args.push("-r".into());
    }
    args.push(dataset.to_string());
    spec(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn ds(s: &str) -> DatasetName {
        DatasetName::new(s).unwrap()
    }

    #[rstest]
    #[case::plain(None, false, &["create", "-V", "10737418240", "tank/vm1"])]
    #[case::sparse(None, true, &["create", "-s", "-V", "10737418240", "tank/vm1"])]
    #[case::volblocksize(Some(16384), false,
        &["create", "-o", "volblocksize=16384", "-V", "10737418240", "tank/vm1"])]
    fn zvol_create_args(
        #[case] volblocksize: Option<u32>,
        #[case] sparse: bool,
        #[case] expected: &[&str],
    ) {
        let spec = zvol_create(&ds("tank/vm1"), 10 << 30, volblocksize, sparse);
        assert_eq!(spec.command, "zfs");
        assert_eq!(
            spec.args,
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(spec.stdin, None);
    }

    fn dp(s: &str) -> DevicePath {
        DevicePath::new(s).unwrap()
    }

    fn pool() -> PoolName {
        PoolName::new("tank").unwrap()
    }

    #[rstest]
    #[case::stripe(VdevLayout::Stripe, None, &["sdb"],
        &["create", "tank", "/dev/sdb"])]
    #[case::mirror_ashift(VdevLayout::Mirror, Some(12), &["sdb", "sdc"],
        &["create", "-o", "ashift=12", "tank", "mirror", "/dev/sdb", "/dev/sdc"])]
    #[case::raidz2(VdevLayout::Raidz2, None, &["sdb", "sdc", "sdd"],
        &["create", "tank", "raidz2", "/dev/sdb", "/dev/sdc", "/dev/sdd"])]
    fn pool_create_args(
        #[case] vdev: VdevLayout,
        #[case] ashift: Option<u8>,
        #[case] devs: &[&str],
        #[case] expected: &[&str],
    ) {
        let devices: Vec<_> = devs.iter().map(|d| dp(&format!("/dev/{d}"))).collect();
        let spec = pool_create(&pool(), vdev, &devices, ashift);
        assert_eq!(spec.command, "zpool");
        assert_eq!(
            spec.args,
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "stripe must not emit an empty vdev keyword"
        );
    }

    #[rstest]
    #[case::data_stripe(VdevClass::Data, VdevLayout::Stripe, &["sdd"],
        &["add", "tank", "/dev/sdd"])]
    #[case::special_mirror(VdevClass::Special, VdevLayout::Mirror, &["sdd", "sde"],
        &["add", "tank", "special", "mirror", "/dev/sdd", "/dev/sde"])]
    #[case::log_mirror(VdevClass::Log, VdevLayout::Mirror, &["sdd", "sde"],
        &["add", "tank", "log", "mirror", "/dev/sdd", "/dev/sde"])]
    #[case::cache(VdevClass::Cache, VdevLayout::Stripe, &["sdd"],
        &["add", "tank", "cache", "/dev/sdd"])]
    #[case::spare(VdevClass::Spare, VdevLayout::Stripe, &["sdd"],
        &["add", "tank", "spare", "/dev/sdd"])]
    #[case::data_raidz2(VdevClass::Data, VdevLayout::Raidz2, &["sdd", "sde", "sdf"],
        &["add", "tank", "raidz2", "/dev/sdd", "/dev/sde", "/dev/sdf"])]
    fn pool_vdev_add_args(
        #[case] class: VdevClass,
        #[case] layout: VdevLayout,
        #[case] devs: &[&str],
        #[case] expected: &[&str],
    ) {
        let devices: Vec<_> = devs.iter().map(|d| dp(&format!("/dev/{d}"))).collect();
        let spec = pool_vdev_add(&pool(), class, layout, &devices);
        assert_eq!(spec.command, "zpool");
        assert_eq!(
            spec.args,
            s(expected),
            "data/stripe must not emit empty keywords"
        );
        assert!(!spec.args.iter().any(|a| a == "-f"), "no forced add");
    }

    #[rstest]
    #[case::remove_vdev(pool_device_remove(&pool(), &VdevTarget::new("mirror-0").unwrap()),
        &["remove", "tank", "mirror-0"])]
    #[case::remove_leaf(pool_device_remove(&pool(), &VdevTarget::new("/dev/sdd").unwrap()),
        &["remove", "tank", "/dev/sdd"])]
    #[case::wait(pool_wait_remove(&pool()), &["wait", "-t", "remove", "tank"])]
    #[case::detach(pool_device_detach(&pool(), &dp("/dev/sdc")), &["detach", "tank", "/dev/sdc"])]
    #[case::online(pool_device_online(&pool(), &dp("/dev/sdb")), &["online", "tank", "/dev/sdb"])]
    #[case::attach_leaf(pool_device_attach(&pool(), &VdevTarget::new("/dev/sdb").unwrap(), &dp("/dev/sdd")),
        &["attach", "tank", "/dev/sdb", "/dev/sdd"])]
    #[case::attach_raidz(pool_device_attach(&pool(), &VdevTarget::new("raidz1-0").unwrap(), &dp("/dev/sdd")),
        &["attach", "tank", "raidz1-0", "/dev/sdd"])]
    fn pool_remove_detach_args(#[case] spec: TaskSpec, #[case] expected: &[&str]) {
        assert_eq!(spec.command, "zpool");
        assert_eq!(spec.args, s(expected));
        assert!(!spec.args.iter().any(|a| a == "-f"), "no forced removal");
    }

    #[test]
    fn other_ops_args() {
        assert_eq!(
            zvol_delete(&ds("tank/vm1")).args,
            s(&["destroy", "tank/vm1"])
        );
        assert_eq!(
            zvol_resize(&ds("tank/vm1"), 20 << 30).args,
            s(&["set", "volsize=21474836480", "tank/vm1"])
        );
        assert_eq!(
            snapshot_create(&ds("tank/vm1"), &SnapName::new("s1").unwrap()).args,
            s(&["snapshot", "tank/vm1@s1"])
        );
        assert_eq!(
            snapshot_destroy(&ds("tank/vm1"), &SnapName::new("s1").unwrap()).args,
            s(&["destroy", "tank/vm1@s1"])
        );
        assert_eq!(
            zfs_clone(
                &ds("tank/csi/pvc-1"),
                &SnapName::new("csi-s1").unwrap(),
                &ds("tank/csi/pvc-2"),
            )
            .args,
            s(&["clone", "tank/csi/pvc-1@csi-s1", "tank/csi/pvc-2"])
        );
    }

    /// `zvol_info` through a fake udev/sysfs tree: present (symlink → zd0 with
    /// a sector count), absent, and a dangling symlink all answer sensibly.
    #[test]
    fn zvol_info_resolves_size_via_sysfs() {
        let tmp = std::env::temp_dir().join(format!("gd-zvolinfo{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let (dev, sys) = (tmp.join("dev/zvol"), tmp.join("sys/block"));
        std::fs::create_dir_all(dev.join("tank/csi")).unwrap();
        std::fs::create_dir_all(sys.join("zd0")).unwrap();
        std::fs::write(sys.join("zd0/size"), "2097152\n").unwrap(); // 1 GiB
        std::fs::write(tmp.join("zd0-target"), "").unwrap();
        std::os::unix::fs::symlink(tmp.join("zd0-target"), dev.join("tank/csi/pvc-1")).unwrap();
        // The canonicalized target's basename must match the sysfs dir; point
        // the link at a file literally named zd0.
        std::fs::rename(tmp.join("zd0-target"), tmp.join("zd0")).unwrap();
        std::os::unix::fs::symlink(tmp.join("zd0"), dev.join("tank/csi/pvc-2")).unwrap();

        assert_eq!(
            zvol_info(&dev, &sys, &ds("tank/csi/pvc-2")),
            (true, 1 << 30)
        );
        assert_eq!(
            zvol_info(&dev, &sys, &ds("tank/csi/absent")),
            (false, 0),
            "no symlink"
        );
        assert_eq!(
            zvol_info(&dev, &sys, &ds("tank/csi/pvc-1")),
            (false, 0),
            "dangling symlink"
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn filesystem_mount_lifecycle_args() {
        let mp = MountPoint::new("/srv/share").unwrap();
        assert_eq!(
            zfs_fs_create(&ds("tank/share"), None).args,
            s(&["create", "tank/share"]),
            "no mountpoint = inherit default; no -V"
        );
        assert_eq!(
            zfs_fs_create(&ds("tank/share"), Some(&mp)).args,
            s(&["create", "-o", "mountpoint=/srv/share", "tank/share"])
        );
        assert_eq!(
            zfs_set_mountpoint(&ds("tank/share"), &mp).args,
            s(&["set", "mountpoint=/srv/share", "tank/share"])
        );
        assert_eq!(
            zfs_mount(&ds("tank/share")).args,
            s(&["mount", "tank/share"])
        );
        assert_eq!(
            zfs_unmount(&ds("tank/share")).args,
            s(&["unmount", "tank/share"])
        );
        assert_eq!(
            zfs_destroy(&ds("tank/share"), false).args,
            s(&["destroy", "tank/share"])
        );
        assert_eq!(
            zfs_destroy(&ds("tank/share"), true).args,
            s(&["destroy", "-r", "tank/share"])
        );
        for spec in [
            zfs_fs_create(&ds("tank/share"), Some(&mp)),
            zfs_mount(&ds("tank/share")),
            zfs_destroy(&ds("tank/share"), true),
        ] {
            assert_eq!(spec.command, "zfs");
        }
    }
}
