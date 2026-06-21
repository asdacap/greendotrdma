//! ZFS mutations as `zfs` CLI tasks. Reads happen unprivileged in greendot-web.

use crate::cmd::TaskSpec;
use greendot_proto::{DatasetName, DevicePath, PoolName, SnapName, VdevLayout};

fn spec(args: Vec<String>) -> TaskSpec {
    TaskSpec::new("zfs", args)
}

fn zpool_spec(args: Vec<String>) -> TaskSpec {
    TaskSpec::new("zpool", args)
}

fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
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

/// `zpool add <pool> <device>`. No `-f`: zpool refuses (and reports) a vdev
/// that would reduce the pool's redundancy, which is the desired behaviour.
pub fn pool_device_add(pool: &PoolName, device: &DevicePath) -> TaskSpec {
    zpool_spec(s(&["add", pool.as_str(), device.as_str()]))
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

    #[test]
    fn pool_add_args() {
        let spec = pool_device_add(&pool(), &dp("/dev/sdd"));
        assert_eq!(spec.command, "zpool");
        assert_eq!(spec.args, s(&["add", "tank", "/dev/sdd"]));
        assert!(!spec.args.iter().any(|a| a == "-f"), "no forced add");
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
    }
}
