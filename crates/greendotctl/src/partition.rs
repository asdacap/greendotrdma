//! GPT partitioning as `sfdisk` CLI tasks. sfdisk re-reads the table itself.

use crate::cmd::TaskSpec;
use crate::util::{dev, s};
use greendot_proto::{BlockDev, PartLabel};
use std::path::Path;

/// Writes a brand-new empty GPT — destroys the existing table.
///
/// `--wipe always` is required: sfdisk's `auto` default only erases filesystem
/// signatures in interactive mode, so a piped script leaves a stale
/// `zfs_member`/`LVM2_member` magic behind and the disk stays unusable.
pub fn table_create(disk: &BlockDev) -> TaskSpec {
    TaskSpec::with_stdin(
        "sfdisk",
        s(&["--wipe", "always", &dev(disk)]),
        "label: gpt\n".into(),
    )
}

pub fn partition_create(
    disk: &BlockDev,
    start_sector: Option<u64>,
    size_sectors: Option<u64>,
    label: &PartLabel,
) -> TaskSpec {
    let mut fields = Vec::new();
    if let Some(start) = start_sector {
        fields.push(format!("start={start}"));
    }
    if let Some(size) = size_sectors {
        fields.push(format!("size={size}"));
    }
    fields.push(format!("name={label}"));
    let script = format!("{}\n", fields.join(", "));
    // `--wipe-partitions always`: a new partition at a removed one's offset would
    // otherwise inherit its signature (a stale `zfs_member`) and stay unusable.
    TaskSpec::with_stdin(
        "sfdisk",
        s(&["--wipe-partitions", "always", "--append", &dev(disk)]),
        script,
    )
}

pub fn partition_delete(disk: &BlockDev, number: u32) -> TaskSpec {
    TaskSpec::new("sfdisk", s(&["--delete", &dev(disk), &number.to_string()]))
}

/// `wipefs --all <partitions…> <device>` — partitions before their disk: a
/// removed vdev's ZFS label sits inside its partition, out of reach of a wipe
/// of the disk alone. wipefs opens each device `O_EXCL`, so the kernel refuses
/// anything mounted, an imported pool's vdev, or an active PV.
pub fn wipe(device: &BlockDev, partitions: &[String]) -> TaskSpec {
    let mut args = s(&["--all"]);
    args.extend(partitions.iter().map(|p| format!("/dev/{p}")));
    args.push(dev(device));
    TaskSpec::new("wipefs", args)
}

/// The partitions of `device` under `sys_class_block` (the entries carrying a
/// `partition` attribute); empty for a partition or an unknown device.
pub fn partitions_of(sys_class_block: &Path, device: &BlockDev) -> Vec<String> {
    let dir = sys_class_block.join(device.as_str());
    crate::actual::dir_names(&dir)
        .into_iter()
        .filter(|name| dir.join(name).join("partition").is_file())
        .collect()
}

/// Resizes partition `number` to `size_sectors`, preserving its start. The
/// script carries *only* `size=` — with `-N`, sfdisk keeps the unspecified
/// start sector (emitting `start=` would move the partition and corrupt data).
pub fn partition_resize(disk: &BlockDev, number: u32, size_sectors: u64) -> TaskSpec {
    TaskSpec::with_stdin(
        "sfdisk",
        s(&["-N", &number.to_string(), &dev(disk)]),
        format!("size={size_sectors}\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn disk() -> BlockDev {
        BlockDev::new("sdb").unwrap()
    }

    #[rstest]
    #[case::full_spec(Some(2048), Some(2097152), "start=2048, size=2097152, name=data\n")]
    #[case::size_only(None, Some(2097152), "size=2097152, name=data\n")]
    #[case::rest_of_disk(None, None, "name=data\n")]
    fn partition_create_script(
        #[case] start: Option<u64>,
        #[case] size: Option<u64>,
        #[case] script: &str,
    ) {
        let spec = partition_create(&disk(), start, size, &PartLabel::new("data").unwrap());
        assert_eq!(spec.command, "sfdisk");
        assert_eq!(
            spec.args,
            s(&["--wipe-partitions", "always", "--append", "/dev/sdb"])
        );
        assert_eq!(spec.stdin.as_deref(), Some(script));
    }

    #[test]
    fn table_create_and_delete() {
        let t = table_create(&disk());
        assert_eq!(
            (t.command.as_str(), t.args.clone(), t.stdin.as_deref()),
            (
                "sfdisk",
                s(&["--wipe", "always", "/dev/sdb"]),
                Some("label: gpt\n")
            )
        );
        let d = partition_delete(&disk(), 3);
        assert_eq!(
            (d.command.as_str(), d.args, d.stdin),
            ("sfdisk", s(&["--delete", "/dev/sdb", "3"]), None)
        );
    }

    /// A fake `/sys/class/block/sdb`: only the entries with a `partition`
    /// attribute are partitions, and the wipe runs them before the disk.
    #[test]
    fn wipe_covers_partitions_before_the_disk() {
        let tmp = std::env::temp_dir().join(format!("gd-wipe{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        for dir in ["sdb/sdb1", "sdb/sdb9", "sdb/queue", "sdb1"] {
            std::fs::create_dir_all(tmp.join(dir)).unwrap();
        }
        std::fs::write(tmp.join("sdb/sdb1/partition"), "1\n").unwrap();
        std::fs::write(tmp.join("sdb/sdb9/partition"), "9\n").unwrap();

        let partitions = partitions_of(&tmp, &disk());
        assert_eq!(partitions, s(&["sdb1", "sdb9"]));
        let spec = wipe(&disk(), &partitions);
        assert_eq!(
            (spec.command.as_str(), spec.args),
            (
                "wipefs",
                s(&["--all", "/dev/sdb1", "/dev/sdb9", "/dev/sdb"])
            )
        );
        let sdb1 = BlockDev::new("sdb1").unwrap();
        assert!(
            partitions_of(&tmp, &sdb1).is_empty(),
            "a partition has none"
        );
        assert_eq!(wipe(&sdb1, &[]).args, s(&["--all", "/dev/sdb1"]));
        assert!(partitions_of(&tmp, &BlockDev::new("sdz").unwrap()).is_empty());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn partition_resize_keeps_start() {
        let r = partition_resize(&disk(), 2, 2097152);
        assert_eq!(r.command, "sfdisk");
        assert_eq!(r.args, s(&["-N", "2", "/dev/sdb"]));
        let stdin = r.stdin.as_deref().unwrap();
        assert_eq!(stdin, "size=2097152\n");
        assert!(
            !stdin.contains("start="),
            "must not move the partition start"
        );
    }
}
