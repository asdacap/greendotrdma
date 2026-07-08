//! Partition shrink as one helper-side operation: probe the filesystem, shrink
//! it, then resize the partition — one subtask per step, all under the caller's
//! mutate lock. The filesystem always shrinks *before* the partition boundary,
//! and a failed step stops the sequence, so the filesystem is never left larger
//! than its partition. All filesystem knowledge (ext* shrinks offline; btrfs
//! only resizes while mounted, so it gets a helper-owned temp mount under
//! `/run/greendotrdma`) lives here — none of it crosses the wire.

use crate::cmd::{self, TaskSpec};
use crate::partition;
use crate::util::s;
use greendot_proto::{BlockDev, SubStatus, Task};
use std::io;

/// Partition device name per the kernel's naming rule: `<disk><n>`, or
/// `<disk>p<n>` when the disk name ends in a digit (`nvme0n1` → `nvme0n1p2`).
fn part_name(disk: &BlockDev, number: u32) -> String {
    if disk.as_str().ends_with(|c: char| c.is_ascii_digit()) {
        format!("{disk}p{number}")
    } else {
        format!("{disk}{number}")
    }
}

/// What the probe learned about the partition to shrink.
struct Probe {
    fstype: Option<String>,
    mounted: bool,
}

/// `lsblk -J -o FSTYPE,MOUNTPOINT <device>` — one node, no children.
fn lsblk(device: &str) -> TaskSpec {
    TaskSpec::new("lsblk", s(&["-J", "-o", "FSTYPE,MOUNTPOINT", device]))
}

/// Parses [`lsblk`]'s JSON: `{"blockdevices":[{"fstype":…,"mountpoint":…}]}`.
/// `None` when the device wasn't found (empty list) or the shape is wrong.
fn parse_probe(json: &str) -> Option<Probe> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let dev = v.get("blockdevices")?.as_array()?.first()?;
    let text = |key| {
        dev.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    Some(Probe {
        fstype: text("fstype"),
        mounted: text("mountpoint").is_some(),
    })
}

/// How (or why not) the filesystem can shrink. The web runs the same table as
/// an advisory UI gate; this is the enforced copy — it holds against every
/// caller, not just the web's happy path.
enum FsPlan {
    Ext,
    Btrfs,
    Raw,
}

fn plan_fs(fstype: Option<&str>, mounted: bool) -> Result<FsPlan, String> {
    match fstype {
        None => Ok(FsPlan::Raw),
        Some("ext2" | "ext3" | "ext4") if !mounted => Ok(FsPlan::Ext),
        Some("btrfs") if !mounted => Ok(FsPlan::Btrfs),
        Some("ext2" | "ext3" | "ext4" | "btrfs") => Err("mounted — unmount it first".into()),
        Some("xfs") => Err("XFS cannot be shrunk".into()),
        Some("zfs_member") => Err("part of a ZFS pool".into()),
        Some("LVM2_member") => Err("part of an LVM volume group".into()),
        Some(_) => Err("this filesystem cannot be shrunk".into()),
    }
}

/// `e2fsck -f -y <device>` — resize2fs refuses to shrink an unchecked fs.
fn fsck(device: &str) -> TaskSpec {
    TaskSpec::new("e2fsck", s(&["-f", "-y", device]))
}

/// `resize2fs <device> <N>s` — the `s` suffix is 512-byte sectors, sidestepping
/// the filesystem-block-size unit footgun.
fn resize_ext(device: &str, new_size_sectors: u64) -> TaskSpec {
    TaskSpec::new("resize2fs", s(&[device, &format!("{new_size_sectors}s")]))
}

/// `mount --mkdir -t btrfs <device> <mount_path>` — btrfs resizes only while
/// mounted, so it is temp-mounted at a fixed path (whose parent
/// `/run/greendotrdma` is the service's RuntimeDirectory).
fn btrfs_mount(device: &str, mount_path: &str) -> TaskSpec {
    TaskSpec::new("mount", s(&["--mkdir", "-t", "btrfs", device, mount_path]))
}

/// `btrfs filesystem resize <bytes> <mount_path>`.
fn btrfs_resize(mount_path: &str, new_size: u64) -> TaskSpec {
    TaskSpec::new(
        "btrfs",
        s(&["filesystem", "resize", &new_size.to_string(), mount_path]),
    )
}

/// `umount <mount_path>`.
fn umount(mount_path: &str) -> TaskSpec {
    TaskSpec::new("umount", s(&[mount_path]))
}

/// Unmounts its path on drop unless disarmed: the backstop that keeps the
/// btrfs temp mount from leaking when a sink error (client gone) aborts the
/// sequence between the recorded mount and umount steps.
struct MountGuard<'p> {
    path: &'p str,
    armed: bool,
}

impl Drop for MountGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::process::Command::new("umount").arg(self.path).output();
        }
    }
}

/// Runs the whole shrink as subtasks of `task`: probe → filesystem shrink →
/// partition resize. The first failed step ends the sequence (the partition is
/// only ever resized after the filesystem fit inside it, and never while the
/// btrfs temp mount is up). `Err` only on a sink failure (the client is gone).
pub fn shrink(task: &mut Task, disk: &BlockDev, number: u32, size_sectors: u64) -> io::Result<()> {
    let name = part_name(disk, number);
    let device = format!("/dev/{name}");

    // Probe fstype + mountpoint, refusing mounted/unshrinkable filesystems
    // before anything mutates.
    let mut sub = task.begin_subtask(format!("Probe {device}"));
    let plan = match cmd::capture_into(&mut sub, &lsblk(&device))? {
        Ok(json) => match parse_probe(&json) {
            Some(p) => plan_fs(p.fstype.as_deref(), p.mounted),
            None => Err("could not read its filesystem state".into()),
        },
        Err(msg) => Err(msg),
    };
    let plan = match plan {
        Ok(p) => {
            sub.complete(SubStatus::Success);
            p
        }
        Err(reason) => {
            sub.fail(format!("cannot shrink {device}: {reason}"));
            return Ok(());
        }
    };

    // Shrink the filesystem 1 MiB short of the new partition end for slack.
    let fs_bytes = size_sectors.saturating_mul(512).saturating_sub(1 << 20);
    match plan {
        FsPlan::Raw => task.skipped_subtask("Shrink filesystem (none present)"),
        FsPlan::Ext => {
            let checked = cmd::run(
                task,
                format!("Check filesystem on {device}"),
                &fsck(&device),
            )?;
            if checked != SubStatus::Success {
                return Ok(());
            }
            let spec = resize_ext(&device, fs_bytes / 512);
            if cmd::run(task, format!("Shrink filesystem on {device}"), &spec)?
                != SubStatus::Success
            {
                return Ok(());
            }
        }
        FsPlan::Btrfs => {
            let mp = format!("/run/greendotrdma/btrfs-resize-{name}");
            if cmd::run(task, format!("Mount {device}"), &btrfs_mount(&device, &mp))?
                != SubStatus::Success
            {
                return Ok(());
            }
            let mut guard = MountGuard {
                path: &mp,
                armed: true,
            };
            let spec = btrfs_resize(&mp, fs_bytes);
            let resized = cmd::run(task, format!("Shrink filesystem on {device}"), &spec)?
                == SubStatus::Success;
            // The recorded unmount runs whether the resize succeeded or not,
            // and is the hard gate: the partition is never resized while the
            // filesystem is still mounted.
            if cmd::run(task, format!("Unmount {device}"), &umount(&mp))? == SubStatus::Success {
                guard.armed = false;
            } else {
                return Ok(());
            }
            if !resized {
                return Ok(());
            }
        }
    }

    let spec = partition::partition_resize(disk, number, size_sectors);
    cmd::run(task, format!("Resize partition {number} on {disk}"), &spec)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::sata("sdb", 2, "sdb2")]
    #[case::nvme("nvme0n1", 2, "nvme0n1p2")]
    #[case::mmc("mmcblk0", 1, "mmcblk0p1")]
    fn part_name_follows_kernel_rule(#[case] disk: &str, #[case] n: u32, #[case] expected: &str) {
        assert_eq!(part_name(&BlockDev::new(disk).unwrap(), n), expected);
    }

    #[rstest]
    #[case::ext_idle(
        r#"{"blockdevices":[{"fstype":"ext4","mountpoint":null}]}"#,
        Some("ext4"),
        false
    )]
    #[case::btrfs_mounted(
        r#"{"blockdevices":[{"fstype":"btrfs","mountpoint":"/srv"}]}"#,
        Some("btrfs"),
        true
    )]
    #[case::raw(r#"{"blockdevices":[{"fstype":null,"mountpoint":null}]}"#, None, false)]
    fn parse_probe_reads_lsblk_json(
        #[case] json: &str,
        #[case] fstype: Option<&str>,
        #[case] mounted: bool,
    ) {
        let p = parse_probe(json).unwrap();
        assert_eq!((p.fstype.as_deref(), p.mounted), (fstype, mounted));
    }

    #[test]
    fn parse_probe_rejects_missing_device_and_garbage() {
        assert!(parse_probe(r#"{"blockdevices":[]}"#).is_none());
        assert!(parse_probe("").is_none());
        assert!(parse_probe("not json").is_none());
    }

    /// The enforced shrinkability table (the web mirrors it as a UI gate).
    #[rstest]
    #[case::raw(None, false, Ok(()))]
    #[case::ext4(Some("ext4"), false, Ok(()))]
    #[case::btrfs(Some("btrfs"), false, Ok(()))]
    #[case::ext_mounted(Some("ext4"), true, Err("mounted — unmount it first"))]
    #[case::btrfs_mounted(Some("btrfs"), true, Err("mounted — unmount it first"))]
    #[case::xfs(Some("xfs"), false, Err("XFS cannot be shrunk"))]
    #[case::zfs(Some("zfs_member"), false, Err("part of a ZFS pool"))]
    #[case::lvm(Some("LVM2_member"), false, Err("part of an LVM volume group"))]
    #[case::other(Some("reiserfs"), false, Err("this filesystem cannot be shrunk"))]
    fn plan_fs_enforces_shrinkability(
        #[case] fstype: Option<&str>,
        #[case] mounted: bool,
        #[case] expected: Result<(), &str>,
    ) {
        match (plan_fs(fstype, mounted), expected) {
            (Ok(_), Ok(())) => {}
            (Err(got), Err(want)) => assert_eq!(got, want),
            (got, want) => panic!("{fstype:?}/{mounted}: got {:?}, want {want:?}", got.err()),
        }
    }

    #[test]
    fn fs_step_commands() {
        assert_eq!(
            (fsck("/dev/sdb2").command.as_str(), fsck("/dev/sdb2").args),
            ("e2fsck", s(&["-f", "-y", "/dev/sdb2"]))
        );
        // resize2fs takes the size as 512-byte sectors via the `s` suffix.
        assert_eq!(
            resize_ext("/dev/sdb2", 2097152).args,
            s(&["/dev/sdb2", "2097152s"])
        );
        let mp = "/run/greendotrdma/btrfs-resize-sdb2";
        assert_eq!(
            btrfs_mount("/dev/sdb2", mp).args,
            s(&["--mkdir", "-t", "btrfs", "/dev/sdb2", mp])
        );
        assert_eq!(
            btrfs_resize(mp, 1 << 30).args,
            s(&["filesystem", "resize", "1073741824", mp])
        );
        assert_eq!(umount(mp).args, s(&[mp]));
        assert_eq!(
            lsblk("/dev/sdb2").args,
            s(&["-J", "-o", "FSTYPE,MOUNTPOINT", "/dev/sdb2"])
        );
    }
}
