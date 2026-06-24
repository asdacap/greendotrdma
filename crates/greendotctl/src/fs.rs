//! Filesystem shrink steps as CLI tasks. The web side sequences these (the
//! filesystem is always resized before the partition); each one is a single
//! command.

use crate::cmd::TaskSpec;
use greendot_proto::{DevicePath, MountPath};

fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

/// `e2fsck -f -y <device>` — resize2fs refuses to shrink an unchecked fs.
pub fn fsck(device: &DevicePath) -> TaskSpec {
    TaskSpec::new("e2fsck", s(&["-f", "-y", device.as_str()]))
}

/// `resize2fs <device> <N>s` — the `s` suffix is 512-byte sectors, sidestepping
/// the filesystem-block-size unit footgun.
pub fn resize_ext(device: &DevicePath, new_size_sectors: u64) -> TaskSpec {
    TaskSpec::new(
        "resize2fs",
        s(&[device.as_str(), &format!("{new_size_sectors}s")]),
    )
}

/// `mount --mkdir -t btrfs <device> <mount_path>` — btrfs resizes only while
/// mounted, so the helper temp-mounts it at its own fixed path (whose parent
/// `/run/greendotrdma` is the service's RuntimeDirectory).
pub fn btrfs_mount(device: &DevicePath, mount_path: &MountPath) -> TaskSpec {
    TaskSpec::new(
        "mount",
        s(&[
            "--mkdir",
            "-t",
            "btrfs",
            device.as_str(),
            mount_path.as_str(),
        ]),
    )
}

/// `btrfs filesystem resize <bytes> <mount_path>`.
pub fn btrfs_resize(mount_path: &MountPath, new_size: u64) -> TaskSpec {
    TaskSpec::new(
        "btrfs",
        s(&[
            "filesystem",
            "resize",
            &new_size.to_string(),
            mount_path.as_str(),
        ]),
    )
}

/// `umount <mount_path>`.
pub fn umount(mount_path: &MountPath) -> TaskSpec {
    TaskSpec::new("umount", s(&[mount_path.as_str()]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DevicePath {
        DevicePath::new("/dev/sdb2").unwrap()
    }

    fn mp() -> MountPath {
        MountPath::new("/run/greendotrdma/btrfs-resize-sdb2").unwrap()
    }

    #[test]
    fn fs_step_commands() {
        assert_eq!(
            (fsck(&dev()).command.as_str(), fsck(&dev()).args),
            ("e2fsck", s(&["-f", "-y", "/dev/sdb2"]))
        );
        // resize2fs takes the size as 512-byte sectors via the `s` suffix.
        assert_eq!(
            resize_ext(&dev(), 2097152).args,
            s(&["/dev/sdb2", "2097152s"])
        );
        assert_eq!(
            btrfs_mount(&dev(), &mp()).args,
            s(&[
                "--mkdir",
                "-t",
                "btrfs",
                "/dev/sdb2",
                "/run/greendotrdma/btrfs-resize-sdb2"
            ])
        );
        assert_eq!(
            btrfs_resize(&mp(), 1 << 30).args,
            s(&[
                "filesystem",
                "resize",
                "1073741824",
                "/run/greendotrdma/btrfs-resize-sdb2"
            ])
        );
        assert_eq!(
            umount(&mp()).args,
            s(&["/run/greendotrdma/btrfs-resize-sdb2"])
        );
    }
}
