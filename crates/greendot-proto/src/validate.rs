//! Validators for the string newtypes. Conservative by design: these strings
//! become configfs path components and command arguments in a root process.

/// One name component: starts alphanumeric, then alphanumerics plus `_ . : -`.
fn component(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
}

pub(crate) fn dataset_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s.split('/').all(component)
}

pub(crate) fn snap_name(s: &str) -> bool {
    s.len() <= 255 && component(s)
}

/// LVM volume-group / logical-volume name. LVM allows `[A-Za-z0-9+_.-]`; we
/// additionally forbid a leading `-` (argv flag confusion) and the `.`/`..`
/// entries, and there is no `/` so a name can't introduce a path component.
pub(crate) fn lvm_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 127
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "+_.-".contains(c))
}

pub(crate) fn nqn(s: &str) -> bool {
    s.len() <= 223
        && s.strip_prefix("nqn.").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
        })
}

pub(crate) fn iqn(s: &str) -> bool {
    s.len() <= 223
        && s.strip_prefix("iqn.").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".:-".contains(c))
        })
}

pub(crate) fn block_dev(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub(crate) fn device_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("/dev/") else {
        return false;
    };
    if let Some(dataset) = rest.strip_prefix("zvol/") {
        // ZFS zvol: /dev/zvol/<dataset>
        dataset_name(dataset)
    } else if let Some((vg, lv)) = rest.split_once('/') {
        // LVM logical volume: /dev/<vg>/<lv> (the udev symlink). Exactly two
        // components — a third `/` lands in `lv` and fails `lvm_name`.
        lvm_name(vg) && lvm_name(lv)
    } else {
        // Bare block device: /dev/<dev>
        block_dev(rest)
    }
}

/// vdev keywords and other names `zpool` reserves; a pool may not be named any
/// of these (they would be ambiguous with the `zpool create` grammar).
pub(crate) const RESERVED_VDEV_KEYWORDS: &[&str] = &[
    "mirror",
    "raidz",
    "raidz1",
    "raidz2",
    "raidz3",
    "draid",
    "draid1",
    "draid2",
    "draid3",
    "spare",
    "log",
    "logs",
    "cache",
    "dedup",
    "special",
    "replacing",
];

pub(crate) fn pool_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
        && !RESERVED_VDEV_KEYWORDS
            .iter()
            .any(|k| k.eq_ignore_ascii_case(s))
}

/// The helper's private btrfs temp-mount path: exactly
/// `/run/greendotrdma/btrfs-resize-<block_dev>`, so no caller can point a root
/// mount/umount at an arbitrary location.
pub(crate) fn mount_path(s: &str) -> bool {
    s.strip_prefix("/run/greendotrdma/btrfs-resize-")
        .is_some_and(block_dev)
}

pub(crate) fn netdev(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

/// PCI device address `DOMAIN:BUS:DEV.FUNC`, e.g. `0000:00:10.0`. Lowercase
/// hex, fixed width, conventional function 0-7 (VFs never exceed it). Becomes
/// the `pci/<addr>` handle in a root `devlink` command, so it is pinned exactly.
pub(crate) fn pci_address(s: &str) -> bool {
    let Some((bdf, func)) = s.split_once('.') else {
        return false;
    };
    let mut parts = bdf.split(':');
    let (Some(domain), Some(bus), Some(dev), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let lower_hex = |s: &str, len: usize| {
        s.len() == len
            && s.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    };
    lower_hex(domain, 4)
        && lower_hex(bus, 2)
        && lower_hex(dev, 2)
        && func.len() == 1
        && func.chars().all(|c| ('0'..='7').contains(&c))
}

pub(crate) fn backstore_name(s: &str) -> bool {
    s.len() <= 63 && component(s)
}

pub(crate) fn part_label(s: &str) -> bool {
    (1..=36).contains(&s.len()) && component(s)
}

pub(crate) fn export_name(s: &str) -> bool {
    // Lowercase so the same name is valid in both NQNs and IQNs.
    s.len() <= 64
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-.".contains(c))
}

pub(crate) fn package_name(s: &str) -> bool {
    // Debian package name: lowercase alnum start, then alnum plus `+ - .`.
    (2..=100).contains(&s.len())
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
}

pub(crate) fn username(s: &str) -> bool {
    s.len() <= 32
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}
