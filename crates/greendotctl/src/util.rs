//! Tiny helpers shared by the command builders and sysfs/configfs readers.

use greendot_proto::BlockDev;
use std::path::Path;

/// Owned argv from string literals.
pub(crate) fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

/// `/dev/<device>`.
pub(crate) fn dev(device: &BlockDev) -> String {
    format!("/dev/{device}")
}

/// File contents trimmed; empty when missing or unreadable.
pub(crate) fn read_trim(path: &Path) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// A trimmed file value, `None` if missing or empty.
pub(crate) fn read_trimmed(path: &Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}
