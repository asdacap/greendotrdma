//! Read-only system introspection used by reconciliation. Everything here runs
//! unprivileged from sysfs/configfs; the one privileged read (the NFS report)
//! is fetched by the caller who holds root — greendotctl in-process, or the
//! web via `Request::NfsReport` — and only *parsed* here.

pub mod lio;
pub mod nic;
pub mod nvmet;
pub mod rdma;

use std::path::Path;

/// A configfs attribute trimmed; empty when missing or unreadable.
pub(crate) fn read_attr(dir: &Path, attr: &str) -> String {
    std::fs::read_to_string(dir.join(attr))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// Sorted entry names of a directory; empty when unreadable.
pub(crate) fn dir_names(dir: &Path) -> Vec<String> {
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
