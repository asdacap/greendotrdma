//! Actual NFS state. Unlike ZFS reads, the export table (`exportfs -s`) and the
//! nfsd portlist (`/proc/fs/nfsd/portlist`, root-only) cannot be read by the
//! unprivileged web service, so they come through the helper's `NfsReport`
//! (the `LvmReport` pattern). The parsers here are pure and tested.

use crate::helper_client::HelperClient;
use greendot_proto::{NFS_MANAGED_SENTINEL, NFS_PORTLIST_SENTINEL, Request};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActualNfs {
    /// The live export table (`exportfs -s`) — includes foreign exports.
    pub exports: Vec<NfsExportEntry>,
    /// `Some(port)` when nfsd has an RDMA listener (an `rdma <port>` portlist
    /// line); `None` when serving TCP only.
    pub rdma_port: Option<u16>,
    /// What greendot last applied, parsed from its own exports file:
    /// `(path, client, rw)` — the drift baseline (rw included so an option
    /// change is detected, not just an added/removed client).
    pub managed: BTreeSet<(String, String, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsExportEntry {
    pub path: String,
    pub clients: Vec<String>,
}

impl ActualNfs {
    /// Whether `path` is in the live export table.
    pub fn exported(&self, path: &str) -> bool {
        self.exports.iter().any(|e| e.path == path)
    }
}

/// Parses `exportfs -s` output (exports(5) syntax): each line is
/// `<path> <client>(<opts>) [<client2>(<opts2>) …]`. Clients of the same path
/// (which `exportfs -s` may split across lines) are merged, preserving order.
pub fn parse_exportfs_s(out: &str) -> Vec<NfsExportEntry> {
    let mut entries: Vec<NfsExportEntry> = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(path) = tokens.next() else { continue };
        let clients: Vec<String> = tokens
            .map(|t| t.split('(').next().unwrap_or(t).to_owned())
            .filter(|c| !c.is_empty())
            .collect();
        match entries.iter_mut().find(|e| e.path == path) {
            Some(e) => e.clients.extend(clients),
            None => entries.push(NfsExportEntry {
                path: path.to_owned(),
                clients,
            }),
        }
    }
    entries
}

/// Parses greendot's own exports file into `(path, client, rw)` specs (rw from
/// the `rw` option in the client's parenthesized option group), so drift
/// detection compares the full access intent, not just which clients exist.
pub fn parse_managed_specs(out: &str) -> BTreeSet<(String, String, bool)> {
    let mut set = BTreeSet::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(path) = tokens.next() else { continue };
        for tok in tokens {
            let (client, opts) = match tok.split_once('(') {
                Some((c, rest)) => (c, rest.trim_end_matches(')')),
                None => (tok, ""),
            };
            if client.is_empty() {
                continue;
            }
            let rw = opts.split(',').any(|o| o == "rw");
            set.insert((path.to_owned(), client.to_owned(), rw));
        }
    }
    set
}

/// Finds the RDMA listener port in `/proc/fs/nfsd/portlist` (a line like
/// `rdma 20049`), if any.
pub fn parse_portlist(out: &str) -> Option<u16> {
    out.lines().find_map(|l| {
        let mut parts = l.split_whitespace();
        (parts.next() == Some("rdma"))
            .then(|| parts.next())
            .flatten()
            .and_then(|p| p.parse().ok())
    })
}

/// Splits an `NfsReport` payload into its three sections — live `exportfs -s`,
/// the portlist, then greendot's managed file — and parses each. The split is
/// on *full-line* sentinel matches, so a path/client that happens to contain a
/// sentinel as a substring can't corrupt the boundaries.
pub fn from_report(stdout: &str) -> ActualNfs {
    let mut sections = [String::new(), String::new(), String::new()];
    let mut i = 0usize;
    for line in stdout.lines() {
        if line == NFS_PORTLIST_SENTINEL {
            i = 1;
        } else if line == NFS_MANAGED_SENTINEL {
            i = 2;
        } else {
            sections[i].push_str(line);
            sections[i].push('\n');
        }
    }
    ActualNfs {
        exports: parse_exportfs_s(&sections[0]),
        rdma_port: parse_portlist(&sections[1]),
        managed: parse_managed_specs(&sections[2]),
    }
}

/// Reads NFS actual state through the helper. A helper/transport failure or a
/// missing `exportfs` simply yields an empty state (nothing exported, no RDMA),
/// which the dots render as red — the same graceful degradation as elsewhere.
pub async fn read(helper: &HelperClient) -> ActualNfs {
    let out = helper.collect(Request::NfsReport).await;
    from_report(&out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exportfs_portlist_managed_and_full_report() {
        let exportfs = "/tank/share\t192.168.101.0/24(rw,sync,no_subtree_check,fsid=1)\n\
                        /tank/share\t10.0.0.9(ro,sync,no_subtree_check,fsid=1)\n\
                        /srv/foreign\t*(ro,sync)\n";
        let entries = parse_exportfs_s(exportfs);
        assert_eq!(entries.len(), 2, "two distinct paths");
        assert_eq!(entries[0].path, "/tank/share");
        assert_eq!(
            entries[0].clients,
            ["192.168.101.0/24", "10.0.0.9"],
            "merged"
        );
        assert_eq!(entries[1].path, "/srv/foreign");

        assert_eq!(
            parse_portlist("tcp 2049\nudp 2049\nrdma 20049\n"),
            Some(20049)
        );
        assert_eq!(parse_portlist("tcp 2049\nudp 2049\n"), None);

        // The managed parser keeps the rw/ro flag per (path, client).
        let managed = "/tank/share 192.168.101.0/24(rw,sync,no_subtree_check,fsid=1) 10.0.0.9(ro,sync,no_subtree_check,fsid=1)\n";
        assert_eq!(
            parse_managed_specs(managed),
            [
                (
                    "/tank/share".to_owned(),
                    "192.168.101.0/24".to_owned(),
                    true
                ),
                ("/tank/share".to_owned(), "10.0.0.9".to_owned(), false),
            ]
            .into_iter()
            .collect()
        );

        // Full report: live exports + portlist + greendot's managed file.
        let report = format!(
            "{exportfs}\n{NFS_PORTLIST_SENTINEL}\ntcp 2049\nrdma 20049\n{NFS_MANAGED_SENTINEL}\n/tank/share 192.168.101.0/24(rw,sync,no_subtree_check,fsid=1)\n"
        );
        let actual = from_report(&report);
        assert!(actual.exported("/tank/share") && actual.exported("/srv/foreign"));
        assert!(!actual.exported("/nope"));
        assert_eq!(actual.rdma_port, Some(20049));
        assert_eq!(
            actual.managed,
            [(
                "/tank/share".to_owned(),
                "192.168.101.0/24".to_owned(),
                true
            )]
            .into_iter()
            .collect()
        );

        // A path containing a sentinel-as-substring must NOT split the sections
        // (full-line match only): the live-exports section stays intact.
        let crafted = format!(
            "/x--greendot-portlist--y\t*(ro,sync)\n{NFS_PORTLIST_SENTINEL}\nrdma 20049\n{NFS_MANAGED_SENTINEL}\n"
        );
        let a = from_report(&crafted);
        assert!(
            a.exported("/x--greendot-portlist--y"),
            "substring must not split"
        );
        assert_eq!(a.rdma_port, Some(20049));

        // No sentinels (e.g. exportfs missing) → nothing exported, no rdma.
        let empty = from_report("");
        assert!(empty.exports.is_empty() && empty.rdma_port.is_none() && empty.managed.is_empty());
    }
}
