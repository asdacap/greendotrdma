//! Applies the desired NFS state and reads the actual one. greendot owns a
//! single exports file (`/etc/exports.d/greendot.exports`) and applies changes
//! *surgically* with `exportfs -o`/`-u` per managed `client:path` pair — never a
//! global `exportfs -ra`, which would re-sync `/etc/exports` and ZFS's own
//! `/etc/exports.d/zfs.exports` and prune foreign exports. The file is written
//! purely for boot persistence (nfsd runs `exportfs -r` on start). The RDMA
//! listener is asserted by writing `rdma <port>` to `/proc/fs/nfsd/portlist`
//! (idempotent, root-only), mirroring how `nvmet::apply` writes configfs.

use crate::cmd::{TaskSpec, run_into};
use greendot_proto::{NFS_MANAGED_SENTINEL, NFS_PORTLIST_SENTINEL, NfsDesired, SubStatus, SubTask};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

/// Our exports file. Only files ending in `.exports` are read by `exportfs`, and
/// this one is ours alone — foreign exports live in `/etc/exports` or other
/// `*.exports` files and are never touched.
pub const NFS_EXPORTS_FILE: &str = "/etc/exports.d/greendot.exports";
/// The kernel's nfsd listener-control pseudofile (root-only).
pub const NFSD_PORTLIST: &str = "/proc/fs/nfsd/portlist";

/// Renders the exports file: one line per export, `<path> <client>(<opts>)…`.
/// Every export uses `sync,no_subtree_check` and a stable `fsid`; `rw`/`ro` is
/// per client. Exports with no clients are skipped (an export needs a client).
pub fn render_exports(desired: &NfsDesired) -> String {
    let mut out =
        String::from("# Managed by greendotrdma — do not edit; changes are overwritten.\n");
    for spec in &desired.exports {
        if spec.clients.is_empty() {
            continue;
        }
        out.push_str(spec.path.as_str());
        for c in &spec.clients {
            out.push_str(&format!(" {}({})", c.client, opts(c.rw, spec.fsid)));
        }
        out.push('\n');
    }
    out
}

/// The `exportfs`/exports(5) option string for one client.
fn opts(rw: bool, fsid: u32) -> String {
    format!(
        "{},sync,no_subtree_check,fsid={fsid}",
        if rw { "rw" } else { "ro" }
    )
}

/// The `(client, path)` pairs the desired state wants exported.
fn desired_pairs(desired: &NfsDesired) -> BTreeSet<(String, String)> {
    desired
        .exports
        .iter()
        .flat_map(|s| {
            s.clients
                .iter()
                .map(move |c| (c.client.to_string(), s.path.to_string()))
        })
        .collect()
}

/// Parses our own exports file back into `(client, path)` pairs, so the next
/// apply can `exportfs -u` the ones no longer desired. Tolerant: comment/blank
/// lines and malformed entries are skipped.
fn read_managed(path: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(path) = tokens.next() else { continue };
        for tok in tokens {
            // `client(opts)` → client is the part before `(`.
            let client = tok.split('(').next().unwrap_or(tok);
            if !client.is_empty() {
                pairs.push((client.to_owned(), path.to_owned()));
            }
        }
    }
    pairs
}

/// Atomically writes `desired` to the exports file (temp + rename). The temp
/// name does not end in `.exports`, so `exportfs` never reads a half-written file.
fn write_exports_file(path: &Path, desired: &NfsDesired) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, render_exports(desired))?;
    std::fs::rename(&tmp, path)
}

/// Ensures nfsd is listening for RDMA on `port` by writing `rdma <port>` to the
/// portlist (idempotent — skipped when already present). Returns whether it
/// added the listener. For the `/proc` pseudofile a write registers a listener;
/// the append also keeps a real file's other lines intact for tests.
fn ensure_portlist_rdma(portlist: &Path, port: u16) -> io::Result<bool> {
    let current = std::fs::read_to_string(portlist).unwrap_or_default();
    let line = format!("rdma {port}");
    if current.lines().any(|l| l.trim() == line) {
        return Ok(false);
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(portlist)?;
    writeln!(f, "{line}")?;
    Ok(true)
}

fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

/// Applies `desired` into the caller-opened subtask: each `exportfs`/`systemctl`
/// command streams as a `$ …` echo + output, and their statuses fold into the
/// returned subtask status. `Err` only when the sink fails; operation failures
/// come back as `Failed` (which the web turns into the export's `last_error` and
/// a red dot).
pub fn apply(
    desired: &NfsDesired,
    exports_file: &Path,
    portlist: &Path,
    sub: &mut SubTask,
) -> io::Result<SubStatus> {
    let previous = read_managed(exports_file);
    let want = desired_pairs(desired);
    let mut acc: Option<SubStatus> = None;

    // 1. Persist our file (or remove it when nothing is desired).
    if desired.exports.is_empty() {
        if let Err(e) = std::fs::remove_file(exports_file)
            && e.kind() != io::ErrorKind::NotFound
        {
            let msg = format!("removing {}: {e}", exports_file.display());
            writeln!(sub.stderr(), "{msg}")?;
            sub.set_result(1, Some(msg));
            return Ok(SubStatus::Failed);
        }
    } else if let Err(e) = write_exports_file(exports_file, desired) {
        let msg = format!("writing {}: {e}", exports_file.display());
        writeln!(sub.stderr(), "{msg}")?;
        sub.set_result(1, Some(msg));
        return Ok(SubStatus::Failed);
    }

    // 2. Unexport our previously-managed pairs that are no longer desired.
    for (client, path) in &previous {
        if !want.contains(&(client.clone(), path.clone())) {
            let spec = TaskSpec::new("exportfs", s(&["-u", &format!("{client}:{path}")]));
            acc = Some(SubStatus::fold(acc, run_into(sub, &spec)?));
        }
    }

    if desired.exports.is_empty() {
        writeln!(
            sub.stdout(),
            "no NFS exports desired; removed greendot exports"
        )?;
        return Ok(acc.unwrap_or(SubStatus::Success));
    }

    // 3. Ensure nfsd is up (so /proc/fs/nfsd exists and exportfs can register).
    // `start`, not `enable --now`: the Ubuntu nfs-kernel-server package already
    // enables the unit at install, and `enable` fails on a read-only /etc.
    let spec = TaskSpec::new("systemctl", s(&["start", "nfs-server"]));
    acc = Some(SubStatus::fold(acc, run_into(sub, &spec)?));

    // 4. Assert the RDMA listener (the "must be through RDMA" half).
    match ensure_portlist_rdma(portlist, desired.rdma_port) {
        Ok(added) => writeln!(
            sub.stdout(),
            "NFSoRDMA listener on port {} {}",
            desired.rdma_port,
            if added { "enabled" } else { "already active" }
        )?,
        Err(e) => {
            let msg = format!(
                "enabling NFSoRDMA listener on port {}: {e}",
                desired.rdma_port
            );
            writeln!(sub.stderr(), "{msg}")?;
            sub.set_result(1, Some(msg));
            acc = Some(SubStatus::fold(acc, SubStatus::Failed));
        }
    }

    // 5. Add / update each desired export, one client:path at a time.
    for exp in &desired.exports {
        for c in &exp.clients {
            let spec = TaskSpec::new(
                "exportfs",
                s(&[
                    "-o",
                    &opts(c.rw, exp.fsid),
                    &format!("{}:{}", c.client, exp.path),
                ]),
            );
            acc = Some(SubStatus::fold(acc, run_into(sub, &spec)?));
        }
    }

    Ok(acc.unwrap_or(SubStatus::Success))
}

/// Reads NFS actual state (a privileged read): the live export table
/// (`exportfs -s`, exports(5) syntax), the nfsd portlist, and greendot's own
/// managed exports file (what it last applied — for drift detection), separated
/// by the report sentinels. Missing tools/files read as empty so the dashboard
/// simply shows nothing exported. Parsed back by `actual::nfs::from_report`.
pub fn report(portlist: &Path, exports_file: &Path) -> String {
    let exports = Command::new("exportfs")
        .arg("-s")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let portlist = std::fs::read_to_string(portlist).unwrap_or_default();
    let managed = std::fs::read_to_string(exports_file).unwrap_or_default();
    format!("{exports}\n{NFS_PORTLIST_SENTINEL}\n{portlist}\n{NFS_MANAGED_SENTINEL}\n{managed}")
}

/// Streams [`report`] into the subtask, for the socket `NfsReport` request.
pub fn report_into(
    portlist: &Path,
    exports_file: &Path,
    sub: &mut SubTask,
) -> io::Result<SubStatus> {
    write!(sub.stdout(), "{}", report(portlist, exports_file))?;
    Ok(SubStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Collector;
    use greendot_proto::{NfsClient, NfsClientSpec, NfsExportPath, NfsExportSpec, Task};

    fn export(path: &str, fsid: u32, clients: &[(&str, bool)]) -> NfsExportSpec {
        NfsExportSpec {
            path: NfsExportPath::new(path).unwrap(),
            fsid,
            clients: clients
                .iter()
                .map(|(c, rw)| NfsClientSpec {
                    client: NfsClient::new(*c).unwrap(),
                    rw: *rw,
                })
                .collect(),
        }
    }

    /// Applies `desired` through a one-subtask task and returns the folded
    /// subtask status.
    fn apply_status(desired: &NfsDesired, file: &Path, pl: &Path) -> SubStatus {
        let mut c = Collector::default();
        let mut task = Task::new(&mut c);
        let mut sub = task.begin_subtask("Apply NFS configuration");
        let status = apply(desired, file, pl, &mut sub).unwrap();
        sub.complete(status);
        task.complete().unwrap();
        status
    }

    #[test]
    fn renders_and_reparses_managed_exports() {
        let desired = NfsDesired {
            rdma_port: 20049,
            exports: vec![
                export(
                    "/tank/share",
                    0x6700_0001,
                    &[("192.168.101.0/24", true), ("*", false)],
                ),
                export("/srv/ro", 0x6700_0002, &[("10.0.0.5", false)]),
                export("/empty", 0x6700_0003, &[]), // skipped — no clients
            ],
        };
        let text = render_exports(&desired);
        assert!(text.starts_with("# Managed by greendotrdma"));
        assert!(text.contains("/tank/share 192.168.101.0/24(rw,sync,no_subtree_check,fsid=1728053249) *(ro,sync,no_subtree_check,fsid=1728053249)\n"));
        assert!(text.contains("/srv/ro 10.0.0.5(ro,sync,no_subtree_check,fsid=1728053250)\n"));
        assert!(!text.contains("/empty"), "client-less export is skipped");

        // Round-trip: parsing our own file recovers every (client, path) pair.
        let dir = std::env::temp_dir().join(format!("gd-nfs-render{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("greendot.exports");
        std::fs::write(&file, &text).unwrap();
        let pairs = read_managed(&file);
        assert_eq!(
            pairs,
            vec![
                ("192.168.101.0/24".to_owned(), "/tank/share".to_owned()),
                ("*".to_owned(), "/tank/share".to_owned()),
                ("10.0.0.5".to_owned(), "/srv/ro".to_owned()),
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_portlist_rdma_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("gd-nfs-pl{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pl = dir.join("portlist");
        std::fs::write(&pl, "tcp 2049\nudp 2049\n").unwrap();
        assert!(
            ensure_portlist_rdma(&pl, 20049).unwrap(),
            "added first time"
        );
        let after = std::fs::read_to_string(&pl).unwrap();
        assert!(
            after.contains("tcp 2049") && after.contains("rdma 20049"),
            "{after}"
        );
        assert!(
            !ensure_portlist_rdma(&pl, 20049).unwrap(),
            "second call is a no-op"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_writes_file_and_portlist_then_teardown_removes_file() {
        let dir = std::env::temp_dir().join(format!("gd-nfs-apply{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("greendot.exports");
        let pl = dir.join("portlist");
        std::fs::write(&pl, "tcp 2049\n").unwrap();

        let desired = NfsDesired {
            rdma_port: 20049,
            exports: vec![export(
                "/tank/share",
                0x6700_0001,
                &[("192.168.101.0/24", true)],
            )],
        };
        // systemctl/exportfs are absent in CI → overall status is Failed, but the
        // file + portlist side effects (which don't depend on them) still happen.
        assert_eq!(
            apply_status(&desired, &file, &pl),
            SubStatus::Failed,
            "missing exportfs/systemctl"
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            render_exports(&desired)
        );
        assert!(
            std::fs::read_to_string(&pl).unwrap().contains("rdma 20049"),
            "RDMA listener asserted"
        );

        // Teardown: empty desired removes our file.
        let empty = NfsDesired {
            rdma_port: 20049,
            exports: vec![],
        };
        apply_status(&empty, &file, &pl);
        assert!(!file.exists(), "teardown removes the exports file");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
