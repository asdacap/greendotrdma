//! Parsers for `zpool list -Hp` / `zfs list -Hp` output and the async
//! executors that produce it. `-H` = no headers, tab-separated; `-p` =
//! exact numbers.

use anyhow::{Context, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub name: String,
    pub size: u64,
    pub alloc: u64,
    pub free: u64,
    pub frag_percent: Option<u8>,
    pub health: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsKind {
    Filesystem,
    Volume,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub name: String,
    pub kind: DsKind,
    pub used: u64,
    pub avail: u64,
    /// Only for volumes.
    pub volsize: Option<u64>,
    /// Filesystem mountpoint: an absolute path, or `none`/`legacy`/`-`.
    pub mountpoint: String,
    /// Whether the dataset is currently mounted (`-`/`no` ⇒ false).
    pub mounted: bool,
}

// Consumed by the snapshots page (Phase 7); parser is already exercised by tests.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Full name, `dataset@snap`.
    pub name: String,
    pub used: u64,
    /// Unix timestamp.
    pub creation: i64,
}

fn fields(line: &str, n: usize) -> Result<Vec<&str>> {
    let f: Vec<_> = line.split('\t').collect();
    anyhow::ensure!(
        f.len() == n,
        "expected {n} tab-separated fields, got {line:?}"
    );
    Ok(f)
}

fn num(field: &str) -> Result<u64> {
    field
        .parse()
        .with_context(|| format!("expected a number, got {field:?}"))
}

/// `-` means "not applicable" in zfs/zpool parseable output.
fn opt_num<T: std::str::FromStr>(field: &str) -> Result<Option<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match field {
        "-" => Ok(None),
        n => Ok(Some(n.parse().with_context(|| {
            format!("expected a number or -, got {field:?}")
        })?)),
    }
}

/// `zpool list -Hp -o name,size,alloc,free,frag,health`
pub fn parse_zpool_list(out: &str) -> Result<Vec<Pool>> {
    out.lines()
        .map(|line| {
            let f = fields(line, 6)?;
            Ok(Pool {
                name: f[0].into(),
                size: num(f[1])?,
                alloc: num(f[2])?,
                free: num(f[3])?,
                frag_percent: opt_num(f[4])?,
                health: f[5].into(),
            })
        })
        .collect()
}

/// `zfs list -Hp -t filesystem,volume -o name,type,used,avail,volsize,mountpoint,mounted`
pub fn parse_zfs_list(out: &str) -> Result<Vec<Dataset>> {
    out.lines()
        .map(|line| {
            let f = fields(line, 7)?;
            let kind = match f[1] {
                "filesystem" => DsKind::Filesystem,
                "volume" => DsKind::Volume,
                other => anyhow::bail!("unexpected dataset type {other:?}"),
            };
            Ok(Dataset {
                name: f[0].into(),
                kind,
                used: num(f[2])?,
                avail: num(f[3])?,
                volsize: opt_num(f[4])?,
                mountpoint: f[5].into(),
                // `mounted` is yes/no for filesystems, `-` for volumes.
                mounted: f[6] == "yes",
            })
        })
        .collect()
}

/// `zfs list -Hp -t snapshot -o name,used,creation`
#[allow(dead_code)]
pub fn parse_snapshot_list(out: &str) -> Result<Vec<Snapshot>> {
    out.lines()
        .map(|line| {
            let f = fields(line, 3)?;
            Ok(Snapshot {
                name: f[0].into(),
                used: num(f[1])?,
                creation: f[2].parse()?,
            })
        })
        .collect()
}

/// Which allocation class a pool member belongs to, from the flush-left
/// section labels of `zpool list -v` (`logs`, `cache`, `spare`, `special`,
/// `dedup`; rows before any label are ordinary data vdevs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberClass {
    Data,
    Log,
    Cache,
    Spare,
    Special,
    Dedup,
}

impl MemberClass {
    fn from_label(s: &str) -> Option<Self> {
        Some(match s {
            "logs" => MemberClass::Log,
            "cache" => MemberClass::Cache,
            "spare" => MemberClass::Spare,
            "special" => MemberClass::Special,
            "dedup" => MemberClass::Dedup,
            _ => return None,
        })
    }
}

/// One row of a pool's vdev tree: a top-level vdev (`parent == None`) or a
/// leaf inside a container (`parent == Some("mirror-0")`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMember {
    pub pool: String,
    pub class: MemberClass,
    /// `/dev/...` path (leaf), vdev name like `mirror-0`, or a bare GUID for
    /// a missing device.
    pub name: String,
    /// A device (or missing-device GUID) rather than a vdev container.
    pub is_leaf: bool,
    /// The containing vdev's name for leaves inside a mirror/raidz.
    pub parent: Option<String>,
    pub size: Option<u64>,
    pub alloc: Option<u64>,
    pub health: Option<String>,
}

/// A named vdev container (`mirror-0`, `raidz1-0`, …) as opposed to a leaf.
/// Reuses the `VdevTarget` grammar: valid non-path targets are containers.
fn is_container(name: &str) -> bool {
    !name.starts_with('/') && greendot_proto::VdevTarget::new(name).is_ok()
}

/// The pool vdev tree from `zpool list -vHPp`. Scripted output carries no
/// indentation (every member row is one `\t` + 6 tab-separated fields), so
/// structure is recovered from what zpool prints per row kind:
/// - pool rows are flush-left; so are the class labels (`logs`, `cache`, …,
///   space-padded columns) — those words are reserved pool names, so the
///   first token distinguishes them;
/// - `alloc`/`free` print `-` for anything that is not a top-level vdev, so
///   a leaf with `alloc == -` after a container row is that container's
///   child, while a top-level (stripe) leaf carries real numbers.
pub fn parse_pool_vdevs(out: &str) -> Result<Vec<PoolMember>> {
    let mut members = Vec::new();
    let mut pool: Option<String> = None;
    let mut class = MemberClass::Data;
    let mut container: Option<String> = None;
    for line in out.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            let first = line.split_whitespace().next().unwrap_or_default();
            if let Some(c) = MemberClass::from_label(first) {
                class = c;
            } else {
                pool = Some(first.to_string());
                class = MemberClass::Data;
            }
            container = None;
            continue;
        }
        let f = fields(line.trim_start_matches([' ', '\t']), 6)?;
        let pool = pool
            .clone()
            .with_context(|| format!("member row before any pool: {line:?}"))?;
        let (name, alloc) = (f[0], opt_num::<u64>(f[2])?);
        // `-` in alloc marks a non-top-level row (a child of the last
        // container); real numbers mark a top-level vdev or leaf.
        let parent = if alloc.is_some() {
            None
        } else {
            container.clone()
        };
        if is_container(name) {
            container = Some(name.to_string());
        } else if alloc.is_some() {
            container = None;
        }
        members.push(PoolMember {
            pool,
            class,
            name: name.to_string(),
            is_leaf: !is_container(name),
            parent,
            size: opt_num(f[1])?,
            alloc,
            health: match f[5] {
                "-" => None,
                h => Some(h.to_string()),
            },
        });
    }
    Ok(members)
}

/// Device path → pool name: the leaves of [`parse_pool_vdevs`] (a parse
/// error degrades to the empty map, matching the old lenient behaviour).
///
/// Keys are the real `/dev/<name>` paths [`ZPOOL_LIST_VDEVS`] resolves with
/// `-L`, so they match the lsblk rows verbatim. Only *imported* pools appear:
/// a `zfs_member` device absent from this map carries a label no live pool
/// claims (a stale label, or an exported pool).
pub fn parse_pool_members(out: &str) -> HashMap<String, String> {
    parse_pool_vdevs(out)
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.is_leaf && m.name.starts_with('/'))
        .map(|m| (m.name, m.pool))
        .collect()
}

/// Runs `argv`, returning `None` when the binary isn't installed — a missing
/// `zpool`/`zfs` means ZFS is absent on this host, which callers surface as a
/// distinct "not installed" state rather than an error.
async fn run(argv: &[&str]) -> Result<Option<String>> {
    let output = match tokio::process::Command::new(argv[0])
        .args(&argv[1..])
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("running {}", argv.join(" "))),
    };
    anyhow::ensure!(
        output.status.success(),
        "{} failed: {}",
        argv.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(Some(String::from_utf8(output.stdout)?))
}

pub async fn pools() -> Result<Option<Vec<Pool>>> {
    run(&[
        "zpool",
        "list",
        "-Hp",
        "-o",
        "name,size,alloc,free,frag,health",
    ])
    .await?
    .map(|out| parse_zpool_list(&out))
    .transpose()
}

/// `zpool list -vHLPp`: `-v` per-vdev rows, `-L` resolve symlinks to real
/// device paths, `-P` full leaf paths, `-p` exact numbers. Feeds both
/// [`pool_members`] and [`pool_vdevs`].
///
/// `-L` is what lets a pool created against `/dev/disk/by-id/...` match the
/// `/dev/<name>` rows lsblk reports; without it every such member falls through
/// to the unnamed-pool branch.
const ZPOOL_LIST_VDEVS: &[&str] = &[
    "zpool",
    "list",
    "-vHLPp",
    "-o",
    "name,size,alloc,free,frag,health",
];

/// Device path → pool name. `None` when zpool isn't installed (ZFS absent),
/// like [`pools`].
pub async fn pool_members() -> Result<Option<HashMap<String, String>>> {
    Ok(run(ZPOOL_LIST_VDEVS)
        .await?
        .map(|out| parse_pool_members(&out)))
}

/// The full vdev tree of every pool. `None` when zpool isn't installed.
pub async fn pool_vdevs() -> Result<Option<Vec<PoolMember>>> {
    run(ZPOOL_LIST_VDEVS)
        .await?
        .map(|out| parse_pool_vdevs(&out))
        .transpose()
}

pub async fn datasets() -> Result<Option<Vec<Dataset>>> {
    run(&[
        "zfs",
        "list",
        "-Hp",
        "-t",
        "filesystem,volume",
        "-o",
        "name,type,used,avail,volsize,mountpoint,mounted",
    ])
    .await?
    .map(|out| parse_zfs_list(&out))
    .transpose()
}

#[allow(dead_code)]
pub async fn snapshots() -> Result<Option<Vec<Snapshot>>> {
    run(&[
        "zfs",
        "list",
        "-Hp",
        "-t",
        "snapshot",
        "-o",
        "name,used,creation",
    ])
    .await?
    .map(|out| parse_snapshot_list(&out))
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zpool_list_including_degraded_and_missing_frag() {
        let out = "tank\t3985729650688\t1099511627776\t2886218022912\t4\tONLINE\n\
                   backup\t998579896320\t499289948160\t499289948160\t-\tDEGRADED\n";
        let pools = parse_zpool_list(out).unwrap();
        assert_eq!(
            pools,
            vec![
                Pool {
                    name: "tank".into(),
                    size: 3_985_729_650_688,
                    alloc: 1_099_511_627_776,
                    free: 2_886_218_022_912,
                    frag_percent: Some(4),
                    health: "ONLINE".into(),
                },
                Pool {
                    name: "backup".into(),
                    size: 998_579_896_320,
                    alloc: 499_289_948_160,
                    free: 499_289_948_160,
                    frag_percent: None,
                    health: "DEGRADED".into(),
                },
            ]
        );
        assert!(
            parse_zpool_list("tank\toops\n").is_err(),
            "non-numeric size must error"
        );
        assert_eq!(parse_zpool_list("").unwrap(), vec![]);
    }

    /// `zpool list -vHPp` fixture matching the scripted-mode emitter: member
    /// rows are `\t` + 6 tab-separated fields with NO depth indentation;
    /// `alloc`/`free` are `-` for non-top-level rows; class labels are
    /// flush-left space-padded lines. Covers a mirror + top-level stripe leaf
    /// + log mirror + cache + spare, and a second raidz1 pool.
    const VDEV_FIXTURE: &str = "\
tank\t3985729650688\t1099511627776\t2886218022912\t4\tONLINE
\tmirror-0\t1992864825344\t549755813888\t1443109011456\t4\tONLINE
\t/dev/sdb1\t2000398934016\t-\t-\t-\tONLINE
\t/dev/sdc1\t2000398934016\t-\t-\t-\tONLINE
\t/dev/sdd1\t1992864825344\t549755813888\t1443109011456\t4\tONLINE
logs         -      -      -      -      -
\tmirror-1\t17179869184\t0\t17179869184\t0\tONLINE
\t/dev/sde1\t-\t-\t-\t-\tONLINE
\t/dev/sdf1\t-\t-\t-\t-\tONLINE
cache        -      -      -      -      -
\t/dev/sdg\t480103981056\t120000000000\t360103981056\t0\tONLINE
spare        -      -      -      -      -
\t/dev/sdh\t-\t-\t-\t-\tAVAIL
rz\t11990251733248\t2199023255552\t9791228477696\t1\tONLINE
\traidz1-0\t11990251733248\t2199023255552\t9791228477696\t1\tONLINE
\t/dev/sdi\t-\t-\t-\t-\tONLINE
\t/dev/sdj\t-\t-\t-\t-\tONLINE
";

    #[test]
    fn parses_vdev_tree_with_classes_containers_and_toplevel_leaves() {
        let m = parse_pool_vdevs(VDEV_FIXTURE).unwrap();
        let row = |name: &str| m.iter().find(|r| r.name == name).unwrap();

        assert_eq!(m.len(), 12, "one row per member, pools/labels excluded");
        // Containers vs leaves, and child attribution by `alloc == -`.
        let mirror = row("mirror-0");
        assert_eq!(
            (mirror.is_leaf, mirror.parent.as_deref(), mirror.class),
            (false, None, MemberClass::Data)
        );
        assert_eq!(mirror.alloc, Some(549_755_813_888));
        assert_eq!(row("/dev/sdb1").parent.as_deref(), Some("mirror-0"));
        assert_eq!(row("/dev/sdb1").size, Some(2_000_398_934_016));
        // Top-level stripe leaf after the mirror's children: real alloc ⇒ no parent.
        let stripe = row("/dev/sdd1");
        assert_eq!((stripe.is_leaf, stripe.parent.as_deref()), (true, None));
        // Log mirror and its legs.
        assert_eq!(row("mirror-1").class, MemberClass::Log);
        assert_eq!(
            (row("/dev/sde1").class, row("/dev/sde1").parent.as_deref()),
            (MemberClass::Log, Some("mirror-1"))
        );
        // Cache and spare sections.
        assert_eq!(
            (row("/dev/sdg").class, row("/dev/sdg").parent.as_deref()),
            (MemberClass::Cache, None)
        );
        assert_eq!(
            (row("/dev/sdh").class, row("/dev/sdh").health.as_deref()),
            (MemberClass::Spare, Some("AVAIL"))
        );
        // Second pool resets pool/class/container state.
        assert_eq!(row("raidz1-0").pool, "rz");
        assert_eq!(
            (
                row("/dev/sdi").pool.as_str(),
                row("/dev/sdi").parent.as_deref()
            ),
            ("rz", Some("raidz1-0"))
        );

        // The device→pool map is a derivation of the same parse.
        let map = parse_pool_members(VDEV_FIXTURE);
        assert_eq!(map.get("/dev/sdb1"), Some(&"tank".to_string()));
        assert_eq!(map.get("/dev/sdi"), Some(&"rz".to_string()));
        assert!(!map.contains_key("mirror-0"));

        assert_eq!(parse_pool_vdevs("").unwrap(), vec![]);
        assert!(
            parse_pool_vdevs("tank\t1\t1\t1\t-\tONLINE\n\t/dev/sdb\toops\t-\t-\t-\t-\n").is_err(),
            "non-numeric size must error"
        );
    }

    #[test]
    fn parses_pool_members_skipping_containers() {
        // `-L` must stay in the argv: it is what makes zpool print the real
        // `/dev/<name>` leaves this map is keyed by, rather than by-id symlinks.
        assert!(ZPOOL_LIST_VDEVS.contains(&"-vHLPp"));

        // `zpool list -vHLP`: pool headers are flush-left; vdev containers and
        // leaf devices are tab-indented. Only `/dev/...` leaves map to a pool.
        let out = "tank\t3985729650688\t1099511627776\t2886218022912\t4\tONLINE\n\
                   \tmirror-0\t3985729650688\t1099511627776\t2886218022912\t-\t-\n\
                   \t/dev/sdb\t-\t-\t-\t-\t-\n\
                   \t/dev/sdc\t-\t-\t-\t-\t-\n\
                   backup\t998579896320\t499289948160\t499289948160\t-\tONLINE\n\
                   \t/dev/disk/by-id/wwn-0x5000abc-part1\t-\t-\t-\t-\t-\n";
        let map = parse_pool_members(out);
        assert_eq!(map.get("/dev/sdb"), Some(&"tank".to_string()));
        assert_eq!(map.get("/dev/sdc"), Some(&"tank".to_string()));
        // The mirror-0 container row is not a device → not mapped.
        assert!(!map.contains_key("mirror-0"));
        // `-L` should leave no by-id leaves; one that slips through is still
        // recorded verbatim rather than dropped.
        assert_eq!(
            map.get("/dev/disk/by-id/wwn-0x5000abc-part1"),
            Some(&"backup".to_string())
        );
        assert!(parse_pool_members("").is_empty());
    }

    #[test]
    fn parses_zfs_list_filesystems_and_volumes() {
        let out = "tank\tfilesystem\t1024000\t2886218022912\t-\t/tank\tyes\n\
                   tank/share\tfilesystem\t512000\t2886218022912\t-\tlegacy\tno\n\
                   tank/vols/vm1\tvolume\t10737418240\t2886218022912\t10737418240\t-\t-\n";
        let ds = parse_zfs_list(out).unwrap();
        assert_eq!(ds.len(), 3);
        assert_eq!(ds[0].kind, DsKind::Filesystem);
        assert_eq!(
            (ds[0].volsize, ds[0].mountpoint.as_str(), ds[0].mounted),
            (None, "/tank", true)
        );
        // legacy/unmounted filesystem.
        assert_eq!(
            (ds[1].mountpoint.as_str(), ds[1].mounted),
            ("legacy", false)
        );
        assert_eq!(
            ds[2],
            Dataset {
                name: "tank/vols/vm1".into(),
                kind: DsKind::Volume,
                used: 10_737_418_240,
                avail: 2_886_218_022_912,
                volsize: Some(10_737_418_240),
                mountpoint: "-".into(),
                mounted: false, // volumes report `-`
            }
        );
        assert!(
            parse_zfs_list("tank\tbookmark\t1\t2\t-\t-\t-\n").is_err(),
            "unknown type must error"
        );
    }

    #[tokio::test]
    async fn run_returns_none_for_missing_binary_but_errors_on_failure() {
        // A missing binary (ZFS not installed) yields None, not an error.
        assert!(
            run(&["greendot-no-such-binary", "list"])
                .await
                .unwrap()
                .is_none()
        );
        // A command that exists but exits non-zero is still surfaced as an error.
        assert!(run(&["false"]).await.is_err());
    }

    #[test]
    fn parses_snapshot_list() {
        let out = "tank/vols/vm1@greendot-auto-20260613-020000\t8192\t1781316000\n";
        let snaps = parse_snapshot_list(out).unwrap();
        assert_eq!(
            snaps,
            vec![Snapshot {
                name: "tank/vols/vm1@greendot-auto-20260613-020000".into(),
                used: 8192,
                creation: 1_781_316_000,
            }]
        );
    }
}
