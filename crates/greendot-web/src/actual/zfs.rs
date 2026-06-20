//! Parsers for `zpool list -Hp` / `zfs list -Hp` output and the async
//! executors that produce it. `-H` = no headers, tab-separated; `-p` =
//! exact numbers.

use anyhow::{Context, Result};

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

/// `zfs list -Hp -t filesystem,volume -o name,type,used,avail,volsize`
pub fn parse_zfs_list(out: &str) -> Result<Vec<Dataset>> {
    out.lines()
        .map(|line| {
            let f = fields(line, 5)?;
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

pub async fn datasets() -> Result<Option<Vec<Dataset>>> {
    run(&[
        "zfs",
        "list",
        "-Hp",
        "-t",
        "filesystem,volume",
        "-o",
        "name,type,used,avail,volsize",
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

    #[test]
    fn parses_zfs_list_filesystems_and_volumes() {
        let out = "tank\tfilesystem\t1024000\t2886218022912\t-\n\
                   tank/vols\tfilesystem\t512000\t2886218022912\t-\n\
                   tank/vols/vm1\tvolume\t10737418240\t2886218022912\t10737418240\n";
        let ds = parse_zfs_list(out).unwrap();
        assert_eq!(ds.len(), 3);
        assert_eq!(ds[0].kind, DsKind::Filesystem);
        assert_eq!(ds[0].volsize, None);
        assert_eq!(
            ds[2],
            Dataset {
                name: "tank/vols/vm1".into(),
                kind: DsKind::Volume,
                used: 10_737_418_240,
                avail: 2_886_218_022_912,
                volsize: Some(10_737_418_240),
            }
        );
        assert!(
            parse_zfs_list("tank\tbookmark\t1\t2\t-\n").is_err(),
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
