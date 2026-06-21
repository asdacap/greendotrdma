//! Read-only view of the LIO configfs tree (/sys/kernel/config/target).

use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActualLio {
    pub backstores: Vec<Backstore>,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backstore {
    pub name: String,
    pub udev_path: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub iqn: String,
    pub enabled: bool,
    pub demo_mode: bool,
    /// Backstore names linked as LUNs (we only use lun_0).
    pub luns: Vec<String>,
    pub portals: Vec<Portal>,
    pub acls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Portal {
    /// Directory name, e.g. `10.0.0.5:3260` or `[::1]:3260`.
    pub addr_port: String,
    pub iser: bool,
}

impl Portal {
    /// The address part, without the port.
    pub fn addr(&self) -> &str {
        let addr = self
            .addr_port
            .rsplit_once(':')
            .map_or(self.addr_port.as_str(), |(a, _)| a);
        addr.trim_start_matches('[').trim_end_matches(']')
    }
}

/// One live iSCSI session: a connected initiator on one of our targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IscsiSession {
    pub target_iqn: String,
    pub initiator_iqn: String,
    /// The raw `info` text for an explicit-ACL session (empty for demo-mode
    /// dynamic sessions, which expose no per-session attributes).
    pub detail: String,
}

fn read_attr(dir: &Path, attr: &str) -> String {
    std::fs::read_to_string(dir.join(attr))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn dir_names(dir: &Path) -> Vec<String> {
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

pub fn read(root: &Path) -> ActualLio {
    let mut actual = ActualLio::default();
    for name in dir_names(&root.join("core/iblock_0")) {
        let dir = root.join("core/iblock_0").join(&name);
        if !dir.is_dir() {
            continue; // hba attribute files
        }
        actual.backstores.push(Backstore {
            // `info` is authoritative on real configfs, but `control` is
            // write-only there; we re-read what we wrote via udev_path.
            udev_path: read_attr(&dir, "udev_path"),
            enabled: read_attr(&dir, "enable") == "1",
            name,
        });
    }
    for iqn in dir_names(&root.join("iscsi")) {
        let tpg = root.join("iscsi").join(&iqn).join("tpgt_1");
        if !tpg.is_dir() {
            continue; // discovery_auth and friends
        }
        let luns = dir_names(&tpg.join("lun"))
            .into_iter()
            .filter(|l| l.starts_with("lun_"))
            .flat_map(|l| {
                let lun_dir = tpg.join("lun").join(&l);
                dir_names(&lun_dir).into_iter().filter_map(move |n| {
                    // The symlink's own name is a random rtslib alias; the
                    // backstore it maps to is the target's basename
                    // (core/iblock_0/<name>), which is what we match on.
                    let link = lun_dir.join(&n);
                    if !link.is_symlink() {
                        return None;
                    }
                    std::fs::read_link(&link)
                        .ok()
                        .and_then(|t| t.file_name().map(|s| s.to_string_lossy().into_owned()))
                })
            })
            .collect();
        actual.targets.push(Target {
            enabled: read_attr(&tpg, "enable") == "1",
            demo_mode: read_attr(&tpg.join("attrib"), "generate_node_acls") == "1",
            luns,
            portals: dir_names(&tpg.join("np"))
                .into_iter()
                .map(|p| Portal {
                    iser: read_attr(&tpg.join("np").join(&p), "iser") == "1",
                    addr_port: p,
                })
                .collect(),
            acls: dir_names(&tpg.join("acls")),
            iqn,
        });
    }
    actual
}

/// Live iSCSI sessions from the LIO configfs tree (`iscsi/<iqn>/tpgt_1`).
/// Explicit ACLs expose an `info` file naming the session state; we emit a row
/// only when it reports a logged-in session. Demo-mode (`generate_node_acls`)
/// sessions appear only in `dynamic_sessions`, one connected initiator IQN per
/// line. Unprivileged, like [`read`].
pub fn sessions(root: &Path) -> Vec<IscsiSession> {
    let mut out = Vec::new();
    for iqn in dir_names(&root.join("iscsi")) {
        let tpg = root.join("iscsi").join(&iqn).join("tpgt_1");
        if !tpg.is_dir() {
            continue;
        }
        for initiator in dir_names(&tpg.join("acls")) {
            let info = read_attr(&tpg.join("acls").join(&initiator), "info");
            if !info.contains("LOGGED_IN") {
                continue; // configured but not currently connected
            }
            out.push(IscsiSession {
                target_iqn: iqn.clone(),
                initiator_iqn: initiator,
                detail: info,
            });
        }
        for initiator in read_attr(&tpg, "dynamic_sessions")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            if out
                .iter()
                .any(|s| s.target_iqn == iqn && s.initiator_iqn == initiator)
            {
                continue; // already captured as an explicit ACL
            }
            out.push(IscsiSession {
                target_iqn: iqn.clone(),
                initiator_iqn: initiator.to_owned(),
                detail: String::new(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::v4("10.0.0.5:3260", "10.0.0.5")]
    #[case::v6("[::1]:3260", "::1")]
    fn portal_addr_extraction(#[case] dirname: &str, #[case] want: &str) {
        let portal = Portal {
            addr_port: dirname.into(),
            iser: false,
        };
        assert_eq!(portal.addr(), want);
    }

    #[test]
    fn reads_fixture_tree_and_missing_root_reads_empty() {
        assert_eq!(read(Path::new("/nonexistent/target")), ActualLio::default());

        let tmp = std::env::temp_dir().join(format!("gd-lio-read{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bs = tmp.join("core/iblock_0/vm1");
        std::fs::create_dir_all(&bs).unwrap();
        std::fs::write(bs.join("udev_path"), "/dev/zvol/tank/vm1\n").unwrap();
        std::fs::write(bs.join("enable"), "1\n").unwrap();
        let tpg = tmp.join("iscsi/iqn.2026-06.io.greendot:vm1/tpgt_1");
        std::fs::create_dir_all(tpg.join("lun/lun_0")).unwrap();
        // rtslib names the LUN symlink a random alias; we match on its target.
        std::os::unix::fs::symlink(&bs, tpg.join("lun/lun_0/9f3a2b1c00")).unwrap();
        std::fs::create_dir_all(tpg.join("np/10.0.0.5:3260")).unwrap();
        std::fs::write(tpg.join("np/10.0.0.5:3260/iser"), "1\n").unwrap();
        std::fs::create_dir_all(tpg.join("acls/iqn.1993-08.org.debian:01:abc")).unwrap();
        std::fs::create_dir_all(tpg.join("attrib")).unwrap();
        std::fs::write(tpg.join("attrib/generate_node_acls"), "0\n").unwrap();
        std::fs::write(tpg.join("enable"), "1\n").unwrap();

        let actual = read(&tmp);
        assert_eq!(
            actual,
            ActualLio {
                backstores: vec![Backstore {
                    name: "vm1".into(),
                    udev_path: "/dev/zvol/tank/vm1".into(),
                    enabled: true,
                }],
                targets: vec![Target {
                    iqn: "iqn.2026-06.io.greendot:vm1".into(),
                    enabled: true,
                    demo_mode: false,
                    luns: vec!["vm1".into()],
                    portals: vec![Portal {
                        addr_port: "10.0.0.5:3260".into(),
                        iser: true
                    }],
                    acls: vec!["iqn.1993-08.org.debian:01:abc".into()],
                }],
            }
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn reads_iscsi_sessions_and_missing_root_is_empty() {
        assert!(sessions(Path::new("/nonexistent/target")).is_empty());

        let tmp = std::env::temp_dir().join(format!("gd-lio-sess{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let tpg = tmp.join("iscsi/iqn.2026-06.io.greendot:vm1/tpgt_1");
        // Explicit ACL with a live (logged-in) session.
        let live = tpg.join("acls/iqn.1993-08.org.debian:01:live");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(
            live.join("info"),
            "InitiatorName: iqn.1993-08.org.debian:01:live\nSession State: TARG_SESS_STATE_LOGGED_IN\n",
        )
        .unwrap();
        // Explicit ACL that is configured but not connected — filtered out.
        let idle = tpg.join("acls/iqn.1993-08.org.debian:01:idle");
        std::fs::create_dir_all(&idle).unwrap();
        std::fs::write(idle.join("info"), "No active iSCSI Session\n").unwrap();
        // A demo-mode dynamic session — no ACL dir, listed only here.
        std::fs::write(
            tpg.join("dynamic_sessions"),
            "iqn.1993-08.org.debian:01:dyn\n",
        )
        .unwrap();

        let mut got = sessions(&tmp);
        got.sort_by(|a, b| a.initiator_iqn.cmp(&b.initiator_iqn));
        assert_eq!(
            got,
            vec![
                IscsiSession {
                    target_iqn: "iqn.2026-06.io.greendot:vm1".into(),
                    initiator_iqn: "iqn.1993-08.org.debian:01:dyn".into(),
                    detail: String::new(),
                },
                IscsiSession {
                    target_iqn: "iqn.2026-06.io.greendot:vm1".into(),
                    initiator_iqn: "iqn.1993-08.org.debian:01:live".into(),
                    detail: "InitiatorName: iqn.1993-08.org.debian:01:live\nSession State: TARG_SESS_STATE_LOGGED_IN".into(),
                },
            ]
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
