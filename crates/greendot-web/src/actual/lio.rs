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
                dir_names(&lun_dir)
                    .into_iter()
                    .filter(move |n| lun_dir.join(n).is_symlink())
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
        std::os::unix::fs::symlink(&bs, tpg.join("lun/lun_0/vm1")).unwrap();
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
}
