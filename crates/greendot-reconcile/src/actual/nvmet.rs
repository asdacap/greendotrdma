//! Read-only view of the nvmet configfs tree. A missing tree (module not
//! loaded) reads as empty; malformed entries are skipped.

use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActualNvmet {
    pub subsystems: Vec<Subsys>,
    pub ports: Vec<Port>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsys {
    pub nqn: String,
    pub allow_any_host: bool,
    pub allowed_hosts: Vec<String>,
    pub namespaces: Vec<Namespace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub nsid: u32,
    pub device_path: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub id: u16,
    pub trtype: String,
    pub traddr: String,
    pub trsvcid: String,
    pub subsystems: Vec<String>,
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

pub fn read(root: &Path) -> ActualNvmet {
    let mut actual = ActualNvmet::default();
    for nqn in dir_names(&root.join("subsystems")) {
        let dir = root.join("subsystems").join(&nqn);
        let namespaces = dir_names(&dir.join("namespaces"))
            .into_iter()
            .filter_map(|nsid| {
                let ns_dir = dir.join("namespaces").join(&nsid);
                Some(Namespace {
                    nsid: nsid.parse().ok()?,
                    device_path: read_attr(&ns_dir, "device_path"),
                    enabled: read_attr(&ns_dir, "enable") == "1",
                })
            })
            .collect();
        actual.subsystems.push(Subsys {
            allow_any_host: read_attr(&dir, "attr_allow_any_host") == "1",
            allowed_hosts: dir_names(&dir.join("allowed_hosts")),
            namespaces,
            nqn,
        });
    }
    for id in dir_names(&root.join("ports")) {
        let dir = root.join("ports").join(&id);
        let Ok(id) = id.parse() else { continue };
        actual.ports.push(Port {
            id,
            trtype: read_attr(&dir, "addr_trtype"),
            traddr: read_attr(&dir, "addr_traddr"),
            trsvcid: read_attr(&dir, "addr_trsvcid"),
            subsystems: dir_names(&dir.join("subsystems")),
        });
    }
    actual
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fixture_tree_and_missing_root_reads_empty() {
        assert_eq!(
            read(Path::new("/nonexistent/nvmet")),
            ActualNvmet::default()
        );

        let tmp = std::env::temp_dir().join(format!("gd-nvmet-read{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let subsys = tmp.join("subsystems/nqn.2026-06.io.greendot:vm1");
        std::fs::create_dir_all(subsys.join("namespaces/1")).unwrap();
        std::fs::create_dir_all(subsys.join("allowed_hosts")).unwrap();
        std::fs::write(subsys.join("attr_allow_any_host"), "0\n").unwrap();
        std::fs::write(
            subsys.join("namespaces/1/device_path"),
            "/dev/zvol/tank/vm1\n",
        )
        .unwrap();
        std::fs::write(subsys.join("namespaces/1/enable"), "1\n").unwrap();
        std::fs::File::create(subsys.join("allowed_hosts/nqn.2014-08.org.nvmexpress:host1"))
            .unwrap();
        let port = tmp.join("ports/1");
        std::fs::create_dir_all(port.join("subsystems")).unwrap();
        std::fs::write(port.join("addr_trtype"), "rdma\n").unwrap();
        std::fs::write(port.join("addr_traddr"), "10.0.0.5\n").unwrap();
        std::fs::write(port.join("addr_trsvcid"), "4420\n").unwrap();
        std::fs::File::create(port.join("subsystems/nqn.2026-06.io.greendot:vm1")).unwrap();

        let actual = read(&tmp);
        assert_eq!(
            actual,
            ActualNvmet {
                subsystems: vec![Subsys {
                    nqn: "nqn.2026-06.io.greendot:vm1".into(),
                    allow_any_host: false,
                    allowed_hosts: vec!["nqn.2014-08.org.nvmexpress:host1".into()],
                    namespaces: vec![Namespace {
                        nsid: 1,
                        device_path: "/dev/zvol/tank/vm1".into(),
                        enabled: true,
                    }],
                }],
                ports: vec![Port {
                    id: 1,
                    trtype: "rdma".into(),
                    traddr: "10.0.0.5".into(),
                    trsvcid: "4420".into(),
                    subsystems: vec!["nqn.2026-06.io.greendot:vm1".into()],
                }],
            }
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
