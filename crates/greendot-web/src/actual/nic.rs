//! Per-NIC RDMA capability, classified purely from sysfs (unprivileged).
//!
//! For every network interface we decide whether RDMA is already active, could
//! be turned on (hardware RoCE that's disabled, or Soft-RoCE on a plain NIC),
//! or isn't applicable. The hardware-RoCE-disabled case is the one the green
//! dot can't otherwise explain: a Mellanox NIC whose `enable_roce` is off
//! exposes no `/sys/class/infiniband` device at all.

use super::rdma::{port_active, read_trimmed};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicStatus {
    pub netdev: String,
    /// Backing RDMA device name, when one exists.
    pub rdma: Option<String>,
    pub addrs: Vec<IpAddr>,
    pub kind: NicRdmaKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NicRdmaKind {
    /// An RDMA device backs this NIC and a port is ACTIVE.
    Active,
    /// An RDMA device backs this NIC but no port is up.
    Inactive,
    /// RoCE-capable hardware (Mellanox) with no RDMA device — RoCE is disabled
    /// and can be turned on via devlink at this PCI address.
    CapableDisabled { pci: String },
    /// A plain Ethernet NIC that can get Soft-RoCE (rxe).
    SoftRoceable,
    /// Not an RDMA candidate (virtual interface, IB-only netdev, …).
    Unsupported,
}

/// Mellanox PCI vendor id (ConnectX family). RoCE-capable NICs from other
/// vendors (Broadcom, Intel E810, Chelsio) are not detected yet.
const MELLANOX_VENDOR: &str = "0x15b3";

/// Every netdev backing an RDMA device — `parent` plus every port's GID-table
/// netdev — so multi-port cards and port-2 RoCE netdevs are all captured (a
/// superset of `rdma::read`, which only looks at port 1). Maps netdev →
/// (device name, any-port-active).
fn rdma_backed(ib_root: &Path) -> HashMap<String, (String, bool)> {
    let mut map: HashMap<String, (String, bool)> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(ib_root) else {
        return map;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let dev = entry.file_name().to_string_lossy().into_owned();
        let active = port_active(&dir);
        for nd in backing_netdevs(&dir) {
            map.entry(nd)
                .and_modify(|e| {
                    if active && !e.1 {
                        *e = (dev.clone(), true);
                    }
                })
                .or_insert_with(|| (dev.clone(), active));
        }
    }
    map
}

fn backing_netdevs(dev_dir: &Path) -> Vec<String> {
    let mut nds: Vec<String> = read_trimmed(&dev_dir.join("parent")).into_iter().collect();
    if let Ok(ports) = std::fs::read_dir(dev_dir.join("ports")) {
        for port in ports.flatten() {
            if let Ok(ndevs) = std::fs::read_dir(port.path().join("gid_attrs/ndevs")) {
                nds.extend(ndevs.flatten().filter_map(|nd| read_trimmed(&nd.path())));
            }
        }
    }
    nds.sort();
    nds.dedup();
    nds
}

/// A physical Ethernet NIC: has a PCI `device` and ARPHRD_ETHER link type.
fn is_ethernet(net_dir: &Path) -> bool {
    net_dir.join("device").symlink_metadata().is_ok()
        && read_trimmed(&net_dir.join("type")).as_deref() == Some("1")
}

fn is_mellanox(net_dir: &Path) -> bool {
    read_trimmed(&net_dir.join("device/vendor")).as_deref() == Some(MELLANOX_VENDOR)
}

/// PCI address from the netdev's `device` symlink, e.g. `0000:00:10.0`.
fn nic_pci(net_dir: &Path) -> Option<String> {
    std::fs::read_link(net_dir.join("device"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Classify every interface under `net_root`, using `ib_root` for RDMA backing
/// and `netdev_addrs` for the addresses column. Pure over its inputs.
pub fn classify(
    net_root: &Path,
    ib_root: &Path,
    netdev_addrs: &HashMap<String, Vec<IpAddr>>,
) -> Vec<NicStatus> {
    let backed = rdma_backed(ib_root);
    let Ok(entries) = std::fs::read_dir(net_root) else {
        return Vec::new();
    };
    let mut nics: Vec<NicStatus> = entries
        .flatten()
        .filter_map(|entry| {
            let netdev = entry.file_name().to_string_lossy().into_owned();
            if netdev == "lo" {
                return None;
            }
            let net_dir = entry.path();
            let (rdma, kind) = if let Some((dev, active)) = backed.get(&netdev) {
                let kind = if *active {
                    NicRdmaKind::Active
                } else {
                    NicRdmaKind::Inactive
                };
                (Some(dev.clone()), kind)
            } else if is_ethernet(&net_dir) {
                match is_mellanox(&net_dir).then(|| nic_pci(&net_dir)).flatten() {
                    Some(pci) => (None, NicRdmaKind::CapableDisabled { pci }),
                    None => (None, NicRdmaKind::SoftRoceable),
                }
            } else {
                (None, NicRdmaKind::Unsupported)
            };
            Some(NicStatus {
                rdma,
                kind,
                addrs: netdev_addrs.get(&netdev).cloned().unwrap_or_default(),
                netdev,
            })
        })
        .collect();
    nics.sort_by(|a, b| a.netdev.cmp(&b.netdev));
    nics
}

/// Live NIC classification from `/sys`.
pub fn interfaces() -> Vec<NicStatus> {
    classify(
        Path::new("/sys/class/net"),
        Path::new("/sys/class/infiniband"),
        &super::rdma::netdev_addrs(),
    )
}

/// Parse `devlink dev param show -j` for the `enable_roce` value: `Some(true)`
/// / `Some(false)` if the param is present, `None` if absent (e.g. a VF that
/// can't self-enable RoCE — the fix should not be attempted).
pub fn enable_roce_from_json(json: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let param = v.get("param")?;
    // `{"param": {"pci/<addr>": [ {name, values:[{value}]}, … ]}}`; some
    // versions emit `{"param": [ … ]}` directly — handle both.
    let groups: Vec<&serde_json::Value> = match param {
        serde_json::Value::Object(map) => map.values().collect(),
        serde_json::Value::Array(_) => vec![param],
        _ => return None,
    };
    for arr in groups.iter().filter_map(|g| g.as_array()) {
        for p in arr {
            if p.get("name").and_then(serde_json::Value::as_str) == Some("enable_roce") {
                return p
                    .get("values")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|vs| vs.first())
                    .and_then(|val| val.get("value"))
                    .and_then(serde_json::Value::as_bool);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a fake sysfs tree under a temp root: `<root>/net` (class/net) and
    /// `<root>/ib` (class/infiniband), with PCI device dirs under `<root>/pci`.
    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("gd-nic-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("net")).unwrap();
            std::fs::create_dir_all(root.join("ib")).unwrap();
            std::fs::create_dir_all(root.join("pci")).unwrap();
            Fixture { root }
        }

        /// A netdev with the given ARPHRD `type` and, if `vendor` is set, a PCI
        /// `device` symlink to a `<root>/pci/<pci>` dir carrying that vendor.
        fn netdev(&self, name: &str, type_: &str, pci: Option<(&str, &str)>) {
            let dir = self.root.join("net").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("type"), format!("{type_}\n")).unwrap();
            if let Some((pci, vendor)) = pci {
                let pci_dir = self.root.join("pci").join(pci);
                std::fs::create_dir_all(&pci_dir).unwrap();
                std::fs::write(pci_dir.join("vendor"), format!("{vendor}\n")).unwrap();
                std::os::unix::fs::symlink(&pci_dir, dir.join("device")).unwrap();
            }
        }

        /// An RDMA device backing `netdev` via `parent`, with the given port state.
        fn rdma_parent(&self, dev: &str, netdev: &str, state: &str) {
            let dir = self.root.join("ib").join(dev);
            std::fs::create_dir_all(dir.join("ports/1")).unwrap();
            std::fs::write(dir.join("parent"), format!("{netdev}\n")).unwrap();
            std::fs::write(dir.join("ports/1/state"), format!("{state}\n")).unwrap();
        }

        /// An RDMA device backing `netdev` via the GID-table (a RoCE/IB HCA).
        fn rdma_hca(&self, dev: &str, netdev: &str, state: &str) {
            let dir = self.root.join("ib").join(dev);
            std::fs::create_dir_all(dir.join("ports/1/gid_attrs/ndevs")).unwrap();
            std::fs::write(dir.join("ports/1/gid_attrs/ndevs/0"), format!("{netdev}\n")).unwrap();
            std::fs::write(dir.join("ports/1/state"), format!("{state}\n")).unwrap();
        }

        fn classify(&self) -> Vec<NicStatus> {
            classify(
                &self.root.join("net"),
                &self.root.join("ib"),
                &HashMap::new(),
            )
        }

        fn kind(&self, nics: &[NicStatus], netdev: &str) -> NicRdmaKind {
            nics.iter()
                .find(|n| n.netdev == netdev)
                .unwrap_or_else(|| panic!("no nic {netdev} in {nics:#?}"))
                .kind
                .clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn classifies_every_interface_kind() {
        let f = Fixture::new("kinds");
        // (a) Mellanox VF, Ethernet, no IB device → RoCE disabled, fixable.
        f.netdev("ens16", "1", Some(("0000:00:10.0", "0x15b3")));
        // (b) plain NIC backed by an active Soft-RoCE device → Active.
        f.netdev("eth0", "1", Some(("0000:01:00.0", "0x10ec")));
        f.rdma_parent("rxe-eth0", "eth0", "4: ACTIVE");
        // (c) Mellanox IB-link-layer port, down → Inactive, NOT CapableDisabled.
        f.netdev("ibp1s0", "32", None);
        f.rdma_hca("mlx5_0", "ibp1s0", "1: DOWN");
        // (d) virtual interface (bridge: Ethernet type, no PCI device) → Unsupported.
        f.netdev("br0", "1", None);
        // (e) plain Realtek Ethernet, no RDMA → Soft-RoCE candidate.
        f.netdev("eth1", "1", Some(("0000:02:00.0", "0x10ec")));
        // (f) loopback is excluded.
        f.netdev("lo", "772", None);

        let nics = f.classify();
        assert!(!nics.iter().any(|n| n.netdev == "lo"), "lo excluded");
        assert_eq!(
            f.kind(&nics, "ens16"),
            NicRdmaKind::CapableDisabled {
                pci: "0000:00:10.0".into()
            }
        );
        assert_eq!(f.kind(&nics, "eth0"), NicRdmaKind::Active);
        assert_eq!(
            nics.iter().find(|n| n.netdev == "eth0").unwrap().rdma,
            Some("rxe-eth0".into())
        );
        assert_eq!(f.kind(&nics, "ibp1s0"), NicRdmaKind::Inactive);
        assert_eq!(f.kind(&nics, "br0"), NicRdmaKind::Unsupported);
        assert_eq!(f.kind(&nics, "eth1"), NicRdmaKind::SoftRoceable);
    }

    #[test]
    fn parses_enable_roce_from_devlink_json() {
        let disabled = r#"{"param":{"pci/0000:00:10.0":[
            {"name":"enable_eth","type":"generic","values":[{"cmode":"driverinit","value":true}]},
            {"name":"enable_roce","type":"generic","values":[{"cmode":"driverinit","value":false}]}
        ]}}"#;
        let enabled = r#"{"param":{"pci/0000:00:10.0":[
            {"name":"enable_roce","type":"generic","values":[{"cmode":"driverinit","value":true}]}
        ]}}"#;
        let absent = r#"{"param":{"pci/0000:00:10.0":[
            {"name":"enable_eth","type":"generic","values":[{"cmode":"driverinit","value":true}]}
        ]}}"#;
        assert_eq!(enable_roce_from_json(disabled), Some(false));
        assert_eq!(enable_roce_from_json(enabled), Some(true));
        assert_eq!(enable_roce_from_json(absent), None);
        assert_eq!(enable_roce_from_json("not json"), None);
    }
}
