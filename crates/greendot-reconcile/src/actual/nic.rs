//! Per-NIC RDMA capability. The structural classification (is RDMA already
//! active, down, or absent) is read from sysfs here; the one vendor-aware step —
//! "is this RoCE-capable hardware whose RoCE is off?" — is answered by the helper
//! and injected (see the async wrappers in greendot-web), so this module carries
//! no vendor knowledge. A NIC whose RoCE is off exposes no `/sys/class/infiniband`
//! device at all, which is why that case can't be read here structurally.

use super::rdma::{port_active, read_trimmed};
use greendot_proto::PciAddress;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicStatus {
    pub netdev: String,
    /// Backing RDMA device name, when one exists.
    pub rdma: Option<String>,
    /// The PCI address of the backing physical port, when this is a physical NIC
    /// — the stable identity used to pin an export to this port across IP churn
    /// and NIC swaps.
    pub pci: Option<PciAddress>,
    pub addrs: Vec<IpAddr>,
    pub kind: NicRdmaKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NicRdmaKind {
    /// An RDMA device backs this NIC and a port is ACTIVE.
    Active,
    /// An RDMA device backs this NIC but no port is up.
    Inactive,
    /// RoCE-capable hardware with no RDMA device — RoCE is disabled and can be
    /// turned on (the helper handles the vendor-specific enable). `vendor` is the
    /// label the helper reported for the UI.
    CapableDisabled { vendor: String },
    /// A plain Ethernet NIC that can get Soft-RoCE (rxe).
    SoftRoceable,
    /// Not an RDMA candidate (virtual interface, IB-only netdev, …).
    Unsupported,
}

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

/// PCI address from the netdev's `device` symlink, e.g. `0000:00:10.0` (a plain
/// PCI bus address — no vendor knowledge, so the web reads it directly). Mirrors
/// the helper's `hardware::pci_of`.
fn pci_of(net_dir: &Path) -> Option<PciAddress> {
    let target = std::fs::read_link(net_dir.join("device")).ok()?;
    PciAddress::new(target.file_name()?.to_string_lossy().as_ref()).ok()
}

/// PCI address (bare, e.g. `0000:00:10.0`) → current non-loopback IPs, joining
/// each netdev's `device` symlink with `netdev_addrs`. Pure over its inputs and
/// helper-free, so the reconciler resolves a pinned interface to its live IP
/// without a helper round-trip.
pub fn pci_to_addrs(
    net_root: &Path,
    netdev_addrs: &HashMap<String, Vec<IpAddr>>,
) -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(net_root) else {
        return map;
    };
    for entry in entries.flatten() {
        let Some(pci) = pci_of(&entry.path()) else {
            continue;
        };
        let netdev = entry.file_name().to_string_lossy().into_owned();
        if let Some(addrs) = netdev_addrs.get(&netdev) {
            map.entry(pci.to_string())
                .or_default()
                .extend(addrs.iter().copied());
        }
    }
    map
}

/// Live PCI address → IPs map from `/sys/class/net` and `getifaddrs`.
pub fn pci_addrs() -> HashMap<String, Vec<IpAddr>> {
    pci_to_addrs(Path::new("/sys/class/net"), &super::rdma::netdev_addrs())
}

/// Classify every interface under `net_root`, using `ib_root` for RDMA backing,
/// `netdev_addrs` for the addresses column, and `roce_hw` (netdev → vendor, from
/// the helper) to mark a plain Ethernet NIC as RoCE-capable-but-disabled. Pure
/// over its inputs.
pub fn classify(
    net_root: &Path,
    ib_root: &Path,
    netdev_addrs: &HashMap<String, Vec<IpAddr>>,
    roce_hw: &HashMap<String, String>,
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
                match roce_hw.get(&netdev) {
                    Some(vendor) => (
                        None,
                        NicRdmaKind::CapableDisabled {
                            vendor: vendor.clone(),
                        },
                    ),
                    None => (None, NicRdmaKind::SoftRoceable),
                }
            } else {
                (None, NicRdmaKind::Unsupported)
            };
            Some(NicStatus {
                rdma,
                kind,
                pci: pci_of(&net_dir),
                addrs: netdev_addrs.get(&netdev).cloned().unwrap_or_default(),
                netdev,
            })
        })
        .collect();
    nics.sort_by(|a, b| a.netdev.cmp(&b.netdev));
    nics
}

/// Parses the helper's RoCE-capable NIC inventory (`[{netdev, vendor}]` JSON)
/// into `netdev → vendor`. Garbage/empty degrades to no capable NICs (every
/// plain NIC then reads as a Soft-RoCE candidate).
pub fn parse_roce_capable(stdout: &str) -> HashMap<String, String> {
    #[derive(serde::Deserialize)]
    struct Row {
        netdev: String,
        vendor: String,
    }
    serde_json::from_str::<Vec<Row>>(stdout)
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.netdev, r.vendor))
        .collect()
}

/// An opaque per-NIC RDMA advisory from the helper: a human label and detail
/// explaining why a NIC may lack RDMA and how to fix it. The web renders these
/// verbatim and reads nothing into them — all vendor knowledge stays in the
/// helper (`Request::NicRdmaAdvice`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicAdvice {
    pub label: String,
    pub detail: String,
}

/// Parses the helper's per-NIC advisories (`[{netdev, label, detail}]` JSON)
/// into `netdev → advice`. Garbage/empty/missing-fields degrade to no advisories.
pub fn parse_nic_advice(stdout: &str) -> HashMap<String, NicAdvice> {
    #[derive(serde::Deserialize)]
    struct Row {
        netdev: String,
        label: String,
        detail: String,
    }
    serde_json::from_str::<Vec<Row>>(stdout)
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            (
                r.netdev,
                NicAdvice {
                    label: r.label,
                    detail: r.detail,
                },
            )
        })
        .collect()
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

        /// A netdev with the given ARPHRD `type` and, if `pci` is set, a PCI
        /// `device` symlink (so it reads as a physical Ethernet NIC).
        fn netdev(&self, name: &str, type_: &str, pci: Option<&str>) {
            let dir = self.root.join("net").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("type"), format!("{type_}\n")).unwrap();
            if let Some(pci) = pci {
                let pci_dir = self.root.join("pci").join(pci);
                std::fs::create_dir_all(&pci_dir).unwrap();
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

        fn classify(&self, roce_hw: &HashMap<String, String>) -> Vec<NicStatus> {
            classify(
                &self.root.join("net"),
                &self.root.join("ib"),
                &HashMap::new(),
                roce_hw,
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
        // (a) physical NIC the helper reports as RoCE-capable, no IB device →
        // RoCE disabled, fixable, labelled with the helper's vendor.
        f.netdev("ens16", "1", Some("0000:00:10.0"));
        // (b) plain NIC backed by an active Soft-RoCE device → Active.
        f.netdev("eth0", "1", Some("0000:01:00.0"));
        f.rdma_parent("rxe-eth0", "eth0", "4: ACTIVE");
        // (c) IB-link-layer port, down → Inactive, NOT CapableDisabled.
        f.netdev("ibp1s0", "32", None);
        f.rdma_hca("mlx5_0", "ibp1s0", "1: DOWN");
        // (d) virtual interface (bridge: Ethernet type, no PCI device) → Unsupported.
        f.netdev("br0", "1", None);
        // (e) plain Ethernet, no RDMA, not capable → Soft-RoCE candidate.
        f.netdev("eth1", "1", Some("0000:02:00.0"));
        // (f) loopback is excluded.
        f.netdev("lo", "772", None);

        // The helper's verdict: only ens16 is RoCE-capable hardware. The vendor
        // label is opaque to the web (proving it carries no vendor knowledge).
        let roce_hw = HashMap::from([("ens16".to_string(), "Acme".to_string())]);
        let nics = f.classify(&roce_hw);
        assert!(!nics.iter().any(|n| n.netdev == "lo"), "lo excluded");
        assert_eq!(
            f.kind(&nics, "ens16"),
            NicRdmaKind::CapableDisabled {
                vendor: "Acme".into()
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
    fn reads_pci_address_and_resolves_to_ips() {
        let f = Fixture::new("pci");
        f.netdev("ens16", "1", Some("0000:00:10.0"));
        f.netdev("br0", "1", None); // virtual: no PCI device

        // classify records the physical NIC's PCI address, none for the virtual one.
        let nics = f.classify(&HashMap::new());
        let pci = |netdev: &str| {
            nics.iter()
                .find(|n| n.netdev == netdev)
                .unwrap()
                .pci
                .as_ref()
                .map(ToString::to_string)
        };
        assert_eq!(pci("ens16").as_deref(), Some("0000:00:10.0"));
        assert_eq!(pci("br0"), None);

        // pci_to_addrs joins the `device` symlink with the netdev → IPs map.
        let addrs = HashMap::from([("ens16".to_owned(), vec!["10.0.0.1".parse().unwrap()])]);
        let map = pci_to_addrs(&f.root.join("net"), &addrs);
        assert_eq!(
            map.get("0000:00:10.0"),
            Some(&vec!["10.0.0.1".parse::<IpAddr>().unwrap()])
        );
        assert!(!map.contains_key("br0"));
    }

    #[test]
    fn parses_roce_capable_inventory() {
        let json = r#"[{"netdev":"ens16","vendor":"Acme"},{"netdev":"ens17","vendor":"Acme"}]"#;
        let map = parse_roce_capable(json);
        assert_eq!(map.get("ens16").map(String::as_str), Some("Acme"));
        assert_eq!(map.len(), 2);
        // Garbage / empty degrades to no capable NICs.
        assert!(parse_roce_capable("not json").is_empty());
        assert!(parse_roce_capable("[]").is_empty());
    }

    #[test]
    fn parses_nic_advice_inventory() {
        let json = r#"[{"netdev":"ens16v0","label":"Load the driver","detail":"do X first"}]"#;
        let map = parse_nic_advice(json);
        assert_eq!(
            map.get("ens16v0"),
            Some(&NicAdvice {
                label: "Load the driver".into(),
                detail: "do X first".into(),
            })
        );
        // Garbage / empty / missing fields degrade to no advisories.
        assert!(parse_nic_advice("not json").is_empty());
        assert!(parse_nic_advice("[]").is_empty());
        assert!(parse_nic_advice(r#"[{"netdev":"x"}]"#).is_empty());
    }
}
