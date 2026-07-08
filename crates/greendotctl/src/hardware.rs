//! NIC hardware vendors behind one trait. All vendor-specific knowledge — the
//! PCI fingerprint, the privileged `devlink` commands to probe and turn on
//! hardware RoCE, per-NIC diagnostic advisories, and the UI label — lives in
//! impls of [`NetworkHardware`]. Adding a vendor is one impl plus a `REGISTRY`
//! entry; nothing in greendot-web changes. The web only ever asks
//! vendor-agnostic questions (which NICs are RoCE-capable hardware, "enable
//! RoCE on this NIC", and per-NIC advisories); this module answers them off
//! sysfs and the registry.

use crate::cmd::{TaskSpec, capture_into, run_into};
use crate::util::read_trimmed;
use greendot_proto::{NetdevName, PciAddress, SubStatus, SubTask};
use std::io::{self, Write};
use std::path::Path;

/// Default sysfs netdev root (overridable in tests).
pub const NET_ROOT: &str = "/sys/class/net";

/// Verdict from reading a vendor's RoCE-enable parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoceState {
    /// The parameter exists and RoCE is currently off — safe to enable.
    Disabled,
    /// The parameter exists and RoCE is already on — nothing to do.
    AlreadyEnabled,
    /// The parameter is absent (e.g. an SR-IOV VF that can't self-enable) — the
    /// enable must not be attempted.
    Unavailable,
}

/// One NIC vendor/family. The only place vendor-specific knowledge lives.
pub trait NetworkHardware: Sync {
    /// Short vendor label for the UI, e.g. `"Mellanox"`.
    fn vendor(&self) -> &'static str;
    /// True if this impl handles the given PCI vendor id, e.g. `"0x15b3"`.
    fn matches(&self, vendor_id: &str) -> bool;
    /// Whether this NIC (its sysfs dir) supports the one-click
    /// [`probe`](Self::probe)/[`enable`](Self::enable) flow — drives the
    /// RoCE-capable inventory and vendor-detect for `EnableRoce`.
    /// Advisory-only vendors return false.
    fn enableable(&self, net_dir: &Path) -> bool {
        let _ = net_dir;
        true
    }
    /// Read-only probe of the RoCE-enable parameter. Only reached through
    /// [`enableable`](Self::enableable) NICs.
    fn probe(&self, pci: &PciAddress) -> TaskSpec;
    /// Interpret the probe's stdout into a vendor-neutral verdict.
    fn interpret(&self, stdout: &str) -> RoceState;
    /// The privileged steps, in order, to turn hardware RoCE on.
    fn enable(&self, pci: &PciAddress) -> Vec<TaskSpec>;
    /// Per-NIC RDMA advisory `(label, detail)` for a NIC this vendor owns —
    /// vendor situations invisible from the NIC itself (e.g. host-side driver
    /// ordering for SR-IOV VFs). Rendered opaquely by the web. Default: none.
    fn advice(&self, net_dir: &Path) -> Option<(&'static str, &'static str)> {
        let _ = net_dir;
        None
    }
}

struct Mellanox;

impl NetworkHardware for Mellanox {
    fn vendor(&self) -> &'static str {
        "Mellanox"
    }

    /// Mellanox PCI vendor id (ConnectX family).
    fn matches(&self, vendor_id: &str) -> bool {
        vendor_id == "0x15b3"
    }

    /// `devlink dev param show pci/<pci> -j` — read `enable_roce` before the fix.
    fn probe(&self, pci: &PciAddress) -> TaskSpec {
        devlink(&["dev", "param", "show", &format!("pci/{pci}"), "-j"])
    }

    fn interpret(&self, stdout: &str) -> RoceState {
        match enable_roce_from_json(stdout) {
            Some(false) => RoceState::Disabled,
            Some(true) => RoceState::AlreadyEnabled,
            None => RoceState::Unavailable,
        }
    }

    fn enable(&self, pci: &PciAddress) -> Vec<TaskSpec> {
        vec![
            // `devlink dev param set pci/<pci> name enable_roce value true cmode
            // driverinit`. Hard-coded to `enable_roce` so a compromised web side
            // can't name an arbitrary param.
            devlink(&[
                "dev",
                "param",
                "set",
                &format!("pci/{pci}"),
                "name",
                "enable_roce",
                "value",
                "true",
                "cmode",
                "driverinit",
            ]),
            // `devlink dev reload pci/<pci>` — re-init so the driverinit param
            // takes effect. Resets the device's netdevs.
            devlink(&["dev", "reload", &format!("pci/{pci}")]),
        ]
    }
}

/// Intel NICs. Advisory-only today: no Intel family has a supported one-click
/// enable flow, but irdma-capable SR-IOV VFs get a diagnostic advisory (the
/// host-side driver-ordering requirement is invisible from the VF).
struct Intel;

/// PCI device ids of Intel Ethernet *Adaptive Virtual Functions* (`iavf`) — the
/// SR-IOV VFs of the irdma-capable families (E810/`ice`, X7xx/`i40e`). These
/// VFs get RDMA only when the host loads `irdma` before the VF count is set;
/// non-RDMA Intel VFs (igb/ixgbe) use other ids and are deliberately excluded.
/// One entry today; extend the slice to cover more irdma VF ids.
const INTEL_IRDMA_VF_IDS: &[&str] = &["0x1889"];

/// Human advisory for a detected Intel irdma VF that has no RDMA.
const IRDMA_VF_LABEL: &str = "SR-IOV VF: host must load the RDMA driver before creating VFs";
const IRDMA_VF_DETAIL: &str = "This is an Intel Ethernet Adaptive virtual function. RDMA on the VF \
     works only if the host loads the irdma driver (modprobe irdma) BEFORE the \
     VF count is set via sriov_numvfs. VFs created before irdma is loaded come \
     up without RDMA — on the host, load irdma, then re-create the VFs.";

impl NetworkHardware for Intel {
    fn vendor(&self) -> &'static str {
        "Intel"
    }

    /// Intel's PCI vendor id.
    fn matches(&self, vendor_id: &str) -> bool {
        vendor_id == "0x8086"
    }

    /// No supported one-click enable flow — advisory-only.
    fn enableable(&self, _net_dir: &Path) -> bool {
        false
    }

    // probe/interpret/enable are unreachable while `enableable` is false; they
    // state the honest answer anyway (no settable parameter, nothing to run).
    fn probe(&self, pci: &PciAddress) -> TaskSpec {
        devlink(&["dev", "param", "show", &format!("pci/{pci}"), "-j"])
    }

    fn interpret(&self, _stdout: &str) -> RoceState {
        RoceState::Unavailable
    }

    fn enable(&self, _pci: &PciAddress) -> Vec<TaskSpec> {
        Vec::new()
    }

    fn advice(&self, net_dir: &Path) -> Option<(&'static str, &'static str)> {
        let dev = device_id(net_dir)?;
        INTEL_IRDMA_VF_IDS
            .contains(&dev.as_str())
            .then_some((IRDMA_VF_LABEL, IRDMA_VF_DETAIL))
    }
}

/// Every supported NIC vendor. Append one entry to add a vendor.
static REGISTRY: &[&dyn NetworkHardware] = &[&Mellanox, &Intel];

fn devlink(args: &[&str]) -> TaskSpec {
    TaskSpec::new("devlink", args.iter().map(|s| s.to_string()).collect())
}

/// Parse `devlink dev param show -j` for `enable_roce`: `Some(true)`/`Some(false)`
/// if present, `None` if absent (e.g. a VF that can't self-enable, or a parse
/// error). devlink emits either `{"param":{"pci/<addr>":[…]}}` or `{"param":[…]}`.
fn enable_roce_from_json(json: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let param = v.get("param")?;
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

// ---- sysfs detection (vendor-neutral readers; the vendor decision is the
// registry's `matches`) ----

/// A physical Ethernet NIC: has a PCI `device` and ARPHRD_ETHER (`type` == 1).
fn is_ethernet(net_dir: &Path) -> bool {
    net_dir.join("device").symlink_metadata().is_ok()
        && read_trimmed(&net_dir.join("type")).as_deref() == Some("1")
}

/// PCI vendor id from the netdev's `device/vendor`, e.g. `"0x15b3"`.
fn vendor_id(net_dir: &Path) -> Option<String> {
    read_trimmed(&net_dir.join("device/vendor"))
}

/// PCI device id from the netdev's `device/device`, e.g. `"0x1889"`.
fn device_id(net_dir: &Path) -> Option<String> {
    read_trimmed(&net_dir.join("device/device"))
}

/// PCI address from the netdev's `device` symlink, e.g. `0000:00:10.0`.
fn pci_of(net_dir: &Path) -> Option<PciAddress> {
    let target = std::fs::read_link(net_dir.join("device")).ok()?;
    let name = target.file_name()?.to_string_lossy();
    PciAddress::new(name.as_ref()).ok()
}

/// The registry impl owning `netdev`'s PCI vendor id, if any.
fn vendor_impl(net_dir: &Path) -> Option<&'static dyn NetworkHardware> {
    let id = vendor_id(net_dir)?;
    REGISTRY.iter().copied().find(|hw| hw.matches(&id))
}

/// The vendor impl handling `netdev` for the enable flow, plus its PCI address
/// — when the vendor matches a registry impl, the NIC is enableable, and a PCI
/// address is readable.
fn detect(net_root: &Path, netdev: &str) -> Option<(&'static dyn NetworkHardware, PciAddress)> {
    let net_dir = net_root.join(netdev);
    let hw = vendor_impl(&net_dir).filter(|hw| hw.enableable(&net_dir))?;
    Some((hw, pci_of(&net_dir)?))
}

/// Every ethernet NIC whose PCI vendor matches a registry impl: `(netdev,
/// vendor)`. The web overlays this onto its structural classification to mark a
/// NIC RoCE-capable-but-disabled (when it also has no RDMA device).
pub fn roce_capable(net_root: &Path) -> Vec<(String, &'static str)> {
    let Ok(entries) = std::fs::read_dir(net_root) else {
        return Vec::new();
    };
    let mut out: Vec<(String, &'static str)> = entries
        .flatten()
        .filter_map(|entry| {
            let net_dir = entry.path();
            let hw = is_ethernet(&net_dir)
                .then(|| vendor_impl(&net_dir))
                .flatten()
                .filter(|hw| hw.enableable(&net_dir))?;
            Some((
                entry.file_name().to_string_lossy().into_owned(),
                hw.vendor(),
            ))
        })
        .collect();
    out.sort();
    out
}

/// Per-NIC RDMA advisories as `(netdev, label, detail)` — the vendor-specific
/// explanations the web renders opaquely on the Diagnose page. Each ethernet
/// NIC is matched to its registry vendor and asked for
/// [`NetworkHardware::advice`].
pub fn nic_rdma_advice(net_root: &Path) -> Vec<(String, &'static str, &'static str)> {
    let Ok(entries) = std::fs::read_dir(net_root) else {
        return Vec::new();
    };
    let mut out: Vec<(String, &'static str, &'static str)> = entries
        .flatten()
        .filter_map(|entry| {
            let net_dir = entry.path();
            let hw = is_ethernet(&net_dir)
                .then(|| vendor_impl(&net_dir))
                .flatten()?;
            let (label, detail) = hw.advice(&net_dir)?;
            Some((
                entry.file_name().to_string_lossy().into_owned(),
                label,
                detail,
            ))
        })
        .collect();
    out.sort();
    out
}

/// Turns on hardware RoCE for `netdev`: detect the vendor, probe its RoCE-enable
/// parameter, and — only if present and off — set it and reload the device, all
/// streamed into the caller-opened subtask. The reload briefly drops the NIC.
pub fn enable_into(
    net_root: &Path,
    netdev: &NetdevName,
    sub: &mut SubTask,
) -> io::Result<SubStatus> {
    let Some((hw, pci)) = detect(net_root, netdev.as_str()) else {
        let msg = format!("{netdev} is not RoCE-capable hardware");
        writeln!(sub.stderr(), "{msg}")?;
        sub.set_result(1, Some(msg));
        return Ok(SubStatus::Failed);
    };

    // Confirm the parameter is present and currently off before reloading.
    // The probe's output streams into the subtask so a wrong verdict can be
    // diagnosed from the task page.
    let stdout = match capture_into(sub, &hw.probe(&pci))? {
        Ok(stdout) => {
            sub.stdout().write_all(stdout.as_bytes())?;
            stdout
        }
        Err(msg) => {
            sub.set_result(1, Some(msg));
            return Ok(SubStatus::Failed);
        }
    };
    match hw.interpret(&stdout) {
        RoceState::AlreadyEnabled => {
            writeln!(sub.stdout(), "RoCE is already enabled on {pci}")?;
            return Ok(SubStatus::Success);
        }
        RoceState::Unavailable => {
            let msg = format!(
                "{pci} has no settable enable_roce parameter — on an SR-IOV VF, \
                 enable RoCE on the host/PF"
            );
            writeln!(sub.stderr(), "{msg}")?;
            sub.set_result(1, Some(msg));
            return Ok(SubStatus::Failed);
        }
        RoceState::Disabled => {}
    }

    let mut acc: Option<SubStatus> = None;
    for spec in hw.enable(&pci) {
        acc = Some(SubStatus::fold(acc, run_into(sub, &spec)?));
    }
    Ok(acc.unwrap_or(SubStatus::Success))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a fake `/sys/class/net` tree: a netdev with ARPHRD `type` and, when
    /// `vendor` is set, a PCI `device` symlink to a dir carrying that vendor id.
    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("gd-hw-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("net")).unwrap();
            std::fs::create_dir_all(root.join("pci")).unwrap();
            Fixture { root }
        }

        /// A netdev with the given ARPHRD `type` and, when `pci` is set, a PCI
        /// `device` symlink to a dir carrying that `(pci_addr, vendor, device)`.
        fn netdev(&self, name: &str, type_: &str, pci: Option<(&str, &str, &str)>) {
            let dir = self.root.join("net").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("type"), format!("{type_}\n")).unwrap();
            if let Some((pci, vendor, device)) = pci {
                let pci_dir = self.root.join("pci").join(pci);
                std::fs::create_dir_all(&pci_dir).unwrap();
                std::fs::write(pci_dir.join("vendor"), format!("{vendor}\n")).unwrap();
                std::fs::write(pci_dir.join("device"), format!("{device}\n")).unwrap();
                std::os::unix::fs::symlink(&pci_dir, dir.join("device")).unwrap();
            }
        }

        fn net_root(&self) -> std::path::PathBuf {
            self.root.join("net")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn detect_and_inventory_match_only_registered_vendors() {
        let f = Fixture::new("detect");
        f.netdev("ens16", "1", Some(("0000:00:10.0", "0x15b3", "0x1017"))); // Mellanox
        f.netdev("eth0", "1", Some(("0000:01:00.0", "0x10ec", "0x8168"))); // Realtek
        f.netdev("br0", "1", None); // virtual (no PCI device)

        let (hw, pci) = detect(&f.net_root(), "ens16").expect("Mellanox detected");
        assert_eq!(hw.vendor(), "Mellanox");
        assert_eq!(pci.as_str(), "0000:00:10.0");
        assert!(detect(&f.net_root(), "eth0").is_none(), "Realtek unmatched");
        assert!(detect(&f.net_root(), "br0").is_none(), "no PCI device");

        assert_eq!(
            roce_capable(&f.net_root()),
            vec![("ens16".to_owned(), "Mellanox")]
        );
    }

    #[test]
    fn intel_advice_matches_only_the_adaptive_vf_id_and_never_enables() {
        let f = Fixture::new("ivf");
        // Intel Adaptive VF (8086:1889) → an advisory.
        f.netdev("ens16v0", "1", Some(("0000:00:10.1", "0x8086", "0x1889")));
        // Intel non-RDMA VF (different device id) → no advisory.
        f.netdev("eth2", "1", Some(("0000:02:10.1", "0x8086", "0x10ed")));
        // Non-Intel vendor with the same device id → no advisory (vendor gates).
        f.netdev("eth3", "1", Some(("0000:03:00.0", "0x15b3", "0x1889")));
        // Virtual interface (no PCI device) → no advisory.
        f.netdev("br0", "1", None);

        let advice = nic_rdma_advice(&f.net_root());
        assert_eq!(advice.len(), 1);
        assert_eq!(advice[0].0, "ens16v0");
        assert_eq!(advice[0].1, IRDMA_VF_LABEL);
        assert!(advice[0].2.contains("sriov_numvfs"), "{}", advice[0].2);

        // Advisory-only vendor: Intel NICs are neither in the RoCE-capable
        // inventory nor detected for the enable flow (Mellanox eth3 is).
        assert_eq!(
            roce_capable(&f.net_root()),
            vec![("eth3".to_owned(), "Mellanox")]
        );
        assert!(detect(&f.net_root(), "ens16v0").is_none());
        assert!(detect(&f.net_root(), "eth3").is_some());
    }

    #[test]
    fn mellanox_probe_enable_and_interpret() {
        let pci = PciAddress::new("0000:00:10.0").unwrap();
        let probe = Mellanox.probe(&pci);
        assert_eq!(probe.command, "devlink");
        assert_eq!(
            probe.args,
            ["dev", "param", "show", "pci/0000:00:10.0", "-j"].map(String::from)
        );
        let steps = Mellanox.enable(&pci);
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0].args,
            [
                "dev",
                "param",
                "set",
                "pci/0000:00:10.0",
                "name",
                "enable_roce",
                "value",
                "true",
                "cmode",
                "driverinit"
            ]
            .map(String::from)
        );
        assert_eq!(
            steps[1].args,
            ["dev", "reload", "pci/0000:00:10.0"].map(String::from)
        );

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
        assert_eq!(Mellanox.interpret(disabled), RoceState::Disabled);
        assert_eq!(Mellanox.interpret(enabled), RoceState::AlreadyEnabled);
        assert_eq!(Mellanox.interpret(absent), RoceState::Unavailable);
        assert_eq!(Mellanox.interpret("not json"), RoceState::Unavailable);
    }
}
