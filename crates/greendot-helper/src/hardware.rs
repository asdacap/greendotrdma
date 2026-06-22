//! NIC hardware vendors behind one trait. All vendor-specific knowledge — the
//! PCI fingerprint, the privileged `devlink` commands to probe and turn on
//! hardware RoCE, and the UI label — lives in impls of [`NetworkHardware`].
//! Adding a vendor is one impl plus a `REGISTRY` entry; nothing in greendot-web
//! changes. The web only ever asks two vendor-agnostic questions (which NICs are
//! RoCE-capable hardware, and "enable RoCE on this NIC"); this module answers
//! both off sysfs and the registry.

use crate::cmd::{EventSink, TaskSpec, run_cmd};
use greendot_proto::{NetdevName, PciAddress, TaskEvent};
use std::io;
use std::path::Path;
use std::process::Command;

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
    /// Read-only probe of the RoCE-enable parameter.
    fn probe(&self, pci: &PciAddress) -> TaskSpec;
    /// Interpret the probe's stdout into a vendor-neutral verdict.
    fn interpret(&self, stdout: &str) -> RoceState;
    /// The privileged steps, in order, to turn hardware RoCE on.
    fn enable(&self, pci: &PciAddress) -> Vec<TaskSpec>;
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

/// Every supported NIC vendor. Append one entry to add a vendor.
static REGISTRY: &[&dyn NetworkHardware] = &[&Mellanox];

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

/// A trimmed sysfs value, `None` if missing or empty.
fn read_trimmed(path: &Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// A physical Ethernet NIC: has a PCI `device` and ARPHRD_ETHER (`type` == 1).
fn is_ethernet(net_dir: &Path) -> bool {
    net_dir.join("device").symlink_metadata().is_ok()
        && read_trimmed(&net_dir.join("type")).as_deref() == Some("1")
}

/// PCI vendor id from the netdev's `device/vendor`, e.g. `"0x15b3"`.
fn vendor_id(net_dir: &Path) -> Option<String> {
    read_trimmed(&net_dir.join("device/vendor"))
}

/// PCI address from the netdev's `device` symlink, e.g. `0000:00:10.0`.
fn pci_of(net_dir: &Path) -> Option<PciAddress> {
    let target = std::fs::read_link(net_dir.join("device")).ok()?;
    let name = target.file_name()?.to_string_lossy();
    PciAddress::new(name.as_ref()).ok()
}

/// The vendor impl handling `netdev`, plus its PCI address — when both the vendor
/// matches a registry impl and a PCI address is readable.
fn detect(net_root: &Path, netdev: &str) -> Option<(&'static dyn NetworkHardware, PciAddress)> {
    let net_dir = net_root.join(netdev);
    let id = vendor_id(&net_dir)?;
    let hw = REGISTRY.iter().copied().find(|hw| hw.matches(&id))?;
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
            let id = is_ethernet(&net_dir)
                .then(|| vendor_id(&net_dir))
                .flatten()?;
            let hw = REGISTRY.iter().copied().find(|hw| hw.matches(&id))?;
            Some((
                entry.file_name().to_string_lossy().into_owned(),
                hw.vendor(),
            ))
        })
        .collect();
    out.sort();
    out
}

// ---- streamed handlers (collected/recorded by the web like NfsReport/NfsApply) ----

/// Streams the RoCE-capable NIC inventory as one JSON line — a privileged read
/// the web collects: `[{"netdev":"ens16","vendor":"Mellanox"}, …]`.
pub fn report_capable_into(net_root: &Path, sink: &mut dyn EventSink) -> io::Result<()> {
    sink.emit(TaskEvent::Started {
        command: "roce".into(),
        args: vec!["capable".into()],
        stdin: None,
    })?;
    let nics: Vec<serde_json::Value> = roce_capable(net_root)
        .into_iter()
        .map(|(netdev, vendor)| serde_json::json!({ "netdev": netdev, "vendor": vendor }))
        .collect();
    sink.emit(TaskEvent::Stdout {
        data: serde_json::Value::Array(nics).to_string(),
    })?;
    sink.emit(TaskEvent::Finished {
        exit: 0,
        ok: true,
        error: None,
    })
}

/// Turns on hardware RoCE for `netdev`: detect the vendor, probe its RoCE-enable
/// parameter, and — only if present and off — set it and reload the device, all
/// streamed as one task. The reload briefly drops the NIC.
pub fn enable_into(
    net_root: &Path,
    netdev: &NetdevName,
    sink: &mut dyn EventSink,
) -> io::Result<()> {
    sink.emit(TaskEvent::Started {
        command: "roce".into(),
        args: vec!["enable".into(), netdev.to_string()],
        stdin: None,
    })?;
    let Some((hw, pci)) = detect(net_root, netdev.as_str()) else {
        return finish(
            sink,
            false,
            Some(format!("{netdev} is not RoCE-capable hardware")),
        );
    };

    // Confirm the parameter is present and currently off before reloading.
    let probe = hw.probe(&pci);
    sink.emit(TaskEvent::Stdout {
        data: format!("$ {} {}\n", probe.command, probe.args.join(" ")),
    })?;
    let stdout = match Command::new(&probe.command).args(&probe.args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return finish(
                sink,
                false,
                Some(
                    "devlink is not installed — install the iproute2 package \
                     (Tasks → Install dependencies)"
                        .into(),
                ),
            );
        }
        Err(e) => return finish(sink, false, Some(format!("failed to start devlink: {e}"))),
    };
    match hw.interpret(&stdout) {
        RoceState::AlreadyEnabled => {
            sink.emit(TaskEvent::Stdout {
                data: format!("RoCE is already enabled on {pci}\n"),
            })?;
            return finish(sink, true, None);
        }
        RoceState::Unavailable => {
            return finish(
                sink,
                false,
                Some(format!(
                    "{pci} has no settable enable_roce parameter — on an SR-IOV VF, \
                     enable RoCE on the host/PF"
                )),
            );
        }
        RoceState::Disabled => {}
    }

    let mut ok = true;
    let mut first_err: Option<String> = None;
    for spec in hw.enable(&pci) {
        let (success, msg) = run_cmd(&spec.command, &spec.args, sink)?;
        if !success {
            ok = false;
            first_err.get_or_insert(msg);
        }
    }
    finish(sink, ok, first_err)
}

fn finish(sink: &mut dyn EventSink, ok: bool, err: Option<String>) -> io::Result<()> {
    sink.emit(TaskEvent::Finished {
        exit: if ok { 0 } else { 1 },
        ok,
        error: (!ok).then(|| err.unwrap_or_else(|| "RoCE enable failed".into())),
    })
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
        f.netdev("ens16", "1", Some(("0000:00:10.0", "0x15b3"))); // Mellanox
        f.netdev("eth0", "1", Some(("0000:01:00.0", "0x10ec"))); // Realtek
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
