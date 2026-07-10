//! Mellanox (ConnectX family): the one-click `devlink enable_roce` flow.

use super::{NetworkHardware, RoceState, devlink};
use crate::cmd::TaskSpec;
use greendot_proto::PciAddress;

pub(super) struct Mellanox;

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

    /// `mlx5_ib` normally auto-loads off the mlx5_core auxiliary device, but
    /// not on minimal installs without the udev modalias path — an explicit
    /// load is harmless when it already did.
    fn rdma_modules(&self) -> &'static [&'static str] {
        &["mlx5_ib"]
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

#[cfg(test)]
mod tests {
    use super::*;

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
