//! Renders the desired iSCSI/LIO state to targetcli's JSON and applies it with
//! `targetctl restore` (config fed on stdin).

use crate::cmd::TaskSpec;
use greendot_proto::{LioDesired, LioTargetSpec};
use serde_json::{Value, json};

pub fn apply_spec(desired: &LioDesired) -> TaskSpec {
    TaskSpec::with_config_file("targetctl", vec!["restore".into()], render(desired))
}

pub fn render(desired: &LioDesired) -> String {
    serde_json::to_string_pretty(&document(desired)).expect("lio config serializes")
}

fn document(d: &LioDesired) -> Value {
    json!({
        "fabric_modules": [],
        "storage_objects": d.backstores.iter().map(|b| json!({
            "name": b.name.to_string(),
            "plugin": "block",
            "dev": b.device_path.to_string(),
            "readonly": false,
            "write_back": true,
        })).collect::<Vec<_>>(),
        "targets": d.targets.iter().map(target).collect::<Vec<_>>(),
    })
}

fn target(t: &LioTargetSpec) -> Value {
    let luns: Vec<Value> = t
        .luns
        .iter()
        .map(|l| {
            json!({
                "index": l.lun,
                "storage_object": format!("/backstores/block/{}", l.backstore),
            })
        })
        .collect();
    let mapped_luns: Vec<Value> = t
        .luns
        .iter()
        .map(|l| json!({ "index": l.lun, "tpg_lun": l.lun, "write_protect": false }))
        .collect();
    let node_acls: Vec<Value> = if t.demo_mode {
        vec![]
    } else {
        t.acls
            .iter()
            .map(|a| {
                json!({
                    "node_wwn": a.to_string(),
                    "mapped_luns": mapped_luns,
                    "attributes": {},
                    "auth": {},
                })
            })
            .collect()
    };
    json!({
        "fabric": "iscsi",
        "wwn": t.iqn.to_string(),
        "tpgs": [{
            "tag": 1,
            "enable": t.enabled,
            "attributes": {
                "authentication": 0,
                "generate_node_acls": i32::from(t.demo_mode),
                "cache_dynamic_acls": i32::from(t.demo_mode),
                "demo_mode_write_protect": 0,
            },
            "parameters": {},
            "luns": luns,
            "portals": t.portals.iter().map(|p| json!({
                "ip_address": p.addr.to_string(),
                "port": p.port,
                "iser": p.iser,
            })).collect::<Vec<_>>(),
            "node_acls": node_acls,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use greendot_proto::{
        BackstoreName, DevicePath, Iqn, LioBackstoreSpec, LioLunSpec, LioPortalSpec,
    };

    fn desired(demo_mode: bool) -> LioDesired {
        LioDesired {
            backstores: vec![LioBackstoreSpec {
                name: BackstoreName::new("vm1").unwrap(),
                device_path: DevicePath::new("/dev/zvol/tank/vm1").unwrap(),
            }],
            targets: vec![LioTargetSpec {
                iqn: Iqn::new("iqn.2026-06.io.greendot:vm1").unwrap(),
                enabled: true,
                demo_mode,
                luns: vec![LioLunSpec {
                    lun: 0,
                    backstore: BackstoreName::new("vm1").unwrap(),
                }],
                portals: vec![LioPortalSpec {
                    addr: "10.0.0.5".parse().unwrap(),
                    port: 3260,
                    iser: true,
                }],
                acls: vec![Iqn::new("iqn.1993-08.org.debian:01:abc").unwrap()],
            }],
        }
    }

    #[test]
    fn renders_targetctl_document_with_acls() {
        let spec = apply_spec(&desired(false));
        assert_eq!(spec.command, "targetctl");
        assert_eq!(spec.args, ["restore"].map(String::from).to_vec());
        assert!(spec.stdin_to_file, "config passed as a file argument");
        let doc: Value = serde_json::from_str(spec.stdin.as_ref().unwrap()).unwrap();

        let so = &doc["storage_objects"][0];
        assert_eq!(so["name"], "vm1");
        assert_eq!(so["plugin"], "block");
        assert_eq!(so["dev"], "/dev/zvol/tank/vm1");
        let tpg = &doc["targets"][0]["tpgs"][0];
        assert_eq!(doc["targets"][0]["wwn"], "iqn.2026-06.io.greendot:vm1");
        assert_eq!(tpg["enable"], true);
        assert_eq!(tpg["attributes"]["generate_node_acls"], 0);
        assert_eq!(tpg["luns"][0]["storage_object"], "/backstores/block/vm1");
        assert_eq!(tpg["portals"][0]["ip_address"], "10.0.0.5");
        assert_eq!(tpg["portals"][0]["iser"], true);
        assert_eq!(
            tpg["node_acls"][0]["node_wwn"],
            "iqn.1993-08.org.debian:01:abc"
        );
        assert_eq!(tpg["node_acls"][0]["mapped_luns"][0]["tpg_lun"], 0);
    }

    #[test]
    fn demo_mode_enables_generated_acls_and_drops_explicit_ones() {
        let doc: Value = serde_json::from_str(&render(&desired(true))).unwrap();
        let tpg = &doc["targets"][0]["tpgs"][0];
        assert_eq!(tpg["attributes"]["generate_node_acls"], 1);
        assert_eq!(tpg["attributes"]["cache_dynamic_acls"], 1);
        assert_eq!(tpg["node_acls"], json!([]));
    }
}
