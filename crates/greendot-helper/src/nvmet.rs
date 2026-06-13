//! Renders the desired NVMe-oF state to nvmetcli's JSON and applies it with
//! `nvmetcli restore` (config fed on stdin).

use crate::cmd::TaskSpec;
use greendot_proto::{NvmetDesired, NvmetPortSpec, NvmetSubsysSpec, Transport};
use serde_json::{Value, json};

pub fn apply_spec(desired: &NvmetDesired) -> TaskSpec {
    TaskSpec::with_config_file("nvmetcli", vec!["restore".into()], render(desired))
}

pub fn render(desired: &NvmetDesired) -> String {
    serde_json::to_string_pretty(&document(desired)).expect("nvmet config serializes")
}

fn document(desired: &NvmetDesired) -> Value {
    let mut hosts: Vec<String> = desired
        .subsystems
        .iter()
        .flat_map(|s| s.allowed_hosts.iter().map(|h| h.to_string()))
        .collect();
    hosts.sort();
    hosts.dedup();
    json!({
        "hosts": hosts.iter().map(|h| json!({ "nqn": h })).collect::<Vec<_>>(),
        "subsystems": desired.subsystems.iter().map(subsystem).collect::<Vec<_>>(),
        "ports": desired.ports.iter().map(port).collect::<Vec<_>>(),
    })
}

fn subsystem(s: &NvmetSubsysSpec) -> Value {
    json!({
        "nqn": s.nqn.to_string(),
        "attr": { "allow_any_host": if s.allow_any_host { "1" } else { "0" } },
        "allowed_hosts": s.allowed_hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
        "namespaces": s.namespaces.iter().map(|ns| json!({
            "nsid": ns.nsid,
            "enable": 1,
            "device": { "path": ns.device_path.to_string() },
        })).collect::<Vec<_>>(),
    })
}

fn port(p: &NvmetPortSpec) -> Value {
    let (adrfam, traddr, trsvcid) = match p.trtype {
        Transport::Loop => (String::new(), String::new(), String::new()),
        _ => (
            if p.traddr.is_ipv6() { "ipv6" } else { "ipv4" }.to_string(),
            p.traddr.to_string(),
            p.trsvcid.to_string(),
        ),
    };
    json!({
        "portid": p.id,
        "addr": {
            "adrfam": adrfam,
            "traddr": traddr,
            "treq": "not specified",
            "trsvcid": trsvcid,
            "trtype": p.trtype.as_str(),
        },
        "referrals": [],
        "subsystems": p.subsystems.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use greendot_proto::{DevicePath, Nqn, NvmetNsSpec};

    fn desired() -> NvmetDesired {
        NvmetDesired {
            subsystems: vec![NvmetSubsysSpec {
                nqn: Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap(),
                allow_any_host: false,
                allowed_hosts: vec![Nqn::new("nqn.2014-08.org.nvmexpress:host1").unwrap()],
                namespaces: vec![NvmetNsSpec {
                    nsid: 1,
                    device_path: DevicePath::new("/dev/zvol/tank/vm1").unwrap(),
                }],
            }],
            ports: vec![NvmetPortSpec {
                id: 1,
                trtype: Transport::Rdma,
                traddr: "10.0.0.5".parse().unwrap(),
                trsvcid: 4420,
                subsystems: vec![Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap()],
            }],
        }
    }

    #[test]
    fn renders_nvmetcli_document() {
        let spec = apply_spec(&desired());
        assert_eq!(spec.command, "nvmetcli");
        assert_eq!(spec.args, ["restore"].map(String::from).to_vec());
        assert!(spec.stdin_to_file, "config passed as a file argument");
        let doc: Value = serde_json::from_str(spec.stdin.as_ref().unwrap()).unwrap();

        assert_eq!(doc["hosts"][0]["nqn"], "nqn.2014-08.org.nvmexpress:host1");
        let subsys = &doc["subsystems"][0];
        assert_eq!(subsys["nqn"], "nqn.2026-06.io.greendot:vm1");
        assert_eq!(subsys["attr"]["allow_any_host"], "0");
        assert_eq!(
            subsys["allowed_hosts"][0],
            "nqn.2014-08.org.nvmexpress:host1"
        );
        assert_eq!(subsys["namespaces"][0]["nsid"], 1);
        assert_eq!(subsys["namespaces"][0]["enable"], 1);
        assert_eq!(
            subsys["namespaces"][0]["device"]["path"],
            "/dev/zvol/tank/vm1"
        );
        let p = &doc["ports"][0];
        assert_eq!(p["portid"], 1);
        assert_eq!(p["addr"]["trtype"], "rdma");
        assert_eq!(p["addr"]["adrfam"], "ipv4");
        assert_eq!(p["addr"]["traddr"], "10.0.0.5");
        assert_eq!(p["addr"]["trsvcid"], "4420");
        assert_eq!(p["subsystems"][0], "nqn.2026-06.io.greendot:vm1");
    }

    #[test]
    fn empty_desired_renders_empty_lists() {
        let doc: Value = serde_json::from_str(&render(&NvmetDesired::default())).unwrap();
        assert_eq!(doc["subsystems"], json!([]));
        assert_eq!(doc["ports"], json!([]));
        assert_eq!(doc["hosts"], json!([]));
    }
}
