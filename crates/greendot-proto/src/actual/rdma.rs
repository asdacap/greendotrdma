//! RDMA device / peer DTOs and the pure parsers over tool output. Enumeration
//! from /sys/class/infiniband lives in the daemon-side reader
//! (`greendot_reconcile::actual::rdma`); the address-serving check and the
//! `rdma resource show` JSON parser are pure and live here.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdmaDev {
    pub name: String,
    pub netdev: Option<String>,
    pub active: bool,
    /// IP addresses of the backing netdev — empty when inactive or netdev-less.
    pub addrs: Vec<IpAddr>,
}

/// Whether an nvmet/LIO listen address can actually be served via RDMA.
pub fn addr_served_by_rdma(traddr: &str, devs: &[RdmaDev]) -> bool {
    let Ok(addr) = traddr.parse::<IpAddr>() else {
        return false;
    };
    if addr.is_unspecified() {
        return devs.iter().any(|d| !d.addrs.is_empty());
    }
    devs.iter().any(|d| d.addrs.contains(&addr))
}

/// One live RDMA connection (`rdma resource show cm_id`). This is the only
/// NVMe-oF connection signal on a kernel without CONFIG_NVME_TARGET_DEBUGFS:
/// peer IPs at the RDMA-transport level, with no NQN/hostnqn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdmaPeer {
    /// Local listen address (the target side of the connection).
    pub src_addr: String,
    /// Local listen port — attributes the peer to a transport (4420 → NVMe-oF,
    /// 3260 → iSER). `None` when the tool didn't expose a parseable port.
    pub src_port: Option<u16>,
    /// Remote peer address (the connected client).
    pub dst_addr: String,
    pub state: String,
}

/// Split a `rdma`-reported address that may carry an embedded port: bracketed
/// IPv6 `[::1]:4420`, or IPv4 `10.0.0.5:4420`. A bare IPv6 (no brackets, no
/// port) returns `None` so we don't mistake one of its colons for a port.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        return Some((addr.to_owned(), port.parse().ok()?));
    }
    let (addr, port) = s.rsplit_once(':')?;
    if addr.contains(':') {
        return None; // bare IPv6, no port
    }
    Some((addr.to_owned(), port.parse().ok()?))
}

/// Extract (address, port) from a cm_id entry: prefer a separate numeric port
/// field, else fall back to a port embedded in the address string.
fn addr_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> (String, Option<u16>) {
    let raw = obj
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let port_key = key.replace("addr", "port");
    let port = obj.get(&port_key).and_then(|v| {
        v.as_u64()
            .map(|p| p as u16)
            .or_else(|| v.as_str()?.parse().ok())
    });
    match port {
        Some(p) => (raw, Some(p)),
        None => match split_host_port(&raw) {
            Some((addr, p)) => (addr, Some(p)),
            None => (raw, None),
        },
    }
}

/// Parse `rdma -j resource show cm_id` output into connected peers. Defensive:
/// any shape mismatch yields an empty list (the caller then shows nothing).
pub fn peers_from_json(json: &str) -> Vec<RdmaPeer> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    // `... show cm_id` yields an array; `... show` (all types) yields an object
    // keyed by resource type. Accept either.
    let empty = Vec::new();
    let entries = match &value {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(map) => map.values().find_map(|v| v.as_array()).unwrap_or(&empty),
        _ => &empty,
    };
    entries
        .iter()
        .filter_map(|e| {
            let obj = e.as_object()?;
            let (src_addr, src_port) = addr_field(obj, "src-addr");
            let (dst_addr, _) = addr_field(obj, "dst-addr");
            if dst_addr.is_empty() {
                return None; // no peer ⇒ nothing to show
            }
            Some(RdmaPeer {
                src_addr,
                src_port,
                dst_addr,
                state: obj
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn dev(addrs: &[&str]) -> RdmaDev {
        RdmaDev {
            name: "rxe0".into(),
            netdev: Some("eth0".into()),
            active: true,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    #[rstest]
    #[case::exact_match("10.0.0.5", &["10.0.0.5"], true)]
    #[case::wrong_addr("10.0.0.9", &["10.0.0.5"], false)]
    #[case::wildcard_with_dev("0.0.0.0", &["10.0.0.5"], true)]
    #[case::wildcard_addrless_dev("0.0.0.0", &[], false)]
    #[case::not_an_ip("bogus", &["10.0.0.5"], false)]
    fn rdma_address_backing(#[case] traddr: &str, #[case] addrs: &[&str], #[case] ok: bool) {
        assert_eq!(addr_served_by_rdma(traddr, &[dev(addrs)]), ok);
        assert!(
            !addr_served_by_rdma(traddr, &[]),
            "no devices, never served"
        );
    }

    #[test]
    fn peers_from_json_parses_array_object_and_embedded_ports() {
        // Array form with separate numeric port fields.
        let peers = peers_from_json(
            r#"[{"state":"CONNECTED","src-addr":"10.0.0.5","src-port":4420,"dst-addr":"10.0.0.9","dst-port":50000}]"#,
        );
        assert_eq!(
            peers,
            vec![RdmaPeer {
                src_addr: "10.0.0.5".into(),
                src_port: Some(4420),
                dst_addr: "10.0.0.9".into(),
                state: "CONNECTED".into(),
            }]
        );

        // Ports embedded in the address string (IPv4 src, bracketed IPv6 dst),
        // no separate port keys; object-wrapped under the resource-type key.
        let peers = peers_from_json(
            r#"{"cm_id":[{"state":"CONNECTED","src-addr":"10.0.0.5:3260","dst-addr":"[fe80::1]:50000"}]}"#,
        );
        assert_eq!(
            peers,
            vec![RdmaPeer {
                src_addr: "10.0.0.5".into(),
                src_port: Some(3260),
                dst_addr: "fe80::1".into(),
                state: "CONNECTED".into(),
            }]
        );

        // Garbage, empty, and portless/peerless entries degrade gracefully.
        assert!(peers_from_json("not json").is_empty());
        assert!(peers_from_json("[]").is_empty());
        assert!(peers_from_json(r#"[{"src-addr":"10.0.0.5:4420"}]"#).is_empty());
        let no_port = peers_from_json(r#"[{"src-addr":"10.0.0.5","dst-addr":"10.0.0.9"}]"#);
        assert_eq!(no_port[0].src_port, None);
    }
}
