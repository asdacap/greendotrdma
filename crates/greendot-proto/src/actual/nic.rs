//! Per-NIC RDMA capability DTOs for the helper's vendor-aware inventories. The
//! structural classification from sysfs lives in the daemon-side reader; the
//! web renders these opaque results and reads no vendor knowledge into them.

use crate::PciAddress;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// An opaque per-NIC RDMA advisory from the helper: a human label and detail
/// explaining why a NIC may lack RDMA and how to fix it. The web renders these
/// verbatim and reads nothing into them — all vendor knowledge stays in the
/// helper (the `NicRdmaAdvice` rpc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicAdvice {
    pub label: String,
    pub detail: String,
}

/// One configured address on a NIC: the IP, its prefix length, and whether the
/// kernel marked it dynamic (i.e. DHCP-assigned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicAddr {
    pub addr: String,
    pub prefix: u8,
    /// The kernel's `dynamic` flag — set on DHCP-assigned addresses.
    pub dynamic: bool,
}

/// A NIC's live network configuration, read from `ip` (vendor-neutral). Purely a
/// display DTO; the web renders it and changes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicNetwork {
    pub netdev: String,
    /// Link-layer (MAC) address.
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    /// Operational state, e.g. `UP`/`DOWN`/`UNKNOWN`.
    pub operstate: String,
    /// True when any address is DHCP-assigned (kernel `dynamic` flag).
    pub dhcp: bool,
    pub addrs: Vec<NicAddr>,
    /// Default-route gateway for this interface, when one exists.
    pub gateway: Option<String>,
}

/// Default-route gateway per interface from `ip -j route show default`.
fn default_gateways(route_json: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(serde_json::Value::Array(routes)) = serde_json::from_str(route_json) else {
        return map;
    };
    for route in routes {
        let Some(obj) = route.as_object() else {
            continue;
        };
        if obj.get("dst").and_then(serde_json::Value::as_str) != Some("default") {
            continue;
        }
        if let (Some(dev), Some(gw)) = (
            obj.get("dev").and_then(serde_json::Value::as_str),
            obj.get("gateway").and_then(serde_json::Value::as_str),
        ) {
            map.entry(dev.to_owned()).or_insert_with(|| gw.to_owned());
        }
    }
    map
}

/// Parse `ip -j addr` (link + address inventory) joined with `ip -j route show
/// default` (per-interface gateway) into per-NIC network config. Defensive: any
/// shape mismatch yields an empty list, and `lo` is dropped. `dhcp` is true when
/// any address carries the kernel `dynamic` flag.
pub fn networks_from_json(addr_json: &str, route_json: &str) -> Vec<NicNetwork> {
    let gateways = default_gateways(route_json);
    let Ok(serde_json::Value::Array(links)) = serde_json::from_str(addr_json) else {
        return Vec::new();
    };
    links
        .iter()
        .filter_map(|link| {
            let obj = link.as_object()?;
            let netdev = obj.get("ifname").and_then(serde_json::Value::as_str)?;
            if netdev == "lo" {
                return None;
            }
            let addrs: Vec<NicAddr> = obj
                .get("addr_info")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|a| {
                            let ao = a.as_object()?;
                            Some(NicAddr {
                                addr: ao
                                    .get("local")
                                    .and_then(serde_json::Value::as_str)?
                                    .to_owned(),
                                prefix: ao
                                    .get("prefixlen")
                                    .and_then(serde_json::Value::as_u64)
                                    .unwrap_or(0) as u8,
                                dynamic: ao
                                    .get("dynamic")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(false),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(NicNetwork {
                mac: obj
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                mtu: obj
                    .get("mtu")
                    .and_then(serde_json::Value::as_u64)
                    .map(|m| m as u32),
                operstate: obj
                    .get("operstate")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_owned(),
                dhcp: addrs.iter().any(|a| a.dynamic),
                gateway: gateways.get(netdev).cloned(),
                addrs,
                netdev: netdev.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_from_json_reads_dhcp_static_and_gateway() {
        // eth0: DHCP (dynamic inet), a default gateway; lo is dropped; eth1: a
        // static address, no gateway.
        let addr = r#"[
          {"ifname":"lo","operstate":"UNKNOWN","address":"00:00:00:00:00:00","mtu":65536,
           "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
          {"ifname":"eth0","operstate":"UP","address":"aa:bb:cc:dd:ee:ff","mtu":1500,
           "addr_info":[
             {"family":"inet","local":"10.0.0.5","prefixlen":24,"dynamic":true},
             {"family":"inet6","local":"fe80::1","prefixlen":64}]},
          {"ifname":"eth1","operstate":"DOWN","address":"11:22:33:44:55:66","mtu":9000,
           "addr_info":[{"family":"inet","local":"192.168.1.2","prefixlen":16}]}
        ]"#;
        let route = r#"[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","protocol":"dhcp"}]"#;

        let nics = networks_from_json(addr, route);
        assert_eq!(nics.len(), 2, "lo dropped: {nics:#?}");

        let eth0 = nics.iter().find(|n| n.netdev == "eth0").unwrap();
        assert!(eth0.dhcp);
        assert_eq!(eth0.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(eth0.mtu, Some(1500));
        assert_eq!(eth0.operstate, "UP");
        assert_eq!(eth0.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(eth0.addrs.len(), 2);
        assert_eq!(eth0.addrs[0].addr, "10.0.0.5");
        assert_eq!(eth0.addrs[0].prefix, 24);
        assert!(eth0.addrs[0].dynamic);
        assert!(!eth0.addrs[1].dynamic);

        let eth1 = nics.iter().find(|n| n.netdev == "eth1").unwrap();
        assert!(!eth1.dhcp, "static address is not DHCP");
        assert_eq!(eth1.operstate, "DOWN");
        assert_eq!(eth1.gateway, None);

        // Garbage / empty degrade to no NICs.
        assert!(networks_from_json("not json", "[]").is_empty());
        assert!(networks_from_json("[]", "not json").is_empty());
    }
}
