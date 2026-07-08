//! Per-NIC RDMA capability DTOs and the pure parsers for the helper's
//! vendor-aware inventories. The structural classification from sysfs lives in
//! the daemon-side reader (`greendot_reconcile::actual::nic`); the web renders
//! these opaque results and reads no vendor knowledge into them.

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
