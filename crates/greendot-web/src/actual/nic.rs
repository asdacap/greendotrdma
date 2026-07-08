//! Per-NIC RDMA capability. Both the structural sysfs classification and the
//! vendor-aware RoCE overlay run in the privileged daemon (`TaskRequest::NicInterfaces`
//! combines them); the web collects the opaque `Vec<NicStatus>` JSON and renders
//! it, carrying no vendor knowledge itself. Types come from the shared protocol
//! crate.

use crate::helper_client::HelperClient;
use greendot_proto::TaskRequest;
use std::collections::HashMap;
use std::net::IpAddr;

pub use greendot_proto::actual::nic::*;

/// Live NIC RDMA status: the daemon runs the sysfs classification overlaid with
/// its vendor RoCE-capable verdict and returns the combined list. A transport
/// failure yields no NICs.
pub async fn interfaces(helper: &HelperClient) -> Vec<NicStatus> {
    serde_json::from_str(&helper.collect(TaskRequest::NicInterfaces).await.stdout)
        .unwrap_or_default()
}

/// The live PCI-address → IPs map, read by the daemon from `/sys/class/net`. A
/// transport failure yields an empty map.
pub async fn pci_addrs(helper: &HelperClient) -> HashMap<String, Vec<IpAddr>> {
    serde_json::from_str(&helper.collect(TaskRequest::NicPciAddrs).await.stdout).unwrap_or_default()
}

/// The helper's per-NIC advisories as `netdev → advice`. A transport failure or
/// empty inventory yields no advisories, the same graceful degradation as
/// elsewhere.
pub async fn rdma_advice(helper: &HelperClient) -> HashMap<String, NicAdvice> {
    parse_nic_advice(&helper.collect(TaskRequest::NicRdmaAdvice).await.stdout)
}
