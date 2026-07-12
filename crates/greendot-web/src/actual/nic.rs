//! Per-NIC RDMA capability. Both the structural sysfs classification and the
//! vendor-aware RoCE overlay run in the privileged daemon (the `NicInterfaces`
//! rpc combines them); the web receives the opaque typed reply and renders it,
//! carrying no vendor knowledge itself. Types come from the shared protocol
//! crate.

use crate::helper_client::HelperClient;
use std::collections::HashMap;
use std::net::IpAddr;

pub use greendot_proto::actual::nic::*;

/// Live NIC RDMA status: the daemon runs the sysfs classification overlaid with
/// its vendor RoCE-capable verdict and returns the combined list. A transport
/// failure yields no NICs.
pub async fn interfaces(helper: &HelperClient) -> Vec<NicStatus> {
    helper.nic_interfaces().await
}

/// The live PCI-address → IPs map, read by the daemon from `/sys/class/net`. A
/// transport failure yields an empty map.
pub async fn pci_addrs(helper: &HelperClient) -> HashMap<String, Vec<IpAddr>> {
    helper.nic_pci_addrs().await
}

/// The helper's per-NIC advisories as `netdev → advice`. A transport failure or
/// empty inventory yields no advisories, the same graceful degradation as
/// elsewhere.
pub async fn rdma_advice(helper: &HelperClient) -> HashMap<String, NicAdvice> {
    helper.nic_rdma_advice().await
}

/// Per-NIC network configuration (DHCP/addresses/gateway/MTU/MAC/link state) as
/// `netdev → config`, read by the daemon from iproute2. Display-only; a
/// transport failure yields an empty map.
pub async fn networks(helper: &HelperClient) -> HashMap<String, NicNetwork> {
    helper
        .nic_network()
        .await
        .into_iter()
        .map(|n| (n.netdev.clone(), n))
        .collect()
}
