//! Per-NIC RDMA capability DTOs for the helper's vendor-aware inventories. The
//! structural classification from sysfs lives in the daemon-side reader; the
//! web renders these opaque results and reads no vendor knowledge into them.

use crate::PciAddress;
use serde::{Deserialize, Serialize};
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
