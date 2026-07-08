//! Actual RDMA state. The sysfs enumeration runs in the privileged daemon (the
//! `RdmaDevices` rpc); the web receives the typed reply and renders it, so no
//! sysfs read happens in this unprivileged process. The DTOs and the pure
//! `rdma resource` parser come from the shared protocol crate.

use crate::helper_client::HelperClient;

pub use greendot_proto::actual::rdma::*;

/// Enumerates RDMA devices through the helper. A transport failure yields no
/// devices, the same graceful degradation as elsewhere.
pub async fn devices(helper: &HelperClient) -> Vec<RdmaDev> {
    helper.rdma_devices().await
}
