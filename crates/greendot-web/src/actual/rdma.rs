//! Actual RDMA state. The sysfs enumeration runs in the privileged daemon
//! (`TaskRequest::RdmaDevices`); the web collects the `Vec<RdmaDev>` JSON and renders
//! it, so no sysfs read happens in this unprivileged process. The DTOs and the
//! pure `rdma resource` parser come from the shared protocol crate.

use crate::helper_client::HelperClient;
use greendot_proto::TaskRequest;

pub use greendot_proto::actual::rdma::*;

/// Enumerates RDMA devices through the helper. A transport failure yields no
/// devices, the same graceful degradation as elsewhere.
pub async fn devices(helper: &HelperClient) -> Vec<RdmaDev> {
    serde_json::from_str(&helper.collect(TaskRequest::RdmaDevices).await.stdout).unwrap_or_default()
}
