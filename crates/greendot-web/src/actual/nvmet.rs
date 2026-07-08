//! Actual nvmet state. The configfs read runs in the privileged daemon
//! (`TaskRequest::NvmetReport`); the web collects the `ActualNvmet` JSON and renders
//! it, so no configfs read happens in this unprivileged process. Types come from
//! the shared protocol crate.

use crate::helper_client::HelperClient;
use greendot_proto::TaskRequest;

pub use greendot_proto::actual::nvmet::*;

/// Reads the nvmet configfs tree through the helper. A transport failure or a
/// missing tree yields the empty state (which the dots render as drift), the
/// same graceful degradation as elsewhere.
pub async fn read(helper: &HelperClient) -> ActualNvmet {
    serde_json::from_str(&helper.collect(TaskRequest::NvmetReport).await.stdout).unwrap_or_default()
}
