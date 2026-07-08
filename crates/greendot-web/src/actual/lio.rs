//! Actual LIO state. The configfs reads run in the privileged daemon
//! (`TaskRequest::LioReport` / `TaskRequest::LioSessions`); the web collects the JSON and
//! renders it, so no configfs read happens in this unprivileged process. Types
//! come from the shared protocol crate.

use crate::helper_client::HelperClient;
use greendot_proto::TaskRequest;

pub use greendot_proto::actual::lio::*;

/// Reads the LIO configfs tree through the helper. A transport failure yields
/// the empty state (rendered as drift), the same graceful degradation elsewhere.
pub async fn read(helper: &HelperClient) -> ActualLio {
    serde_json::from_str(&helper.collect(TaskRequest::LioReport).await.stdout).unwrap_or_default()
}

/// Reads live iSCSI sessions through the helper. A transport failure yields no
/// sessions.
pub async fn sessions(helper: &HelperClient) -> Vec<IscsiSession> {
    serde_json::from_str(&helper.collect(TaskRequest::LioSessions).await.stdout).unwrap_or_default()
}
