//! Actual LIO state. The configfs reads run in the privileged daemon (the
//! `LioReport` / `LioSessions` rpcs); the web receives the typed replies and
//! renders them, so no configfs read happens in this unprivileged process.
//! Types come from the shared protocol crate.

use crate::helper_client::HelperClient;

pub use greendot_proto::actual::lio::*;

/// Reads the LIO configfs tree through the helper. A transport failure yields
/// the empty state (rendered as drift), the same graceful degradation elsewhere.
pub async fn read(helper: &HelperClient) -> ActualLio {
    helper.lio_report().await
}

/// Reads live iSCSI sessions through the helper. A transport failure yields no
/// sessions.
pub async fn sessions(helper: &HelperClient) -> Vec<IscsiSession> {
    helper.lio_sessions().await
}
