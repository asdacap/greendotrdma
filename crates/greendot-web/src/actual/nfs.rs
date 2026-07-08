//! Actual NFS state. The parsers and types live in the shared protocol crate
//! (`greendot_proto::actual::nfs`); the privileged fetch runs in the daemon
//! (the `NfsReport` rpc — the export table and the root-only nfsd portlist
//! cannot be read by the unprivileged web service).

use crate::helper_client::HelperClient;

pub use greendot_proto::actual::nfs::*;

/// Reads NFS actual state through the helper. A helper/transport failure or a
/// missing `exportfs` simply yields an empty state (nothing exported, no RDMA),
/// which the dots render as red — the same graceful degradation as elsewhere.
pub async fn read(helper: &HelperClient) -> ActualNfs {
    helper.nfs_report().await
}
