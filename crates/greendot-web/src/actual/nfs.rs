//! Actual NFS state. The parsers and types moved to the shared `greendot-reconcile`
//! crate (pure, used by reconciliation); the privileged fetch stays here because
//! it needs the web's async `HelperClient`. Unlike ZFS reads, the export table
//! (`exportfs -s`) and the nfsd portlist (`/proc/fs/nfsd/portlist`, root-only)
//! cannot be read by the unprivileged web service, so they come through the
//! helper's `NfsReport`.

use crate::helper_client::HelperClient;
use greendot_proto::Request;

pub use greendot_reconcile::actual::nfs::*;

/// Reads NFS actual state through the helper. A helper/transport failure or a
/// missing `exportfs` simply yields an empty state (nothing exported, no RDMA),
/// which the dots render as red — the same graceful degradation as elsewhere.
pub async fn read(helper: &HelperClient) -> ActualNfs {
    let out = helper.collect(Request::NfsReport).await;
    from_report(&out.stdout)
}
