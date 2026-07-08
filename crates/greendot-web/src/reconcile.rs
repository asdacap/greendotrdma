//! Desired-state reconciliation runs entirely in the privileged daemon now: the
//! web's drift pre-check (`routes::block_export::reconcile_state`) asks the daemon
//! via the `ReconcileDryRun` rpc rather than rendering/diffing locally. The only
//! pure bit the web still needs for display — resolving an export's pinned
//! interfaces to their listen IPs — comes from the shared protocol crate.

pub use greendot_proto::desired::{
    iscsi_render_error, listen_addrs, nfs_render_error, nvme_render_error,
};
