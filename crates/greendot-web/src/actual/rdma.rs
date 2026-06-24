//! RDMA device enumeration from /sys/class/infiniband. Moved to the shared
//! `greendot-reconcile` crate (it is pure and used by reconciliation); re-exported
//! here so existing `crate::actual::rdma::*` paths keep working.

pub use greendot_reconcile::actual::rdma::*;
