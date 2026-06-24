//! Read-only view of the LIO configfs tree. The reader moved to the shared
//! `greendot-reconcile` crate (it is pure and used by reconciliation); re-exported
//! here so existing `crate::actual::lio::*` paths keep working.

pub use greendot_reconcile::actual::lio::*;
