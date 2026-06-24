//! Read-only view of the nvmet configfs tree. The reader moved to the shared
//! `greendot-reconcile` crate (it is pure and used by reconciliation); re-exported
//! here so existing `crate::actual::nvmet::*` paths keep working.

pub use greendot_reconcile::actual::nvmet::*;
