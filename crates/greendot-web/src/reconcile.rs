//! Desired-state reconciliation now lives in the shared `greendot-reconcile`
//! crate, so the standalone `greendotctl reconcile` and the web's drift pre-check
//! (`routes::block_export::reconcile_state`) share one implementation. Re-exported
//! here so existing `crate::reconcile::*` paths keep working: `render_*`,
//! `*_satisfied`, `listen_addrs`, and the `RECONCILE_*` setting keys.

pub use greendot_reconcile::reconcile::*;
