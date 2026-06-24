//! The service configuration now lives in the shared `greendot-reconcile` crate
//! so the standalone `greendotctl reconcile` reads the same `Config` the web
//! server does. Re-exported here so existing `crate::config::Config` paths work.

pub use greendot_reconcile::config::Config;
