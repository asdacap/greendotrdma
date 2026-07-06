//! Desired-state rendering and drift detection, shared by the `greendotctl`
//! binary (whose reconcile driver applies everything inline, in-process as
//! root) and the `greendot-web` server (which renders the same drift
//! pre-check). It reads the desired state from the config TOML and the actual
//! system state from sysfs/configfs; the privileged applies themselves live in
//! greendotctl.

pub mod actual;
pub mod config;
pub mod os;
pub mod reconcile;
pub mod state;
