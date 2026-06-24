//! Library crate for the `greendot-web` server binary. The reconcile CLI now
//! lives in the `greendotctl` binary (which merges the helper daemon and the
//! reconcile tool); the transport-agnostic reconcile logic both share is in the
//! `greendot-reconcile` crate.

pub mod actual;
pub mod auth;
pub mod config;
pub mod dot;
pub mod fmt;
pub mod helper_client;
pub mod metrics;
pub mod reconcile;
pub mod routes;
pub mod snapshots;
pub mod state;
pub mod task_runner;
