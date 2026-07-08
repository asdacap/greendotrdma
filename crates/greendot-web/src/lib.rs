//! Library crate for the `greendot-web` server binary. It depends only on the
//! shared `greendot-proto` contract: every hardware/configfs/sysfs read and the
//! reconcile logic run in the privileged `greendotctl` daemon, which the web
//! reaches over gRPC. No hardware-specific code lives in this crate.

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
