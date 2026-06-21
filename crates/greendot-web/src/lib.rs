//! Library crate shared by the `greendot-web` server binary and the
//! `greendot-cli` command-line tool (e.g. `greendot-cli reconcile`).

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
