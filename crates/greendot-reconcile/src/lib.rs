//! Transport-agnostic desired-state reconciliation, shared by the `greendotctl`
//! binary (which applies in-process as root, or over the helper socket) and the
//! `greendot-web` server (which renders the same drift pre-check). It reads the
//! desired state from the config TOML, reads the actual system state from
//! sysfs/configfs, and drives the privileged apply steps through an [`Executor`]
//! so the same logic works whether the writes happen in-process or over the
//! helper's Unix socket.

pub mod actual;
pub mod config;
pub mod reconcile;
pub mod state;
