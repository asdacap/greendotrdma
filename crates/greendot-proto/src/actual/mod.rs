//! Actual-state DTOs and their pure parsers — the *read* half of the protocol
//! contract. greendotctl reads live system state (sysfs/configfs/CLIs) and
//! serializes these types as JSON on a task's stdout; greendot-web deserializes
//! and renders them, so both name one model. The privileged reader functions
//! themselves live in greendot-reconcile (daemon-only); only the data shapes and
//! the pure parsers that turn tool output into them live here.

pub mod lio;
pub mod nfs;
pub mod nic;
pub mod nvmet;
pub mod rdma;
