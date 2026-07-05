//! Read-only system introspection used by reconciliation. Everything here runs
//! unprivileged from sysfs/configfs; the one privileged read (the NFS report)
//! is fetched by the caller who holds root — greendotctl in-process, or the
//! web via `Request::NfsReport` — and only *parsed* here.

pub mod lio;
pub mod nfs;
pub mod nic;
pub mod nvmet;
pub mod rdma;
