//! Read-only system introspection used by reconciliation. Everything here runs
//! unprivileged from sysfs/configfs; the one privileged read (the NFS report)
//! is fetched through the [`crate::reconcile::Executor`], not from here.

pub mod lio;
pub mod nfs;
pub mod nic;
pub mod nvmet;
pub mod rdma;
