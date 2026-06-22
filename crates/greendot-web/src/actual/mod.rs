//! Read-only system introspection. Everything here runs unprivileged, except
//! `lvm` and `nfs`, whose reads need root and so go through the helper.

pub mod apt;
pub mod block;
pub mod lio;
pub mod lvm;
pub mod nfs;
pub mod nic;
pub mod nvmet;
pub mod rdma;
pub mod zfs;
