//! Read-only system introspection. Everything here runs unprivileged, except
//! `lvm`, whose reporting needs root and so goes through the helper.

pub mod apt;
pub mod block;
pub mod lio;
pub mod lvm;
pub mod nvmet;
pub mod rdma;
pub mod zfs;
