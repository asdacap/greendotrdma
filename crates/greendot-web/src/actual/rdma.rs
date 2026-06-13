//! RDMA device enumeration. Real enumeration of /sys/class/infiniband lands
//! in Phase 4; the type is defined now because the dot logic depends on it.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaDev {
    pub name: String,
    /// IP addresses of the netdev(s) backing this RDMA device.
    pub addrs: Vec<IpAddr>,
}

/// Whether an nvmet/LIO listen address can actually be served via RDMA.
pub fn addr_served_by_rdma(traddr: &str, devs: &[RdmaDev]) -> bool {
    let Ok(addr) = traddr.parse::<IpAddr>() else {
        return false;
    };
    if addr.is_unspecified() {
        return !devs.is_empty();
    }
    devs.iter().any(|d| d.addrs.contains(&addr))
}

pub fn devices() -> Vec<RdmaDev> {
    Vec::new() // Phase 4: read /sys/class/infiniband
}
