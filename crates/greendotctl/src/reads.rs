//! Structural/privileged reads the web collects as JSON on a task's stdout
//! (like `nfs::report_into`). Each runs a `crate::actual` reader over the
//! canonical system paths and serializes a shared `greendot_proto::actual` DTO,
//! so the unprivileged web never touches configfs/sysfs itself.

use crate::hardware;
use crate::nvmet::NVMET_ROOT;
use greendot_proto::{SubStatus, SubTask};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

/// LIO configfs root (matches the config default; the daemon owns the path).
const LIO_ROOT: &str = "/sys/kernel/config/target";
/// RDMA device class root.
const IB_ROOT: &str = "/sys/class/infiniband";

/// Writes `data` as one JSON blob to the subtask's stdout and reports success —
/// the shared shape of every collected read.
fn emit_json<T: serde::Serialize>(sub: &mut SubTask, data: &T) -> io::Result<SubStatus> {
    write!(
        sub.stdout(),
        "{}",
        serde_json::to_string(data).unwrap_or_default()
    )?;
    Ok(SubStatus::Success)
}

/// The nvmet configfs tree as `ActualNvmet` JSON.
pub fn nvmet_report_into(sub: &mut SubTask) -> io::Result<SubStatus> {
    emit_json(sub, &crate::actual::nvmet::read(Path::new(NVMET_ROOT)))
}

/// The LIO configfs tree as `ActualLio` JSON.
pub fn lio_report_into(sub: &mut SubTask) -> io::Result<SubStatus> {
    emit_json(sub, &crate::actual::lio::read(Path::new(LIO_ROOT)))
}

/// Live iSCSI sessions as `Vec<IscsiSession>` JSON.
pub fn lio_sessions_into(sub: &mut SubTask) -> io::Result<SubStatus> {
    emit_json(sub, &crate::actual::lio::sessions(Path::new(LIO_ROOT)))
}

/// RDMA devices as `Vec<RdmaDev>` JSON.
pub fn rdma_devices_into(sub: &mut SubTask) -> io::Result<SubStatus> {
    emit_json(sub, &crate::actual::rdma::devices())
}

/// The live PCI-address → IPs map as JSON.
pub fn nic_pci_addrs_into(sub: &mut SubTask) -> io::Result<SubStatus> {
    emit_json(sub, &crate::actual::nic::pci_addrs())
}

/// Every NIC's RDMA status as `Vec<NicStatus>` JSON: the structural sysfs
/// classification overlaid with the vendor RoCE-capable map, combined here so
/// the web renders one opaque list and carries no vendor knowledge.
pub fn nic_interfaces_into(sub: &mut SubTask) -> io::Result<SubStatus> {
    let roce_hw: HashMap<String, String> = hardware::roce_capable(Path::new(hardware::NET_ROOT))
        .into_iter()
        .map(|(netdev, vendor)| (netdev, vendor.to_owned()))
        .collect();
    let netdev_addrs = crate::actual::rdma::netdev_addrs();
    let nics = crate::actual::nic::classify(
        Path::new(hardware::NET_ROOT),
        Path::new(IB_ROOT),
        &netdev_addrs,
        &roce_hw,
    );
    emit_json(sub, &nics)
}
