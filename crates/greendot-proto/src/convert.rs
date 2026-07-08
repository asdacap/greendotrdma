//! Conversions between the generated protobuf transport types (`crate::pb`) and
//! the validated domain model (`CallRequest`/`TaskRequest`/`Response`/
//! `TaskEvent` and the newtypes in `types`).
//!
//! Direction matters for security:
//! - **`From<domain> for pb::…`** (client egress) is infallible: domain values
//!   are already valid, so we just unwrap them into plain strings/ints.
//! - **`TryFrom<pb::…> for domain`** (server ingress) re-runs every validator by
//!   routing each string field through its newtype `::new()`. This is the single
//!   choke point that restores the "decoding re-validates" property that serde
//!   gave us for free but prost does not — the daemon MUST go through it.

use crate::pb;
use crate::{
    BackstoreName, BlockDev, CallRequest, DatasetName, DevicePath, ErrKind, Iqn, LioBackstoreSpec,
    LioDesired, LioLunSpec, LioPortalSpec, LioTargetSpec, LvName, LvmReport, MountPoint,
    NetdevName, NfsClient, NfsClientSpec, NfsDesired, NfsExportPath, NfsExportSpec, Nqn,
    NvmetDesired, NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, PackageName, PartLabel, PoolName,
    Response, Secret, SnapName, SubStatus, TaskEvent, TaskRequest, Transport, Username,
    ValidationError, VdevLayout, VgName,
};
use std::net::IpAddr;

/// A failure converting a decoded protobuf message into the validated domain
/// model. On the server this maps to `ErrKind::Validation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConvertError {}

impl From<ValidationError> for ConvertError {
    fn from(e: ValidationError) -> Self {
        ConvertError(e.to_string())
    }
}

// ---- small helpers ----

fn to_u16(v: u32, what: &str) -> Result<u16, ConvertError> {
    u16::try_from(v).map_err(|_| ConvertError(format!("{what} out of u16 range: {v}")))
}

fn to_u8(v: u32, what: &str) -> Result<u8, ConvertError> {
    u8::try_from(v).map_err(|_| ConvertError(format!("{what} out of u8 range: {v}")))
}

fn parse_ip(s: &str) -> Result<IpAddr, ConvertError> {
    s.parse()
        .map_err(|_| ConvertError(format!("invalid IP address: {s:?}")))
}

/// Validate a `Vec<String>` into a `Vec<newtype>` using the newtype constructor.
fn map_new<T, F>(v: Vec<String>, f: F) -> Result<Vec<T>, ConvertError>
where
    F: Fn(String) -> Result<T, ValidationError>,
{
    v.into_iter()
        .map(|s| f(s).map_err(ConvertError::from))
        .collect()
}

/// Validate a `Vec<pb::Spec>` into a `Vec<domain::Spec>` via `TryFrom`.
fn map_try<P, T>(v: Vec<P>) -> Result<Vec<T>, ConvertError>
where
    T: TryFrom<P, Error = ConvertError>,
{
    v.into_iter().map(T::try_from).collect()
}

/// Unwrap a `Vec<newtype>` into a `Vec<String>` (egress).
fn strs<T: AsRef<str>>(v: &[T]) -> Vec<String> {
    v.iter().map(|s| s.as_ref().to_owned()).collect()
}

// The newtypes deref to `&str` via `as_str`; give them AsRef<str> so `strs`
// works uniformly.
macro_rules! as_ref_str {
    ($($t:ty),* $(,)?) => {$(
        impl AsRef<str> for $t {
            fn as_ref(&self) -> &str { self.as_str() }
        }
    )*};
}
as_ref_str!(DatasetName, DevicePath, Nqn, Iqn, BlockDev, PackageName);

// ---- enums ----

impl From<Transport> for pb::Transport {
    fn from(t: Transport) -> Self {
        match t {
            Transport::Rdma => pb::Transport::Rdma,
            Transport::Tcp => pb::Transport::Tcp,
            Transport::Loop => pb::Transport::Loop,
        }
    }
}
impl TryFrom<pb::Transport> for Transport {
    type Error = ConvertError;
    fn try_from(t: pb::Transport) -> Result<Self, ConvertError> {
        Ok(match t {
            pb::Transport::Rdma => Transport::Rdma,
            pb::Transport::Tcp => Transport::Tcp,
            pb::Transport::Loop => Transport::Loop,
            pb::Transport::Unspecified => {
                return Err(ConvertError("unspecified transport".into()));
            }
        })
    }
}

impl From<VdevLayout> for pb::VdevLayout {
    fn from(v: VdevLayout) -> Self {
        match v {
            VdevLayout::Stripe => pb::VdevLayout::Stripe,
            VdevLayout::Mirror => pb::VdevLayout::Mirror,
            VdevLayout::Raidz1 => pb::VdevLayout::Raidz1,
            VdevLayout::Raidz2 => pb::VdevLayout::Raidz2,
            VdevLayout::Raidz3 => pb::VdevLayout::Raidz3,
        }
    }
}
impl TryFrom<pb::VdevLayout> for VdevLayout {
    type Error = ConvertError;
    fn try_from(v: pb::VdevLayout) -> Result<Self, ConvertError> {
        Ok(match v {
            pb::VdevLayout::Stripe => VdevLayout::Stripe,
            pb::VdevLayout::Mirror => VdevLayout::Mirror,
            pb::VdevLayout::Raidz1 => VdevLayout::Raidz1,
            pb::VdevLayout::Raidz2 => VdevLayout::Raidz2,
            pb::VdevLayout::Raidz3 => VdevLayout::Raidz3,
            pb::VdevLayout::Unspecified => {
                return Err(ConvertError("unspecified vdev layout".into()));
            }
        })
    }
}

impl From<LvmReport> for pb::LvmReportKind {
    fn from(r: LvmReport) -> Self {
        match r {
            LvmReport::Vgs => pb::LvmReportKind::Vgs,
            LvmReport::Lvs => pb::LvmReportKind::Lvs,
            LvmReport::Pvs => pb::LvmReportKind::Pvs,
        }
    }
}
impl TryFrom<pb::LvmReportKind> for LvmReport {
    type Error = ConvertError;
    fn try_from(r: pb::LvmReportKind) -> Result<Self, ConvertError> {
        Ok(match r {
            pb::LvmReportKind::Vgs => LvmReport::Vgs,
            pb::LvmReportKind::Lvs => LvmReport::Lvs,
            pb::LvmReportKind::Pvs => LvmReport::Pvs,
            pb::LvmReportKind::Unspecified => {
                return Err(ConvertError("unspecified lvm report".into()));
            }
        })
    }
}

impl From<ErrKind> for pb::ErrKind {
    fn from(k: ErrKind) -> Self {
        match k {
            ErrKind::AuthFailed => pb::ErrKind::AuthFailed,
            ErrKind::NotInAdminGroup => pb::ErrKind::NotInAdminGroup,
            ErrKind::Validation => pb::ErrKind::Validation,
            ErrKind::Busy => pb::ErrKind::Busy,
            ErrKind::Sys => pb::ErrKind::Sys,
            ErrKind::CmdFailed => pb::ErrKind::CmdFailed,
            ErrKind::Unsupported => pb::ErrKind::Unsupported,
        }
    }
}
impl TryFrom<pb::ErrKind> for ErrKind {
    type Error = ConvertError;
    fn try_from(k: pb::ErrKind) -> Result<Self, ConvertError> {
        Ok(match k {
            pb::ErrKind::AuthFailed => ErrKind::AuthFailed,
            pb::ErrKind::NotInAdminGroup => ErrKind::NotInAdminGroup,
            pb::ErrKind::Validation => ErrKind::Validation,
            pb::ErrKind::Busy => ErrKind::Busy,
            pb::ErrKind::Sys => ErrKind::Sys,
            pb::ErrKind::CmdFailed => ErrKind::CmdFailed,
            pb::ErrKind::Unsupported => ErrKind::Unsupported,
            pb::ErrKind::Unspecified => {
                return Err(ConvertError("unspecified error kind".into()));
            }
        })
    }
}

/// Decode a prost `i32` enumeration field into its proto enum, rejecting values
/// outside the schema.
fn dec_transport(i: i32) -> Result<Transport, ConvertError> {
    let p =
        pb::Transport::try_from(i).map_err(|_| ConvertError(format!("unknown transport {i}")))?;
    Transport::try_from(p)
}

fn dec_vdev(i: i32) -> Result<VdevLayout, ConvertError> {
    let p = pb::VdevLayout::try_from(i)
        .map_err(|_| ConvertError(format!("unknown vdev layout {i}")))?;
    VdevLayout::try_from(p)
}

fn dec_lvm_report(i: i32) -> Result<LvmReport, ConvertError> {
    let p = pb::LvmReportKind::try_from(i)
        .map_err(|_| ConvertError(format!("unknown lvm report {i}")))?;
    LvmReport::try_from(p)
}

// ---- desired-state nested structs ----

impl From<NvmetDesired> for pb::NvmetDesired {
    fn from(d: NvmetDesired) -> Self {
        pb::NvmetDesired {
            subsystems: d.subsystems.into_iter().map(Into::into).collect(),
            ports: d.ports.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::NvmetDesired> for NvmetDesired {
    type Error = ConvertError;
    fn try_from(d: pb::NvmetDesired) -> Result<Self, ConvertError> {
        Ok(NvmetDesired {
            subsystems: map_try(d.subsystems)?,
            ports: map_try(d.ports)?,
        })
    }
}

impl From<NvmetSubsysSpec> for pb::NvmetSubsysSpec {
    fn from(s: NvmetSubsysSpec) -> Self {
        pb::NvmetSubsysSpec {
            nqn: s.nqn.as_str().to_owned(),
            allow_any_host: s.allow_any_host,
            allowed_hosts: strs(&s.allowed_hosts),
            namespaces: s.namespaces.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::NvmetSubsysSpec> for NvmetSubsysSpec {
    type Error = ConvertError;
    fn try_from(s: pb::NvmetSubsysSpec) -> Result<Self, ConvertError> {
        Ok(NvmetSubsysSpec {
            nqn: Nqn::new(s.nqn)?,
            allow_any_host: s.allow_any_host,
            allowed_hosts: map_new(s.allowed_hosts, Nqn::new)?,
            namespaces: map_try(s.namespaces)?,
        })
    }
}

impl From<NvmetNsSpec> for pb::NvmetNsSpec {
    fn from(n: NvmetNsSpec) -> Self {
        pb::NvmetNsSpec {
            nsid: n.nsid,
            device_path: n.device_path.as_str().to_owned(),
        }
    }
}
impl TryFrom<pb::NvmetNsSpec> for NvmetNsSpec {
    type Error = ConvertError;
    fn try_from(n: pb::NvmetNsSpec) -> Result<Self, ConvertError> {
        Ok(NvmetNsSpec {
            nsid: n.nsid,
            device_path: DevicePath::new(n.device_path)?,
        })
    }
}

impl From<NvmetPortSpec> for pb::NvmetPortSpec {
    fn from(p: NvmetPortSpec) -> Self {
        pb::NvmetPortSpec {
            id: u32::from(p.id),
            trtype: pb::Transport::from(p.trtype) as i32,
            traddr: p.traddr.to_string(),
            trsvcid: u32::from(p.trsvcid),
            subsystems: strs(&p.subsystems),
        }
    }
}
impl TryFrom<pb::NvmetPortSpec> for NvmetPortSpec {
    type Error = ConvertError;
    fn try_from(p: pb::NvmetPortSpec) -> Result<Self, ConvertError> {
        Ok(NvmetPortSpec {
            id: to_u16(p.id, "port id")?,
            trtype: dec_transport(p.trtype)?,
            traddr: parse_ip(&p.traddr)?,
            trsvcid: to_u16(p.trsvcid, "trsvcid")?,
            subsystems: map_new(p.subsystems, Nqn::new)?,
        })
    }
}

impl From<LioDesired> for pb::LioDesired {
    fn from(d: LioDesired) -> Self {
        pb::LioDesired {
            backstores: d.backstores.into_iter().map(Into::into).collect(),
            targets: d.targets.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::LioDesired> for LioDesired {
    type Error = ConvertError;
    fn try_from(d: pb::LioDesired) -> Result<Self, ConvertError> {
        Ok(LioDesired {
            backstores: map_try(d.backstores)?,
            targets: map_try(d.targets)?,
        })
    }
}

impl From<LioBackstoreSpec> for pb::LioBackstoreSpec {
    fn from(b: LioBackstoreSpec) -> Self {
        pb::LioBackstoreSpec {
            name: b.name.as_str().to_owned(),
            device_path: b.device_path.as_str().to_owned(),
        }
    }
}
impl TryFrom<pb::LioBackstoreSpec> for LioBackstoreSpec {
    type Error = ConvertError;
    fn try_from(b: pb::LioBackstoreSpec) -> Result<Self, ConvertError> {
        Ok(LioBackstoreSpec {
            name: BackstoreName::new(b.name)?,
            device_path: DevicePath::new(b.device_path)?,
        })
    }
}

impl From<LioTargetSpec> for pb::LioTargetSpec {
    fn from(t: LioTargetSpec) -> Self {
        pb::LioTargetSpec {
            iqn: t.iqn.as_str().to_owned(),
            enabled: t.enabled,
            demo_mode: t.demo_mode,
            luns: t.luns.into_iter().map(Into::into).collect(),
            portals: t.portals.into_iter().map(Into::into).collect(),
            acls: strs(&t.acls),
        }
    }
}
impl TryFrom<pb::LioTargetSpec> for LioTargetSpec {
    type Error = ConvertError;
    fn try_from(t: pb::LioTargetSpec) -> Result<Self, ConvertError> {
        Ok(LioTargetSpec {
            iqn: Iqn::new(t.iqn)?,
            enabled: t.enabled,
            demo_mode: t.demo_mode,
            luns: map_try(t.luns)?,
            portals: map_try(t.portals)?,
            acls: map_new(t.acls, Iqn::new)?,
        })
    }
}

impl From<LioLunSpec> for pb::LioLunSpec {
    fn from(l: LioLunSpec) -> Self {
        pb::LioLunSpec {
            lun: l.lun,
            backstore: l.backstore.as_str().to_owned(),
        }
    }
}
impl TryFrom<pb::LioLunSpec> for LioLunSpec {
    type Error = ConvertError;
    fn try_from(l: pb::LioLunSpec) -> Result<Self, ConvertError> {
        Ok(LioLunSpec {
            lun: l.lun,
            backstore: BackstoreName::new(l.backstore)?,
        })
    }
}

impl From<LioPortalSpec> for pb::LioPortalSpec {
    fn from(p: LioPortalSpec) -> Self {
        pb::LioPortalSpec {
            addr: p.addr.to_string(),
            port: u32::from(p.port),
            iser: p.iser,
        }
    }
}
impl TryFrom<pb::LioPortalSpec> for LioPortalSpec {
    type Error = ConvertError;
    fn try_from(p: pb::LioPortalSpec) -> Result<Self, ConvertError> {
        Ok(LioPortalSpec {
            addr: parse_ip(&p.addr)?,
            port: to_u16(p.port, "portal port")?,
            iser: p.iser,
        })
    }
}

impl From<NfsDesired> for pb::NfsDesired {
    fn from(d: NfsDesired) -> Self {
        pb::NfsDesired {
            exports: d.exports.into_iter().map(Into::into).collect(),
            rdma_port: u32::from(d.rdma_port),
        }
    }
}
impl TryFrom<pb::NfsDesired> for NfsDesired {
    type Error = ConvertError;
    fn try_from(d: pb::NfsDesired) -> Result<Self, ConvertError> {
        Ok(NfsDesired {
            exports: map_try(d.exports)?,
            rdma_port: to_u16(d.rdma_port, "rdma_port")?,
        })
    }
}

impl From<NfsExportSpec> for pb::NfsExportSpec {
    fn from(e: NfsExportSpec) -> Self {
        pb::NfsExportSpec {
            path: e.path.as_str().to_owned(),
            fsid: e.fsid,
            clients: e.clients.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::NfsExportSpec> for NfsExportSpec {
    type Error = ConvertError;
    fn try_from(e: pb::NfsExportSpec) -> Result<Self, ConvertError> {
        Ok(NfsExportSpec {
            path: NfsExportPath::new(e.path)?,
            fsid: e.fsid,
            clients: map_try(e.clients)?,
        })
    }
}

impl From<NfsClientSpec> for pb::NfsClientSpec {
    fn from(c: NfsClientSpec) -> Self {
        pb::NfsClientSpec {
            client: c.client.as_str().to_owned(),
            rw: c.rw,
        }
    }
}
impl TryFrom<pb::NfsClientSpec> for NfsClientSpec {
    type Error = ConvertError;
    fn try_from(c: pb::NfsClientSpec) -> Result<Self, ConvertError> {
        Ok(NfsClientSpec {
            client: NfsClient::new(c.client)?,
            rw: c.rw,
        })
    }
}

// ---- CallRequest ----

impl From<CallRequest> for pb::CallRequest {
    fn from(r: CallRequest) -> Self {
        use pb::call_request::Op;
        let op = match r {
            CallRequest::Ping => Op::Ping(pb::Empty {}),
            CallRequest::Authenticate { username, password } => {
                Op::Authenticate(pb::Authenticate {
                    username: username.as_str().to_owned(),
                    password: password.0,
                })
            }
        };
        pb::CallRequest { op: Some(op) }
    }
}

impl TryFrom<pb::CallRequest> for CallRequest {
    type Error = ConvertError;
    fn try_from(r: pb::CallRequest) -> Result<Self, ConvertError> {
        use pb::call_request::Op;
        let op =
            r.op.ok_or_else(|| ConvertError("call request has no op set".into()))?;
        Ok(match op {
            Op::Ping(_) => CallRequest::Ping,
            Op::Authenticate(a) => CallRequest::Authenticate {
                username: Username::new(a.username)?,
                password: Secret(a.password),
            },
        })
    }
}

// ---- TaskRequest ----

impl From<TaskRequest> for pb::TaskRequest {
    fn from(r: TaskRequest) -> Self {
        use pb::task_request::Op;
        let op = match r {
            TaskRequest::ZvolCreate {
                dataset,
                size,
                volblocksize,
                sparse,
            } => Op::ZvolCreate(pb::ZvolCreate {
                dataset: dataset.as_str().to_owned(),
                size,
                volblocksize,
                sparse,
            }),
            TaskRequest::ZvolDelete { dataset } => Op::ZvolDelete(pb::ZvolDelete {
                dataset: dataset.as_str().to_owned(),
            }),
            TaskRequest::ZvolResize { dataset, new_size } => Op::ZvolResize(pb::ZvolResize {
                dataset: dataset.as_str().to_owned(),
                new_size,
            }),
            TaskRequest::SnapshotCreate { dataset, snap } => {
                Op::SnapshotCreate(pb::SnapshotCreate {
                    dataset: dataset.as_str().to_owned(),
                    snap: snap.as_str().to_owned(),
                })
            }
            TaskRequest::SnapshotDestroy { dataset, snap } => {
                Op::SnapshotDestroy(pb::SnapshotDestroy {
                    dataset: dataset.as_str().to_owned(),
                    snap: snap.as_str().to_owned(),
                })
            }
            TaskRequest::ZfsFsCreate {
                dataset,
                mountpoint,
            } => Op::ZfsFsCreate(pb::ZfsFsCreate {
                dataset: dataset.as_str().to_owned(),
                mountpoint: mountpoint.map(|m| m.as_str().to_owned()),
            }),
            TaskRequest::ZfsSetMountpoint {
                dataset,
                mountpoint,
            } => Op::ZfsSetMountpoint(pb::ZfsSetMountpoint {
                dataset: dataset.as_str().to_owned(),
                mountpoint: mountpoint.as_str().to_owned(),
            }),
            TaskRequest::ZfsMount { dataset } => Op::ZfsMount(pb::ZfsMount {
                dataset: dataset.as_str().to_owned(),
            }),
            TaskRequest::ZfsUnmount { dataset } => Op::ZfsUnmount(pb::ZfsUnmount {
                dataset: dataset.as_str().to_owned(),
            }),
            TaskRequest::ZfsDestroy { dataset, recursive } => Op::ZfsDestroy(pb::ZfsDestroy {
                dataset: dataset.as_str().to_owned(),
                recursive,
            }),
            TaskRequest::PartitionTableCreate { disk } => {
                Op::PartitionTableCreate(pb::PartitionTableCreate {
                    disk: disk.as_str().to_owned(),
                })
            }
            TaskRequest::PartitionCreate {
                disk,
                start_sector,
                size_sectors,
                label,
            } => Op::PartitionCreate(pb::PartitionCreate {
                disk: disk.as_str().to_owned(),
                start_sector,
                size_sectors,
                label: label.as_str().to_owned(),
            }),
            TaskRequest::PartitionDelete { disk, number } => {
                Op::PartitionDelete(pb::PartitionDelete {
                    disk: disk.as_str().to_owned(),
                    number,
                })
            }
            TaskRequest::PartitionShrink {
                disk,
                number,
                size_sectors,
            } => Op::PartitionShrink(pb::PartitionShrink {
                disk: disk.as_str().to_owned(),
                number,
                size_sectors,
            }),
            TaskRequest::PoolCreate {
                name,
                vdev,
                devices,
                ashift,
            } => Op::PoolCreate(pb::PoolCreate {
                name: name.as_str().to_owned(),
                vdev: pb::VdevLayout::from(vdev) as i32,
                devices: strs(&devices),
                ashift: ashift.map(u32::from),
            }),
            TaskRequest::PoolDeviceAdd { pool, device } => Op::PoolDeviceAdd(pb::PoolDeviceAdd {
                pool: pool.as_str().to_owned(),
                device: device.as_str().to_owned(),
            }),
            TaskRequest::SmartReport { device } => Op::SmartReport(pb::SmartReport {
                device: device.as_str().to_owned(),
            }),
            TaskRequest::SmartHealth { devices } => Op::SmartHealth(pb::SmartHealth {
                devices: strs(&devices),
            }),
            TaskRequest::LvmReport { what } => Op::LvmReport(pb::LvmReport {
                what: pb::LvmReportKind::from(what) as i32,
            }),
            TaskRequest::VgCreate { name, devices } => Op::VgCreate(pb::VgCreate {
                name: name.as_str().to_owned(),
                devices: strs(&devices),
            }),
            TaskRequest::VgExtend { vg, device } => Op::VgExtend(pb::VgExtend {
                vg: vg.as_str().to_owned(),
                device: device.as_str().to_owned(),
            }),
            TaskRequest::VgReduce { vg, device } => Op::VgReduce(pb::VgReduce {
                vg: vg.as_str().to_owned(),
                device: device.as_str().to_owned(),
            }),
            TaskRequest::VgRemove { vg } => Op::VgRemove(pb::VgRemove {
                vg: vg.as_str().to_owned(),
            }),
            TaskRequest::LvCreate { vg, name, size } => Op::LvCreate(pb::LvCreate {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                size,
            }),
            TaskRequest::ThinPoolCreate { vg, name, size } => {
                Op::ThinPoolCreate(pb::ThinPoolCreate {
                    vg: vg.as_str().to_owned(),
                    name: name.as_str().to_owned(),
                    size,
                })
            }
            TaskRequest::ThinLvCreate {
                vg,
                pool,
                name,
                virtual_size,
            } => Op::ThinLvCreate(pb::ThinLvCreate {
                vg: vg.as_str().to_owned(),
                pool: pool.as_str().to_owned(),
                name: name.as_str().to_owned(),
                virtual_size,
            }),
            TaskRequest::LvResize { vg, name, new_size } => Op::LvResize(pb::LvResize {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                new_size,
            }),
            TaskRequest::LvShrink { vg, name, new_size } => Op::LvShrink(pb::LvShrink {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                new_size,
            }),
            TaskRequest::LvRename { vg, name, new_name } => Op::LvRename(pb::LvRename {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                new_name: new_name.as_str().to_owned(),
            }),
            TaskRequest::LvDelete { vg, name } => Op::LvDelete(pb::LvDelete {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
            }),
            TaskRequest::NvmetApply { desired } => Op::NvmetApply(pb::NvmetApply {
                desired: Some(desired.into()),
            }),
            TaskRequest::LioApply { desired } => Op::LioApply(pb::LioApply {
                desired: Some(desired.into()),
            }),
            TaskRequest::NfsApply { desired } => Op::NfsApply(pb::NfsApply {
                desired: Some(desired.into()),
            }),
            TaskRequest::NfsReport => Op::NfsReport(pb::Empty {}),
            TaskRequest::Reconcile => Op::Reconcile(pb::Reconcile {}),
            TaskRequest::RxeAdd { netdev } => Op::RxeAdd(pb::RxeAdd {
                netdev: netdev.as_str().to_owned(),
            }),
            TaskRequest::RoceCapableNics => Op::RoceCapableNics(pb::Empty {}),
            TaskRequest::EnableRoce { netdev } => Op::EnableRoce(pb::EnableRoce {
                netdev: netdev.as_str().to_owned(),
            }),
            TaskRequest::NicRdmaAdvice => Op::NicRdmaAdvice(pb::Empty {}),
            TaskRequest::RdmaResources => Op::RdmaResources(pb::Empty {}),
            TaskRequest::InstallPackages { packages } => Op::InstallPackages(pb::InstallPackages {
                packages: strs(&packages),
            }),
            TaskRequest::NvmetReport => Op::NvmetReport(pb::Empty {}),
            TaskRequest::LioReport => Op::LioReport(pb::Empty {}),
            TaskRequest::LioSessions => Op::LioSessions(pb::Empty {}),
            TaskRequest::RdmaDevices => Op::RdmaDevices(pb::Empty {}),
            TaskRequest::NicPciAddrs => Op::NicPciAddrs(pb::Empty {}),
            TaskRequest::NicInterfaces => Op::NicInterfaces(pb::Empty {}),
            TaskRequest::ReconcileDryRun => Op::ReconcileDryRun(pb::Empty {}),
        };
        pb::TaskRequest { op: Some(op) }
    }
}

impl TryFrom<pb::TaskRequest> for TaskRequest {
    type Error = ConvertError;
    fn try_from(r: pb::TaskRequest) -> Result<Self, ConvertError> {
        use pb::task_request::Op;
        let op =
            r.op.ok_or_else(|| ConvertError("task request has no op set".into()))?;
        Ok(match op {
            Op::ZvolCreate(z) => TaskRequest::ZvolCreate {
                dataset: DatasetName::new(z.dataset)?,
                size: z.size,
                volblocksize: z.volblocksize,
                sparse: z.sparse,
            },
            Op::ZvolDelete(z) => TaskRequest::ZvolDelete {
                dataset: DatasetName::new(z.dataset)?,
            },
            Op::ZvolResize(z) => TaskRequest::ZvolResize {
                dataset: DatasetName::new(z.dataset)?,
                new_size: z.new_size,
            },
            Op::SnapshotCreate(s) => TaskRequest::SnapshotCreate {
                dataset: DatasetName::new(s.dataset)?,
                snap: SnapName::new(s.snap)?,
            },
            Op::SnapshotDestroy(s) => TaskRequest::SnapshotDestroy {
                dataset: DatasetName::new(s.dataset)?,
                snap: SnapName::new(s.snap)?,
            },
            Op::ZfsFsCreate(z) => TaskRequest::ZfsFsCreate {
                dataset: DatasetName::new(z.dataset)?,
                mountpoint: z.mountpoint.map(MountPoint::new).transpose()?,
            },
            Op::ZfsSetMountpoint(z) => TaskRequest::ZfsSetMountpoint {
                dataset: DatasetName::new(z.dataset)?,
                mountpoint: MountPoint::new(z.mountpoint)?,
            },
            Op::ZfsMount(z) => TaskRequest::ZfsMount {
                dataset: DatasetName::new(z.dataset)?,
            },
            Op::ZfsUnmount(z) => TaskRequest::ZfsUnmount {
                dataset: DatasetName::new(z.dataset)?,
            },
            Op::ZfsDestroy(z) => TaskRequest::ZfsDestroy {
                dataset: DatasetName::new(z.dataset)?,
                recursive: z.recursive,
            },
            Op::PartitionTableCreate(p) => TaskRequest::PartitionTableCreate {
                disk: BlockDev::new(p.disk)?,
            },
            Op::PartitionCreate(p) => TaskRequest::PartitionCreate {
                disk: BlockDev::new(p.disk)?,
                start_sector: p.start_sector,
                size_sectors: p.size_sectors,
                label: PartLabel::new(p.label)?,
            },
            Op::PartitionDelete(p) => TaskRequest::PartitionDelete {
                disk: BlockDev::new(p.disk)?,
                number: p.number,
            },
            Op::PartitionShrink(p) => TaskRequest::PartitionShrink {
                disk: BlockDev::new(p.disk)?,
                number: p.number,
                size_sectors: p.size_sectors,
            },
            Op::PoolCreate(p) => TaskRequest::PoolCreate {
                name: PoolName::new(p.name)?,
                vdev: dec_vdev(p.vdev)?,
                devices: map_new(p.devices, DevicePath::new)?,
                ashift: p.ashift.map(|v| to_u8(v, "ashift")).transpose()?,
            },
            Op::PoolDeviceAdd(p) => TaskRequest::PoolDeviceAdd {
                pool: PoolName::new(p.pool)?,
                device: DevicePath::new(p.device)?,
            },
            Op::SmartReport(s) => TaskRequest::SmartReport {
                device: BlockDev::new(s.device)?,
            },
            Op::SmartHealth(s) => TaskRequest::SmartHealth {
                devices: map_new(s.devices, BlockDev::new)?,
            },
            Op::LvmReport(l) => TaskRequest::LvmReport {
                what: dec_lvm_report(l.what)?,
            },
            Op::VgCreate(v) => TaskRequest::VgCreate {
                name: VgName::new(v.name)?,
                devices: map_new(v.devices, DevicePath::new)?,
            },
            Op::VgExtend(v) => TaskRequest::VgExtend {
                vg: VgName::new(v.vg)?,
                device: DevicePath::new(v.device)?,
            },
            Op::VgReduce(v) => TaskRequest::VgReduce {
                vg: VgName::new(v.vg)?,
                device: DevicePath::new(v.device)?,
            },
            Op::VgRemove(v) => TaskRequest::VgRemove {
                vg: VgName::new(v.vg)?,
            },
            Op::LvCreate(l) => TaskRequest::LvCreate {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                size: l.size,
            },
            Op::ThinPoolCreate(t) => TaskRequest::ThinPoolCreate {
                vg: VgName::new(t.vg)?,
                name: LvName::new(t.name)?,
                size: t.size,
            },
            Op::ThinLvCreate(t) => TaskRequest::ThinLvCreate {
                vg: VgName::new(t.vg)?,
                pool: LvName::new(t.pool)?,
                name: LvName::new(t.name)?,
                virtual_size: t.virtual_size,
            },
            Op::LvResize(l) => TaskRequest::LvResize {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                new_size: l.new_size,
            },
            Op::LvShrink(l) => TaskRequest::LvShrink {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                new_size: l.new_size,
            },
            Op::LvRename(l) => TaskRequest::LvRename {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                new_name: LvName::new(l.new_name)?,
            },
            Op::LvDelete(l) => TaskRequest::LvDelete {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
            },
            Op::NvmetApply(n) => TaskRequest::NvmetApply {
                desired: n
                    .desired
                    .ok_or_else(|| ConvertError("nvmet_apply missing desired".into()))?
                    .try_into()?,
            },
            Op::LioApply(l) => TaskRequest::LioApply {
                desired: l
                    .desired
                    .ok_or_else(|| ConvertError("lio_apply missing desired".into()))?
                    .try_into()?,
            },
            Op::NfsApply(n) => TaskRequest::NfsApply {
                desired: n
                    .desired
                    .ok_or_else(|| ConvertError("nfs_apply missing desired".into()))?
                    .try_into()?,
            },
            Op::NfsReport(_) => TaskRequest::NfsReport,
            Op::Reconcile(_) => TaskRequest::Reconcile,
            Op::RxeAdd(r) => TaskRequest::RxeAdd {
                netdev: NetdevName::new(r.netdev)?,
            },
            Op::RoceCapableNics(_) => TaskRequest::RoceCapableNics,
            Op::EnableRoce(e) => TaskRequest::EnableRoce {
                netdev: NetdevName::new(e.netdev)?,
            },
            Op::NicRdmaAdvice(_) => TaskRequest::NicRdmaAdvice,
            Op::RdmaResources(_) => TaskRequest::RdmaResources,
            Op::InstallPackages(i) => TaskRequest::InstallPackages {
                packages: map_new(i.packages, PackageName::new)?,
            },
            Op::NvmetReport(_) => TaskRequest::NvmetReport,
            Op::LioReport(_) => TaskRequest::LioReport,
            Op::LioSessions(_) => TaskRequest::LioSessions,
            Op::RdmaDevices(_) => TaskRequest::RdmaDevices,
            Op::NicPciAddrs(_) => TaskRequest::NicPciAddrs,
            Op::NicInterfaces(_) => TaskRequest::NicInterfaces,
            Op::ReconcileDryRun(_) => TaskRequest::ReconcileDryRun,
        })
    }
}

// ---- Response ----

impl From<Response> for pb::Response {
    fn from(r: Response) -> Self {
        use pb::response::Result as R;
        let result = match r {
            Response::Ok => R::Ok(pb::Empty {}),
            Response::OkAuth { username } => R::OkAuth(pb::OkAuth { username }),
            Response::Err { kind, message } => R::Err(pb::ErrResponse {
                kind: pb::ErrKind::from(kind) as i32,
                message,
            }),
        };
        pb::Response {
            result: Some(result),
        }
    }
}

impl TryFrom<pb::Response> for Response {
    type Error = ConvertError;
    fn try_from(r: pb::Response) -> Result<Self, ConvertError> {
        use pb::response::Result as R;
        let result = r
            .result
            .ok_or_else(|| ConvertError("response has no result set".into()))?;
        Ok(match result {
            R::Ok(_) => Response::Ok,
            R::OkAuth(a) => Response::OkAuth {
                username: a.username,
            },
            R::Err(e) => {
                let kind = pb::ErrKind::try_from(e.kind)
                    .map_err(|_| ConvertError(format!("unknown error kind {}", e.kind)))?;
                Response::Err {
                    kind: ErrKind::try_from(kind)?,
                    message: e.message,
                }
            }
        })
    }
}

// ---- TaskEvent ----

impl From<SubStatus> for pb::SubStatus {
    fn from(s: SubStatus) -> Self {
        match s {
            SubStatus::Success => pb::SubStatus::Success,
            SubStatus::Failed => pb::SubStatus::Failed,
            SubStatus::Skipped => pb::SubStatus::Skipped,
        }
    }
}
impl TryFrom<i32> for SubStatus {
    type Error = ConvertError;
    fn try_from(i: i32) -> Result<Self, ConvertError> {
        let p = pb::SubStatus::try_from(i)
            .map_err(|_| ConvertError(format!("unknown sub status {i}")))?;
        Ok(match p {
            pb::SubStatus::Success => SubStatus::Success,
            pb::SubStatus::Failed => SubStatus::Failed,
            pb::SubStatus::Skipped => SubStatus::Skipped,
            pb::SubStatus::Unspecified => {
                return Err(ConvertError("unspecified sub status".into()));
            }
        })
    }
}

impl From<TaskEvent> for pb::TaskEvent {
    fn from(ev: TaskEvent) -> Self {
        use pb::task_event::Event;
        let event = match ev {
            TaskEvent::SubtaskStarted {
                name,
                command,
                args,
                stdin,
            } => Event::SubtaskStarted(pb::SubtaskStarted {
                name,
                command,
                args,
                stdin,
            }),
            TaskEvent::Stdout { data } => Event::Stdout(pb::Output { data }),
            TaskEvent::Stderr { data } => Event::Stderr(pb::Output { data }),
            TaskEvent::SubtaskFinished {
                status,
                exit,
                error,
            } => Event::SubtaskFinished(pb::SubtaskFinished {
                status: pb::SubStatus::from(status) as i32,
                exit,
                error,
            }),
            TaskEvent::Finished { status, error } => Event::Finished(pb::Finished {
                status: pb::SubStatus::from(status) as i32,
                error,
            }),
        };
        pb::TaskEvent { event: Some(event) }
    }
}

impl TryFrom<pb::TaskEvent> for TaskEvent {
    type Error = ConvertError;
    fn try_from(ev: pb::TaskEvent) -> Result<Self, ConvertError> {
        use pb::task_event::Event;
        let event = ev
            .event
            .ok_or_else(|| ConvertError("task event has no event set".into()))?;
        Ok(match event {
            Event::SubtaskStarted(s) => TaskEvent::SubtaskStarted {
                name: s.name,
                command: s.command,
                args: s.args,
                stdin: s.stdin,
            },
            Event::Stdout(o) => TaskEvent::Stdout { data: o.data },
            Event::Stderr(o) => TaskEvent::Stderr { data: o.data },
            Event::SubtaskFinished(f) => TaskEvent::SubtaskFinished {
                status: SubStatus::try_from(f.status)?,
                exit: f.exit,
                error: f.error,
            },
            Event::Finished(f) => TaskEvent::Finished {
                status: SubStatus::try_from(f.status)?,
                error: f.error,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LioLunSpec, NFS_RDMA_PORT, NfsExportSpec, NvmetNsSpec, NvmetSubsysSpec};
    use prost::Message;
    use rstest::rstest;

    /// domain -> pb -> wire bytes -> pb -> domain must be the identity. This
    /// exercises the real gRPC path (prost encode/decode), not just the structs.
    fn wire_roundtrip(req: &TaskRequest) -> TaskRequest {
        let on_wire = pb::TaskRequest::from(req.clone()).encode_to_vec();
        let decoded = pb::TaskRequest::decode(on_wire.as_slice()).unwrap();
        TaskRequest::try_from(decoded).unwrap()
    }

    #[rstest]
    #[case::zvol_some(TaskRequest::ZvolCreate {
        dataset: DatasetName::new("tank/vols/vm1").unwrap(),
        size: 10 << 30,
        volblocksize: Some(16384),
        sparse: true,
    })]
    #[case::zvol_none(TaskRequest::ZvolCreate {
        dataset: DatasetName::new("tank/vols/vm1").unwrap(),
        size: 10 << 30,
        volblocksize: None,
        sparse: false,
    })]
    #[case::part_create(TaskRequest::PartitionCreate {
        disk: BlockDev::new("sdb").unwrap(),
        start_sector: None,
        size_sectors: Some(2097152),
        label: PartLabel::new("data").unwrap(),
    })]
    #[case::pool_create(TaskRequest::PoolCreate {
        name: PoolName::new("tank").unwrap(),
        vdev: VdevLayout::Mirror,
        devices: vec![
            DevicePath::new("/dev/sdb").unwrap(),
            DevicePath::new("/dev/sdc").unwrap(),
        ],
        ashift: Some(12),
    })]
    #[case::lvm_report(TaskRequest::LvmReport { what: LvmReport::Lvs })]
    #[case::thin_lv(TaskRequest::ThinLvCreate {
        vg: VgName::new("vg0").unwrap(),
        pool: LvName::new("pool0").unwrap(),
        name: LvName::new("vm1").unwrap(),
        virtual_size: 20 << 30,
    })]
    #[case::partition_shrink(TaskRequest::PartitionShrink {
        disk: BlockDev::new("sdb").unwrap(),
        number: 2,
        size_sectors: 2097152,
    })]
    #[case::rxe_add(TaskRequest::RxeAdd { netdev: NetdevName::new("eth0").unwrap() })]
    #[case::smart_health(TaskRequest::SmartHealth {
        devices: vec![BlockDev::new("sda").unwrap(), BlockDev::new("nvme0n1").unwrap()],
    })]
    #[case::nvmet(TaskRequest::NvmetApply {
        desired: NvmetDesired {
            subsystems: vec![NvmetSubsysSpec {
                nqn: Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap(),
                allow_any_host: false,
                allowed_hosts: vec![Nqn::new("nqn.2014-08.org.nvmexpress:host1").unwrap()],
                namespaces: vec![NvmetNsSpec {
                    nsid: 1,
                    device_path: DevicePath::new("/dev/zvol/tank/vm1").unwrap(),
                }],
            }],
            ports: vec![NvmetPortSpec {
                id: 1,
                trtype: Transport::Rdma,
                traddr: "192.168.1.10".parse().unwrap(),
                trsvcid: 4420,
                subsystems: vec![Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap()],
            }],
        },
    })]
    #[case::lio(TaskRequest::LioApply {
        desired: LioDesired {
            backstores: vec![LioBackstoreSpec {
                name: BackstoreName::new("vm1").unwrap(),
                device_path: DevicePath::new("/dev/zvol/tank/vm1").unwrap(),
            }],
            targets: vec![LioTargetSpec {
                iqn: Iqn::new("iqn.2026-06.io.greendot:vm1").unwrap(),
                enabled: true,
                demo_mode: false,
                luns: vec![LioLunSpec { lun: 0, backstore: BackstoreName::new("vm1").unwrap() }],
                portals: vec![LioPortalSpec { addr: "::1".parse().unwrap(), port: 3260, iser: true }],
                acls: vec![Iqn::new("iqn.1993-08.org.debian:01:abc").unwrap()],
            }],
        },
    })]
    #[case::nfs(TaskRequest::NfsApply {
        desired: NfsDesired {
            rdma_port: NFS_RDMA_PORT,
            exports: vec![NfsExportSpec {
                path: NfsExportPath::new("/tank/share").unwrap(),
                fsid: 0x6700_0001,
                clients: vec![NfsClientSpec {
                    client: NfsClient::new("192.168.101.0/24").unwrap(),
                    rw: true,
                }],
            }],
        },
    })]
    #[case::nfs_report(TaskRequest::NfsReport)]
    #[case::reconcile(TaskRequest::Reconcile)]
    #[case::roce(TaskRequest::RoceCapableNics)]
    #[case::enable_roce(TaskRequest::EnableRoce { netdev: NetdevName::new("ens16").unwrap() })]
    #[case::advice(TaskRequest::NicRdmaAdvice)]
    #[case::rdma(TaskRequest::RdmaResources)]
    #[case::install(TaskRequest::InstallPackages {
        packages: vec![PackageName::new("nvme-cli").unwrap()],
    })]
    #[case::nvmet_report(TaskRequest::NvmetReport)]
    #[case::lio_report(TaskRequest::LioReport)]
    #[case::lio_sessions(TaskRequest::LioSessions)]
    #[case::rdma_devices(TaskRequest::RdmaDevices)]
    #[case::nic_pci_addrs(TaskRequest::NicPciAddrs)]
    #[case::nic_interfaces(TaskRequest::NicInterfaces)]
    #[case::reconcile_dry_run(TaskRequest::ReconcileDryRun)]
    fn task_request_wire_roundtrips(#[case] req: TaskRequest) {
        assert_eq!(wire_roundtrip(&req), req);
    }

    #[rstest]
    #[case::ping(CallRequest::Ping)]
    #[case::auth(CallRequest::Authenticate {
        username: Username::new("alice").unwrap(),
        password: Secret("hunter2".into()),
    })]
    fn call_request_wire_roundtrips(#[case] req: CallRequest) {
        let on_wire = pb::CallRequest::from(req.clone()).encode_to_vec();
        let decoded = pb::CallRequest::decode(on_wire.as_slice()).unwrap();
        assert_eq!(CallRequest::try_from(decoded).unwrap(), req);
    }

    /// A `Call` username is validated on ingress just like every task field.
    #[test]
    fn invalid_call_payload_is_rejected_on_ingress() {
        let bad = pb::CallRequest {
            op: Some(pb::call_request::Op::Authenticate(pb::Authenticate {
                username: "root; reboot".into(),
                password: "x".into(),
            })),
        };
        assert!(CallRequest::try_from(bad).is_err());
    }

    #[test]
    fn response_and_task_event_roundtrip() {
        for resp in [
            Response::Ok,
            Response::OkAuth {
                username: "alice".into(),
            },
            Response::err(ErrKind::CmdFailed, "zfs exited 1"),
        ] {
            let decoded =
                pb::Response::decode(pb::Response::from(resp.clone()).encode_to_vec().as_slice())
                    .unwrap();
            assert_eq!(Response::try_from(decoded).unwrap(), resp);
        }
        for ev in [
            TaskEvent::SubtaskStarted {
                name: "Create zvol".into(),
                command: Some("zfs".into()),
                args: vec!["create".into()],
                stdin: Some("x".into()),
            },
            TaskEvent::SubtaskStarted {
                name: "Load kernel modules".into(),
                command: None,
                args: vec![],
                stdin: None,
            },
            TaskEvent::Stdout { data: "out".into() },
            TaskEvent::Stderr { data: "err".into() },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Success,
                exit: 0,
                error: None,
            },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Failed,
                exit: 1,
                error: Some("boom".into()),
            },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Skipped,
                exit: 0,
                error: None,
            },
            TaskEvent::Finished {
                status: SubStatus::Success,
                error: None,
            },
            TaskEvent::Finished {
                status: SubStatus::Failed,
                error: Some("boom".into()),
            },
        ] {
            let decoded =
                pb::TaskEvent::decode(pb::TaskEvent::from(ev.clone()).encode_to_vec().as_slice())
                    .unwrap();
            assert_eq!(TaskEvent::try_from(decoded).unwrap(), ev);
        }
        // A `SubStatus` of 0 (UNSPECIFIED) is rejected on ingress, mirroring the
        // other enum-ingress checks — an unset status must not decode as Success.
        for bad in [
            pb::task_event::Event::SubtaskFinished(pb::SubtaskFinished {
                status: 0,
                exit: 0,
                error: None,
            }),
            pb::task_event::Event::Finished(pb::Finished {
                status: 0,
                error: None,
            }),
        ] {
            assert!(TaskEvent::try_from(pb::TaskEvent { event: Some(bad) }).is_err());
        }
    }

    // Build a `pb::TaskRequest` directly from an op (bypassing validation, as a
    // malicious/buggy client could) to prove ingress `TryFrom` rejects it.
    fn bad(op: pb::task_request::Op) -> ConvertError {
        TaskRequest::try_from(pb::TaskRequest { op: Some(op) }).unwrap_err()
    }

    #[test]
    fn invalid_payloads_are_rejected_on_ingress() {
        use pb::task_request::Op;
        // The equivalent of the serde corpus in lib.rs — validation must still
        // run at the proto->domain boundary (prost does not run it for us).
        bad(Op::ZvolDelete(pb::ZvolDelete {
            dataset: "../../etc".into(),
        }));
        bad(Op::RxeAdd(pb::RxeAdd {
            netdev: "eth0/../x".into(),
        }));
        bad(Op::InstallPackages(pb::InstallPackages {
            packages: vec!["foo;rm -rf".into()],
        }));
        bad(Op::PoolCreate(pb::PoolCreate {
            name: "mirror".into(), // reserved vdev keyword
            vdev: pb::VdevLayout::Stripe as i32,
            devices: vec!["/dev/sdb".into()],
            ashift: None,
        }));
        bad(Op::LvDelete(pb::LvDelete {
            vg: "vg0".into(),
            name: "../x".into(),
        }));
        bad(Op::VgCreate(pb::VgCreate {
            name: "-bad".into(),
            devices: vec!["/dev/sdb".into()],
        }));
        bad(Op::PartitionShrink(pb::PartitionShrink {
            disk: "../sda".into(),
            number: 1,
            size_sectors: 1024,
        }));
        bad(Op::EnableRoce(pb::EnableRoce {
            netdev: "eth0 ; reboot".into(),
        }));
        bad(Op::ZfsMount(pb::ZfsMount {
            dataset: "../../etc".into(),
        }));
        bad(Op::ZfsSetMountpoint(pb::ZfsSetMountpoint {
            dataset: "tank/share".into(),
            mountpoint: "/tank/../etc".into(),
        }));
        bad(Op::NfsApply(pb::NfsApply {
            desired: Some(pb::NfsDesired {
                rdma_port: 20049,
                exports: vec![pb::NfsExportSpec {
                    path: "/tank/../etc".into(),
                    fsid: 1,
                    clients: vec![],
                }],
            }),
        }));
        bad(Op::NfsApply(pb::NfsApply {
            desired: Some(pb::NfsDesired {
                rdma_port: 20049,
                exports: vec![pb::NfsExportSpec {
                    path: "/srv".into(),
                    fsid: 1,
                    clients: vec![pb::NfsClientSpec {
                        client: "h(rw".into(),
                        rw: true,
                    }],
                }],
            }),
        }));
        // Transport-shape failures unique to the proto port:
        bad(Op::PoolCreate(pb::PoolCreate {
            name: "tank".into(),
            vdev: 0, // VDEV_LAYOUT_UNSPECIFIED
            devices: vec!["/dev/sdb".into()],
            ashift: None,
        }));
        bad(Op::NvmetApply(pb::NvmetApply {
            desired: Some(pb::NvmetDesired {
                subsystems: vec![],
                ports: vec![pb::NvmetPortSpec {
                    id: 70000, // > u16::MAX
                    trtype: pb::Transport::Rdma as i32,
                    traddr: "10.0.0.1".into(),
                    trsvcid: 4420,
                    subsystems: vec![],
                }],
            }),
        }));
        bad(Op::NvmetApply(pb::NvmetApply {
            desired: Some(pb::NvmetDesired {
                subsystems: vec![],
                ports: vec![pb::NvmetPortSpec {
                    id: 1,
                    trtype: pb::Transport::Rdma as i32,
                    traddr: "not-an-ip".into(),
                    trsvcid: 4420,
                    subsystems: vec![],
                }],
            }),
        }));
        bad(Op::NvmetApply(pb::NvmetApply { desired: None })); // missing nested
    }

    #[test]
    fn missing_op_is_rejected() {
        assert!(TaskRequest::try_from(pb::TaskRequest { op: None }).is_err());
        assert!(CallRequest::try_from(pb::CallRequest { op: None }).is_err());
    }
}
