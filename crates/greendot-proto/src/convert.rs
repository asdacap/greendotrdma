//! Conversions between the generated protobuf transport types (`crate::pb`) and
//! the validated domain model (`Request`/`Response`/`TaskEvent` and the newtypes
//! in `types`).
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
    BackstoreName, BlockDev, DatasetName, DevicePath, ErrKind, Iqn, KernelModule, LioBackstoreSpec,
    LioDesired, LioLunSpec, LioPortalSpec, LioTargetSpec, LvName, LvmReport, MountPath, MountPoint,
    NetdevName, NfsClient, NfsClientSpec, NfsDesired, NfsExportPath, NfsExportSpec, Nqn,
    NvmetDesired, NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, PackageName, PartLabel, PoolName,
    Request, Response, Secret, SnapName, TaskEvent, Transport, Username, ValidationError,
    VdevLayout, VgName,
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

impl From<KernelModule> for pb::KernelModule {
    fn from(m: KernelModule) -> Self {
        match m {
            KernelModule::NvmetLoop => pb::KernelModule::NvmetLoop,
            KernelModule::NvmetTcp => pb::KernelModule::NvmetTcp,
            KernelModule::NvmetRdma => pb::KernelModule::NvmetRdma,
            KernelModule::Iscsi => pb::KernelModule::Iscsi,
            KernelModule::Iser => pb::KernelModule::Iser,
            KernelModule::Rxe => pb::KernelModule::Rxe,
            KernelModule::Rpcrdma => pb::KernelModule::Rpcrdma,
        }
    }
}
impl TryFrom<pb::KernelModule> for KernelModule {
    type Error = ConvertError;
    fn try_from(m: pb::KernelModule) -> Result<Self, ConvertError> {
        Ok(match m {
            pb::KernelModule::NvmetLoop => KernelModule::NvmetLoop,
            pb::KernelModule::NvmetTcp => KernelModule::NvmetTcp,
            pb::KernelModule::NvmetRdma => KernelModule::NvmetRdma,
            pb::KernelModule::Iscsi => KernelModule::Iscsi,
            pb::KernelModule::Iser => KernelModule::Iser,
            pb::KernelModule::Rxe => KernelModule::Rxe,
            pb::KernelModule::Rpcrdma => KernelModule::Rpcrdma,
            pb::KernelModule::Unspecified => {
                return Err(ConvertError("unspecified kernel module".into()));
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
fn dec_kernel_modules(v: Vec<i32>) -> Result<Vec<KernelModule>, ConvertError> {
    v.into_iter()
        .map(|i| {
            let p = pb::KernelModule::try_from(i)
                .map_err(|_| ConvertError(format!("unknown kernel module {i}")))?;
            KernelModule::try_from(p)
        })
        .collect()
}

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

// ---- Request ----

impl From<Request> for pb::Request {
    fn from(r: Request) -> Self {
        use pb::request::Op;
        let op = match r {
            Request::Ping => Op::Ping(pb::Empty {}),
            Request::Authenticate { username, password } => Op::Authenticate(pb::Authenticate {
                username: username.as_str().to_owned(),
                password: password.0,
            }),
            Request::ZvolCreate {
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
            Request::ZvolDelete { dataset } => Op::ZvolDelete(pb::ZvolDelete {
                dataset: dataset.as_str().to_owned(),
            }),
            Request::ZvolResize { dataset, new_size } => Op::ZvolResize(pb::ZvolResize {
                dataset: dataset.as_str().to_owned(),
                new_size,
            }),
            Request::SnapshotCreate { dataset, snap } => Op::SnapshotCreate(pb::SnapshotCreate {
                dataset: dataset.as_str().to_owned(),
                snap: snap.as_str().to_owned(),
            }),
            Request::SnapshotDestroy { dataset, snap } => {
                Op::SnapshotDestroy(pb::SnapshotDestroy {
                    dataset: dataset.as_str().to_owned(),
                    snap: snap.as_str().to_owned(),
                })
            }
            Request::ZfsFsCreate {
                dataset,
                mountpoint,
            } => Op::ZfsFsCreate(pb::ZfsFsCreate {
                dataset: dataset.as_str().to_owned(),
                mountpoint: mountpoint.map(|m| m.as_str().to_owned()),
            }),
            Request::ZfsSetMountpoint {
                dataset,
                mountpoint,
            } => Op::ZfsSetMountpoint(pb::ZfsSetMountpoint {
                dataset: dataset.as_str().to_owned(),
                mountpoint: mountpoint.as_str().to_owned(),
            }),
            Request::ZfsMount { dataset } => Op::ZfsMount(pb::ZfsMount {
                dataset: dataset.as_str().to_owned(),
            }),
            Request::ZfsUnmount { dataset } => Op::ZfsUnmount(pb::ZfsUnmount {
                dataset: dataset.as_str().to_owned(),
            }),
            Request::ZfsDestroy { dataset, recursive } => Op::ZfsDestroy(pb::ZfsDestroy {
                dataset: dataset.as_str().to_owned(),
                recursive,
            }),
            Request::PartitionTableCreate { disk } => {
                Op::PartitionTableCreate(pb::PartitionTableCreate {
                    disk: disk.as_str().to_owned(),
                })
            }
            Request::PartitionCreate {
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
            Request::PartitionDelete { disk, number } => Op::PartitionDelete(pb::PartitionDelete {
                disk: disk.as_str().to_owned(),
                number,
            }),
            Request::PartitionResize {
                disk,
                number,
                size_sectors,
            } => Op::PartitionResize(pb::PartitionResize {
                disk: disk.as_str().to_owned(),
                number,
                size_sectors,
            }),
            Request::Fsck { device } => Op::Fsck(pb::Fsck {
                device: device.as_str().to_owned(),
            }),
            Request::ResizeExt {
                device,
                new_size_sectors,
            } => Op::ResizeExt(pb::ResizeExt {
                device: device.as_str().to_owned(),
                new_size_sectors,
            }),
            Request::BtrfsMount { device, mount_path } => Op::BtrfsMount(pb::BtrfsMount {
                device: device.as_str().to_owned(),
                mount_path: mount_path.as_str().to_owned(),
            }),
            Request::BtrfsResize {
                mount_path,
                new_size,
            } => Op::BtrfsResize(pb::BtrfsResize {
                mount_path: mount_path.as_str().to_owned(),
                new_size,
            }),
            Request::Umount { mount_path } => Op::Umount(pb::Umount {
                mount_path: mount_path.as_str().to_owned(),
            }),
            Request::PoolCreate {
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
            Request::PoolDeviceAdd { pool, device } => Op::PoolDeviceAdd(pb::PoolDeviceAdd {
                pool: pool.as_str().to_owned(),
                device: device.as_str().to_owned(),
            }),
            Request::SmartReport { device } => Op::SmartReport(pb::SmartReport {
                device: device.as_str().to_owned(),
            }),
            Request::SmartHealth { devices } => Op::SmartHealth(pb::SmartHealth {
                devices: strs(&devices),
            }),
            Request::LvmReport { what } => Op::LvmReport(pb::LvmReport {
                what: pb::LvmReportKind::from(what) as i32,
            }),
            Request::VgCreate { name, devices } => Op::VgCreate(pb::VgCreate {
                name: name.as_str().to_owned(),
                devices: strs(&devices),
            }),
            Request::VgExtend { vg, device } => Op::VgExtend(pb::VgExtend {
                vg: vg.as_str().to_owned(),
                device: device.as_str().to_owned(),
            }),
            Request::VgReduce { vg, device } => Op::VgReduce(pb::VgReduce {
                vg: vg.as_str().to_owned(),
                device: device.as_str().to_owned(),
            }),
            Request::VgRemove { vg } => Op::VgRemove(pb::VgRemove {
                vg: vg.as_str().to_owned(),
            }),
            Request::LvCreate { vg, name, size } => Op::LvCreate(pb::LvCreate {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                size,
            }),
            Request::ThinPoolCreate { vg, name, size } => Op::ThinPoolCreate(pb::ThinPoolCreate {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                size,
            }),
            Request::ThinLvCreate {
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
            Request::LvResize { vg, name, new_size } => Op::LvResize(pb::LvResize {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                new_size,
            }),
            Request::LvShrink { vg, name, new_size } => Op::LvShrink(pb::LvShrink {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                new_size,
            }),
            Request::LvRename { vg, name, new_name } => Op::LvRename(pb::LvRename {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
                new_name: new_name.as_str().to_owned(),
            }),
            Request::LvDelete { vg, name } => Op::LvDelete(pb::LvDelete {
                vg: vg.as_str().to_owned(),
                name: name.as_str().to_owned(),
            }),
            Request::NvmetApply { desired } => Op::NvmetApply(pb::NvmetApply {
                desired: Some(desired.into()),
            }),
            Request::LioApply { desired } => Op::LioApply(pb::LioApply {
                desired: Some(desired.into()),
            }),
            Request::NfsApply { desired } => Op::NfsApply(pb::NfsApply {
                desired: Some(desired.into()),
            }),
            Request::NfsReport => Op::NfsReport(pb::Empty {}),
            Request::EnsureModules { modules } => Op::EnsureModules(pb::EnsureModules {
                modules: modules
                    .into_iter()
                    .map(|m| pb::KernelModule::from(m) as i32)
                    .collect(),
            }),
            Request::RxeLinkAdd { netdev } => Op::RxeLinkAdd(pb::RxeLinkAdd {
                netdev: netdev.as_str().to_owned(),
            }),
            Request::RoceCapableNics => Op::RoceCapableNics(pb::Empty {}),
            Request::EnableRoce { netdev } => Op::EnableRoce(pb::EnableRoce {
                netdev: netdev.as_str().to_owned(),
            }),
            Request::NicRdmaAdvice => Op::NicRdmaAdvice(pb::Empty {}),
            Request::RdmaResources => Op::RdmaResources(pb::Empty {}),
            Request::InstallPackages { packages } => Op::InstallPackages(pb::InstallPackages {
                packages: strs(&packages),
            }),
        };
        pb::Request { op: Some(op) }
    }
}

impl TryFrom<pb::Request> for Request {
    type Error = ConvertError;
    fn try_from(r: pb::Request) -> Result<Self, ConvertError> {
        use pb::request::Op;
        let op =
            r.op.ok_or_else(|| ConvertError("request has no op set".into()))?;
        Ok(match op {
            Op::Ping(_) => Request::Ping,
            Op::Authenticate(a) => Request::Authenticate {
                username: Username::new(a.username)?,
                password: Secret(a.password),
            },
            Op::ZvolCreate(z) => Request::ZvolCreate {
                dataset: DatasetName::new(z.dataset)?,
                size: z.size,
                volblocksize: z.volblocksize,
                sparse: z.sparse,
            },
            Op::ZvolDelete(z) => Request::ZvolDelete {
                dataset: DatasetName::new(z.dataset)?,
            },
            Op::ZvolResize(z) => Request::ZvolResize {
                dataset: DatasetName::new(z.dataset)?,
                new_size: z.new_size,
            },
            Op::SnapshotCreate(s) => Request::SnapshotCreate {
                dataset: DatasetName::new(s.dataset)?,
                snap: SnapName::new(s.snap)?,
            },
            Op::SnapshotDestroy(s) => Request::SnapshotDestroy {
                dataset: DatasetName::new(s.dataset)?,
                snap: SnapName::new(s.snap)?,
            },
            Op::ZfsFsCreate(z) => Request::ZfsFsCreate {
                dataset: DatasetName::new(z.dataset)?,
                mountpoint: z.mountpoint.map(MountPoint::new).transpose()?,
            },
            Op::ZfsSetMountpoint(z) => Request::ZfsSetMountpoint {
                dataset: DatasetName::new(z.dataset)?,
                mountpoint: MountPoint::new(z.mountpoint)?,
            },
            Op::ZfsMount(z) => Request::ZfsMount {
                dataset: DatasetName::new(z.dataset)?,
            },
            Op::ZfsUnmount(z) => Request::ZfsUnmount {
                dataset: DatasetName::new(z.dataset)?,
            },
            Op::ZfsDestroy(z) => Request::ZfsDestroy {
                dataset: DatasetName::new(z.dataset)?,
                recursive: z.recursive,
            },
            Op::PartitionTableCreate(p) => Request::PartitionTableCreate {
                disk: BlockDev::new(p.disk)?,
            },
            Op::PartitionCreate(p) => Request::PartitionCreate {
                disk: BlockDev::new(p.disk)?,
                start_sector: p.start_sector,
                size_sectors: p.size_sectors,
                label: PartLabel::new(p.label)?,
            },
            Op::PartitionDelete(p) => Request::PartitionDelete {
                disk: BlockDev::new(p.disk)?,
                number: p.number,
            },
            Op::PartitionResize(p) => Request::PartitionResize {
                disk: BlockDev::new(p.disk)?,
                number: p.number,
                size_sectors: p.size_sectors,
            },
            Op::Fsck(f) => Request::Fsck {
                device: DevicePath::new(f.device)?,
            },
            Op::ResizeExt(r) => Request::ResizeExt {
                device: DevicePath::new(r.device)?,
                new_size_sectors: r.new_size_sectors,
            },
            Op::BtrfsMount(b) => Request::BtrfsMount {
                device: DevicePath::new(b.device)?,
                mount_path: MountPath::new(b.mount_path)?,
            },
            Op::BtrfsResize(b) => Request::BtrfsResize {
                mount_path: MountPath::new(b.mount_path)?,
                new_size: b.new_size,
            },
            Op::Umount(u) => Request::Umount {
                mount_path: MountPath::new(u.mount_path)?,
            },
            Op::PoolCreate(p) => Request::PoolCreate {
                name: PoolName::new(p.name)?,
                vdev: dec_vdev(p.vdev)?,
                devices: map_new(p.devices, DevicePath::new)?,
                ashift: p.ashift.map(|v| to_u8(v, "ashift")).transpose()?,
            },
            Op::PoolDeviceAdd(p) => Request::PoolDeviceAdd {
                pool: PoolName::new(p.pool)?,
                device: DevicePath::new(p.device)?,
            },
            Op::SmartReport(s) => Request::SmartReport {
                device: BlockDev::new(s.device)?,
            },
            Op::SmartHealth(s) => Request::SmartHealth {
                devices: map_new(s.devices, BlockDev::new)?,
            },
            Op::LvmReport(l) => Request::LvmReport {
                what: dec_lvm_report(l.what)?,
            },
            Op::VgCreate(v) => Request::VgCreate {
                name: VgName::new(v.name)?,
                devices: map_new(v.devices, DevicePath::new)?,
            },
            Op::VgExtend(v) => Request::VgExtend {
                vg: VgName::new(v.vg)?,
                device: DevicePath::new(v.device)?,
            },
            Op::VgReduce(v) => Request::VgReduce {
                vg: VgName::new(v.vg)?,
                device: DevicePath::new(v.device)?,
            },
            Op::VgRemove(v) => Request::VgRemove {
                vg: VgName::new(v.vg)?,
            },
            Op::LvCreate(l) => Request::LvCreate {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                size: l.size,
            },
            Op::ThinPoolCreate(t) => Request::ThinPoolCreate {
                vg: VgName::new(t.vg)?,
                name: LvName::new(t.name)?,
                size: t.size,
            },
            Op::ThinLvCreate(t) => Request::ThinLvCreate {
                vg: VgName::new(t.vg)?,
                pool: LvName::new(t.pool)?,
                name: LvName::new(t.name)?,
                virtual_size: t.virtual_size,
            },
            Op::LvResize(l) => Request::LvResize {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                new_size: l.new_size,
            },
            Op::LvShrink(l) => Request::LvShrink {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                new_size: l.new_size,
            },
            Op::LvRename(l) => Request::LvRename {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
                new_name: LvName::new(l.new_name)?,
            },
            Op::LvDelete(l) => Request::LvDelete {
                vg: VgName::new(l.vg)?,
                name: LvName::new(l.name)?,
            },
            Op::NvmetApply(n) => Request::NvmetApply {
                desired: n
                    .desired
                    .ok_or_else(|| ConvertError("nvmet_apply missing desired".into()))?
                    .try_into()?,
            },
            Op::LioApply(l) => Request::LioApply {
                desired: l
                    .desired
                    .ok_or_else(|| ConvertError("lio_apply missing desired".into()))?
                    .try_into()?,
            },
            Op::NfsApply(n) => Request::NfsApply {
                desired: n
                    .desired
                    .ok_or_else(|| ConvertError("nfs_apply missing desired".into()))?
                    .try_into()?,
            },
            Op::NfsReport(_) => Request::NfsReport,
            Op::EnsureModules(e) => Request::EnsureModules {
                modules: dec_kernel_modules(e.modules)?,
            },
            Op::RxeLinkAdd(r) => Request::RxeLinkAdd {
                netdev: NetdevName::new(r.netdev)?,
            },
            Op::RoceCapableNics(_) => Request::RoceCapableNics,
            Op::EnableRoce(e) => Request::EnableRoce {
                netdev: NetdevName::new(e.netdev)?,
            },
            Op::NicRdmaAdvice(_) => Request::NicRdmaAdvice,
            Op::RdmaResources(_) => Request::RdmaResources,
            Op::InstallPackages(i) => Request::InstallPackages {
                packages: map_new(i.packages, PackageName::new)?,
            },
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

impl From<TaskEvent> for pb::TaskEvent {
    fn from(ev: TaskEvent) -> Self {
        use pb::task_event::Event;
        let event = match ev {
            TaskEvent::Started {
                command,
                args,
                stdin,
            } => Event::Started(pb::Started {
                command,
                args,
                stdin,
            }),
            TaskEvent::Stdout { data } => Event::Stdout(pb::Output { data }),
            TaskEvent::Stderr { data } => Event::Stderr(pb::Output { data }),
            TaskEvent::Finished { exit, ok, error } => {
                Event::Finished(pb::Finished { exit, ok, error })
            }
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
            Event::Started(s) => TaskEvent::Started {
                command: s.command,
                args: s.args,
                stdin: s.stdin,
            },
            Event::Stdout(o) => TaskEvent::Stdout { data: o.data },
            Event::Stderr(o) => TaskEvent::Stderr { data: o.data },
            Event::Finished(f) => TaskEvent::Finished {
                exit: f.exit,
                ok: f.ok,
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
    fn wire_roundtrip(req: &Request) -> Request {
        let on_wire = pb::Request::from(req.clone()).encode_to_vec();
        let decoded = pb::Request::decode(on_wire.as_slice()).unwrap();
        Request::try_from(decoded).unwrap()
    }

    #[rstest]
    #[case::ping(Request::Ping)]
    #[case::auth(Request::Authenticate {
        username: Username::new("alice").unwrap(),
        password: Secret("hunter2".into()),
    })]
    #[case::zvol_some(Request::ZvolCreate {
        dataset: DatasetName::new("tank/vols/vm1").unwrap(),
        size: 10 << 30,
        volblocksize: Some(16384),
        sparse: true,
    })]
    #[case::zvol_none(Request::ZvolCreate {
        dataset: DatasetName::new("tank/vols/vm1").unwrap(),
        size: 10 << 30,
        volblocksize: None,
        sparse: false,
    })]
    #[case::part_create(Request::PartitionCreate {
        disk: BlockDev::new("sdb").unwrap(),
        start_sector: None,
        size_sectors: Some(2097152),
        label: PartLabel::new("data").unwrap(),
    })]
    #[case::pool_create(Request::PoolCreate {
        name: PoolName::new("tank").unwrap(),
        vdev: VdevLayout::Mirror,
        devices: vec![
            DevicePath::new("/dev/sdb").unwrap(),
            DevicePath::new("/dev/sdc").unwrap(),
        ],
        ashift: Some(12),
    })]
    #[case::lvm_report(Request::LvmReport { what: LvmReport::Lvs })]
    #[case::thin_lv(Request::ThinLvCreate {
        vg: VgName::new("vg0").unwrap(),
        pool: LvName::new("pool0").unwrap(),
        name: LvName::new("vm1").unwrap(),
        virtual_size: 20 << 30,
    })]
    #[case::modules(Request::EnsureModules {
        modules: vec![KernelModule::NvmetRdma, KernelModule::Rxe],
    })]
    #[case::smart_health(Request::SmartHealth {
        devices: vec![BlockDev::new("sda").unwrap(), BlockDev::new("nvme0n1").unwrap()],
    })]
    #[case::nvmet(Request::NvmetApply {
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
    #[case::lio(Request::LioApply {
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
    #[case::nfs(Request::NfsApply {
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
    #[case::nfs_report(Request::NfsReport)]
    #[case::roce(Request::RoceCapableNics)]
    #[case::enable_roce(Request::EnableRoce { netdev: NetdevName::new("ens16").unwrap() })]
    #[case::advice(Request::NicRdmaAdvice)]
    #[case::rdma(Request::RdmaResources)]
    #[case::install(Request::InstallPackages {
        packages: vec![PackageName::new("nvme-cli").unwrap()],
    })]
    fn request_wire_roundtrips(#[case] req: Request) {
        assert_eq!(wire_roundtrip(&req), req);
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
            TaskEvent::Started {
                command: "zfs".into(),
                args: vec!["create".into()],
                stdin: Some("x".into()),
            },
            TaskEvent::Stdout { data: "out".into() },
            TaskEvent::Stderr { data: "err".into() },
            TaskEvent::Finished {
                exit: 0,
                ok: true,
                error: None,
            },
            TaskEvent::Finished {
                exit: 1,
                ok: false,
                error: Some("boom".into()),
            },
        ] {
            let decoded =
                pb::TaskEvent::decode(pb::TaskEvent::from(ev.clone()).encode_to_vec().as_slice())
                    .unwrap();
            assert_eq!(TaskEvent::try_from(decoded).unwrap(), ev);
        }
    }

    // Build a `pb::Request` directly from an op (bypassing validation, as a
    // malicious/buggy client could) to prove ingress `TryFrom` rejects it.
    fn bad(op: pb::request::Op) -> ConvertError {
        Request::try_from(pb::Request { op: Some(op) }).unwrap_err()
    }

    #[test]
    fn invalid_payloads_are_rejected_on_ingress() {
        use pb::request::Op;
        // The equivalent of the serde corpus in lib.rs — validation must still
        // run at the proto->domain boundary (prost does not run it for us).
        bad(Op::ZvolDelete(pb::ZvolDelete {
            dataset: "../../etc".into(),
        }));
        bad(Op::RxeLinkAdd(pb::RxeLinkAdd {
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
        bad(Op::BtrfsResize(pb::BtrfsResize {
            mount_path: "/run/greendotrdma/btrfs-resize-../etc".into(),
            new_size: 1024,
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
        assert!(Request::try_from(pb::Request { op: None }).is_err());
    }
}
