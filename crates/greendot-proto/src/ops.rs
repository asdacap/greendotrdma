//! The validated domain ops — one struct per rpc, the typed twin of its wire
//! request message in [`crate::pb`].
//!
//! Direction matters for security, exactly as it did for the old request
//! enums:
//! - **`From<ops::X> for pb::X`** (client egress) is infallible: domain values
//!   are already valid.
//! - **`TryFrom<pb::X> for ops::X`** (server ingress) re-runs every validator
//!   by routing each string through its newtype constructor. The daemon's
//!   generic rpc middleware requires this bound, so no rpc can skip it — this
//!   is the security choke point.

use crate::convert::{
    dec_lvm_report, dec_transport, dec_vdev, map_new, parse_ip, strs, to_u8, to_u16,
};
use crate::pb;
use crate::{
    BlockDev, ConvertError, CsiNqn, DatasetName, DevicePath, LvName, LvmReport as LvmReportKind,
    MountPoint, NetdevName, Nqn, NsUuid, PackageName, PartLabel, PoolName, Secret, SnapName,
    SshFingerprint, Transport, Username, ValidationError, VdevLayout, VdevTarget, VgName,
};
use std::net::IpAddr;

/// Fieldless ops: a unit marker struct with the trivial (but still mandatory)
/// ingress conversion, so the daemon's middleware bound holds uniformly.
macro_rules! unit_op {
    ($(#[$m:meta])* $name:ident, $wire:ty) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;
        impl TryFrom<$wire> for $name {
            type Error = ConvertError;
            fn try_from(_: $wire) -> Result<Self, ConvertError> {
                Ok($name)
            }
        }
        impl From<$name> for $wire {
            fn from(_: $name) -> Self {
                Default::default()
            }
        }
    };
}

// ---- One-shot ----

/// PAM authentication + admin-group check, run by root because the web is
/// unprivileged and only root can read `/etc/shadow`. Its own rpc (never a
/// recorded task — that would write the password into the task log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticate {
    pub username: Username,
    pub password: Secret,
}

impl TryFrom<pb::Authenticate> for Authenticate {
    type Error = ConvertError;
    fn try_from(a: pb::Authenticate) -> Result<Self, ConvertError> {
        Ok(Authenticate {
            username: Username::new(a.username)?,
            password: Secret(a.password),
        })
    }
}
impl From<Authenticate> for pb::Authenticate {
    fn from(a: Authenticate) -> Self {
        pb::Authenticate {
            username: a.username.as_str().to_owned(),
            password: a.password.0,
        }
    }
}

// ---- ZFS zvols and snapshots ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZvolCreate {
    pub dataset: DatasetName,
    pub size: u64,
    pub volblocksize: Option<u32>,
    pub sparse: bool,
}

impl TryFrom<pb::ZvolCreate> for ZvolCreate {
    type Error = ConvertError;
    fn try_from(z: pb::ZvolCreate) -> Result<Self, ConvertError> {
        Ok(ZvolCreate {
            dataset: DatasetName::new(z.dataset)?,
            size: z.size,
            volblocksize: z.volblocksize,
            sparse: z.sparse,
        })
    }
}
impl From<ZvolCreate> for pb::ZvolCreate {
    fn from(z: ZvolCreate) -> Self {
        pb::ZvolCreate {
            dataset: z.dataset.as_str().to_owned(),
            size: z.size,
            volblocksize: z.volblocksize,
            sparse: z.sparse,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZvolDelete {
    pub dataset: DatasetName,
}

impl TryFrom<pb::ZvolDelete> for ZvolDelete {
    type Error = ConvertError;
    fn try_from(z: pb::ZvolDelete) -> Result<Self, ConvertError> {
        Ok(ZvolDelete {
            dataset: DatasetName::new(z.dataset)?,
        })
    }
}
impl From<ZvolDelete> for pb::ZvolDelete {
    fn from(z: ZvolDelete) -> Self {
        pb::ZvolDelete {
            dataset: z.dataset.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZvolResize {
    pub dataset: DatasetName,
    pub new_size: u64,
}

impl TryFrom<pb::ZvolResize> for ZvolResize {
    type Error = ConvertError;
    fn try_from(z: pb::ZvolResize) -> Result<Self, ConvertError> {
        Ok(ZvolResize {
            dataset: DatasetName::new(z.dataset)?,
            new_size: z.new_size,
        })
    }
}
impl From<ZvolResize> for pb::ZvolResize {
    fn from(z: ZvolResize) -> Self {
        pb::ZvolResize {
            dataset: z.dataset.as_str().to_owned(),
            new_size: z.new_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCreate {
    pub dataset: DatasetName,
    pub snap: SnapName,
}

impl TryFrom<pb::SnapshotCreate> for SnapshotCreate {
    type Error = ConvertError;
    fn try_from(s: pb::SnapshotCreate) -> Result<Self, ConvertError> {
        Ok(SnapshotCreate {
            dataset: DatasetName::new(s.dataset)?,
            snap: SnapName::new(s.snap)?,
        })
    }
}
impl From<SnapshotCreate> for pb::SnapshotCreate {
    fn from(s: SnapshotCreate) -> Self {
        pb::SnapshotCreate {
            dataset: s.dataset.as_str().to_owned(),
            snap: s.snap.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDestroy {
    pub dataset: DatasetName,
    pub snap: SnapName,
}

impl TryFrom<pb::SnapshotDestroy> for SnapshotDestroy {
    type Error = ConvertError;
    fn try_from(s: pb::SnapshotDestroy) -> Result<Self, ConvertError> {
        Ok(SnapshotDestroy {
            dataset: DatasetName::new(s.dataset)?,
            snap: SnapName::new(s.snap)?,
        })
    }
}
impl From<SnapshotDestroy> for pb::SnapshotDestroy {
    fn from(s: SnapshotDestroy) -> Self {
        pb::SnapshotDestroy {
            dataset: s.dataset.as_str().to_owned(),
            snap: s.snap.as_str().to_owned(),
        }
    }
}

/// `zfs clone <dataset>@<snap> <target>`, optionally followed by a volsize
/// bump — creating a bigger volume from a snapshot is one intent, so the
/// resize rides along server-side rather than as a client-side sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsClone {
    pub dataset: DatasetName,
    pub snap: SnapName,
    pub target: DatasetName,
    pub new_size: Option<u64>,
}

impl TryFrom<pb::ZfsClone> for ZfsClone {
    type Error = ConvertError;
    fn try_from(c: pb::ZfsClone) -> Result<Self, ConvertError> {
        Ok(ZfsClone {
            dataset: DatasetName::new(c.dataset)?,
            snap: SnapName::new(c.snap)?,
            target: DatasetName::new(c.target)?,
            new_size: c.new_size,
        })
    }
}
impl From<ZfsClone> for pb::ZfsClone {
    fn from(c: ZfsClone) -> Self {
        pb::ZfsClone {
            dataset: c.dataset.as_str().to_owned(),
            snap: c.snap.as_str().to_owned(),
            target: c.target.as_str().to_owned(),
            new_size: c.new_size,
        }
    }
}

/// Structural read: does the zvol exist, and how big is it? (CSI CreateVolume
/// idempotency and expand no-op detection.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZvolInfo {
    pub dataset: DatasetName,
}

impl TryFrom<pb::ZvolInfo> for ZvolInfo {
    type Error = ConvertError;
    fn try_from(z: pb::ZvolInfo) -> Result<Self, ConvertError> {
        Ok(ZvolInfo {
            dataset: DatasetName::new(z.dataset)?,
        })
    }
}
impl From<ZvolInfo> for pb::ZvolInfo {
    fn from(z: ZvolInfo) -> Self {
        pb::ZvolInfo {
            dataset: z.dataset.as_str().to_owned(),
        }
    }
}

// ---- ZFS filesystem datasets ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsFsCreate {
    pub dataset: DatasetName,
    /// `None` inherits the default `<pool>/<path>` mountpoint.
    pub mountpoint: Option<MountPoint>,
}

impl TryFrom<pb::ZfsFsCreate> for ZfsFsCreate {
    type Error = ConvertError;
    fn try_from(z: pb::ZfsFsCreate) -> Result<Self, ConvertError> {
        Ok(ZfsFsCreate {
            dataset: DatasetName::new(z.dataset)?,
            mountpoint: z.mountpoint.map(MountPoint::new).transpose()?,
        })
    }
}
impl From<ZfsFsCreate> for pb::ZfsFsCreate {
    fn from(z: ZfsFsCreate) -> Self {
        pb::ZfsFsCreate {
            dataset: z.dataset.as_str().to_owned(),
            mountpoint: z.mountpoint.map(|m| m.as_str().to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsSetMountpoint {
    pub dataset: DatasetName,
    pub mountpoint: MountPoint,
}

impl TryFrom<pb::ZfsSetMountpoint> for ZfsSetMountpoint {
    type Error = ConvertError;
    fn try_from(z: pb::ZfsSetMountpoint) -> Result<Self, ConvertError> {
        Ok(ZfsSetMountpoint {
            dataset: DatasetName::new(z.dataset)?,
            mountpoint: MountPoint::new(z.mountpoint)?,
        })
    }
}
impl From<ZfsSetMountpoint> for pb::ZfsSetMountpoint {
    fn from(z: ZfsSetMountpoint) -> Self {
        pb::ZfsSetMountpoint {
            dataset: z.dataset.as_str().to_owned(),
            mountpoint: z.mountpoint.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsMount {
    pub dataset: DatasetName,
}

impl TryFrom<pb::ZfsMount> for ZfsMount {
    type Error = ConvertError;
    fn try_from(z: pb::ZfsMount) -> Result<Self, ConvertError> {
        Ok(ZfsMount {
            dataset: DatasetName::new(z.dataset)?,
        })
    }
}
impl From<ZfsMount> for pb::ZfsMount {
    fn from(z: ZfsMount) -> Self {
        pb::ZfsMount {
            dataset: z.dataset.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsUnmount {
    pub dataset: DatasetName,
}

impl TryFrom<pb::ZfsUnmount> for ZfsUnmount {
    type Error = ConvertError;
    fn try_from(z: pb::ZfsUnmount) -> Result<Self, ConvertError> {
        Ok(ZfsUnmount {
            dataset: DatasetName::new(z.dataset)?,
        })
    }
}
impl From<ZfsUnmount> for pb::ZfsUnmount {
    fn from(z: ZfsUnmount) -> Self {
        pb::ZfsUnmount {
            dataset: z.dataset.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZfsDestroy {
    pub dataset: DatasetName,
    pub recursive: bool,
}

impl TryFrom<pb::ZfsDestroy> for ZfsDestroy {
    type Error = ConvertError;
    fn try_from(z: pb::ZfsDestroy) -> Result<Self, ConvertError> {
        Ok(ZfsDestroy {
            dataset: DatasetName::new(z.dataset)?,
            recursive: z.recursive,
        })
    }
}
impl From<ZfsDestroy> for pb::ZfsDestroy {
    fn from(z: ZfsDestroy) -> Self {
        pb::ZfsDestroy {
            dataset: z.dataset.as_str().to_owned(),
            recursive: z.recursive,
        }
    }
}

// ---- ZFS pools ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolCreate {
    pub name: PoolName,
    pub vdev: VdevLayout,
    pub devices: Vec<DevicePath>,
    pub ashift: Option<u8>,
}

impl TryFrom<pb::PoolCreate> for PoolCreate {
    type Error = ConvertError;
    fn try_from(p: pb::PoolCreate) -> Result<Self, ConvertError> {
        Ok(PoolCreate {
            name: PoolName::new(p.name)?,
            vdev: dec_vdev(p.vdev)?,
            devices: map_new(p.devices, DevicePath::new)?,
            ashift: p.ashift.map(|v| to_u8(v, "ashift")).transpose()?,
        })
    }
}
impl From<PoolCreate> for pb::PoolCreate {
    fn from(p: PoolCreate) -> Self {
        pb::PoolCreate {
            name: p.name.as_str().to_owned(),
            vdev: pb::VdevLayout::from(p.vdev) as i32,
            devices: strs(&p.devices),
            ashift: p.ashift.map(u32::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDeviceAdd {
    pub pool: PoolName,
    pub device: DevicePath,
}

impl TryFrom<pb::PoolDeviceAdd> for PoolDeviceAdd {
    type Error = ConvertError;
    fn try_from(p: pb::PoolDeviceAdd) -> Result<Self, ConvertError> {
        Ok(PoolDeviceAdd {
            pool: PoolName::new(p.pool)?,
            device: DevicePath::new(p.device)?,
        })
    }
}
impl From<PoolDeviceAdd> for pb::PoolDeviceAdd {
    fn from(p: PoolDeviceAdd) -> Self {
        pb::PoolDeviceAdd {
            pool: p.pool.as_str().to_owned(),
            device: p.device.as_str().to_owned(),
        }
    }
}

/// `zpool remove` (plus a `zpool wait -t remove` subtask, so the task only
/// finishes when evacuation completes). The whole task holds the mutate lock,
/// so a long evacuation blocks other mutations until it returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDeviceRemove {
    pub pool: PoolName,
    pub target: VdevTarget,
}

impl TryFrom<pb::PoolDeviceRemove> for PoolDeviceRemove {
    type Error = ConvertError;
    fn try_from(p: pb::PoolDeviceRemove) -> Result<Self, ConvertError> {
        Ok(PoolDeviceRemove {
            pool: PoolName::new(p.pool)?,
            target: VdevTarget::new(p.target)?,
        })
    }
}
impl From<PoolDeviceRemove> for pb::PoolDeviceRemove {
    fn from(p: PoolDeviceRemove) -> Self {
        pb::PoolDeviceRemove {
            pool: p.pool.as_str().to_owned(),
            target: p.target.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDeviceDetach {
    pub pool: PoolName,
    pub device: DevicePath,
}

impl TryFrom<pb::PoolDeviceDetach> for PoolDeviceDetach {
    type Error = ConvertError;
    fn try_from(p: pb::PoolDeviceDetach) -> Result<Self, ConvertError> {
        Ok(PoolDeviceDetach {
            pool: PoolName::new(p.pool)?,
            device: DevicePath::new(p.device)?,
        })
    }
}
impl From<PoolDeviceDetach> for pb::PoolDeviceDetach {
    fn from(p: PoolDeviceDetach) -> Self {
        pb::PoolDeviceDetach {
            pool: p.pool.as_str().to_owned(),
            device: p.device.as_str().to_owned(),
        }
    }
}

// ---- Partitioning ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionTableCreate {
    pub disk: BlockDev,
}

impl TryFrom<pb::PartitionTableCreate> for PartitionTableCreate {
    type Error = ConvertError;
    fn try_from(p: pb::PartitionTableCreate) -> Result<Self, ConvertError> {
        Ok(PartitionTableCreate {
            disk: BlockDev::new(p.disk)?,
        })
    }
}
impl From<PartitionTableCreate> for pb::PartitionTableCreate {
    fn from(p: PartitionTableCreate) -> Self {
        pb::PartitionTableCreate {
            disk: p.disk.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionCreate {
    pub disk: BlockDev,
    pub start_sector: Option<u64>,
    pub size_sectors: Option<u64>,
    pub label: PartLabel,
}

impl TryFrom<pb::PartitionCreate> for PartitionCreate {
    type Error = ConvertError;
    fn try_from(p: pb::PartitionCreate) -> Result<Self, ConvertError> {
        Ok(PartitionCreate {
            disk: BlockDev::new(p.disk)?,
            start_sector: p.start_sector,
            size_sectors: p.size_sectors,
            label: PartLabel::new(p.label)?,
        })
    }
}
impl From<PartitionCreate> for pb::PartitionCreate {
    fn from(p: PartitionCreate) -> Self {
        pb::PartitionCreate {
            disk: p.disk.as_str().to_owned(),
            start_sector: p.start_sector,
            size_sectors: p.size_sectors,
            label: p.label.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionDelete {
    pub disk: BlockDev,
    pub number: u32,
}

impl TryFrom<pb::PartitionDelete> for PartitionDelete {
    type Error = ConvertError;
    fn try_from(p: pb::PartitionDelete) -> Result<Self, ConvertError> {
        Ok(PartitionDelete {
            disk: BlockDev::new(p.disk)?,
            number: p.number,
        })
    }
}
impl From<PartitionDelete> for pb::PartitionDelete {
    fn from(p: PartitionDelete) -> Self {
        pb::PartitionDelete {
            disk: p.disk.as_str().to_owned(),
            number: p.number,
        }
    }
}

/// Shrink a partition *and its filesystem* in place (start sector preserved),
/// as one operation: the daemon probes the filesystem itself, refuses mounted
/// or unshrinkable filesystems, shrinks the filesystem first, then the
/// partition — the whole sequence under one mutate lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionShrink {
    pub disk: BlockDev,
    pub number: u32,
    pub size_sectors: u64,
}

impl TryFrom<pb::PartitionShrink> for PartitionShrink {
    type Error = ConvertError;
    fn try_from(p: pb::PartitionShrink) -> Result<Self, ConvertError> {
        Ok(PartitionShrink {
            disk: BlockDev::new(p.disk)?,
            number: p.number,
            size_sectors: p.size_sectors,
        })
    }
}
impl From<PartitionShrink> for pb::PartitionShrink {
    fn from(p: PartitionShrink) -> Self {
        pb::PartitionShrink {
            disk: p.disk.as_str().to_owned(),
            number: p.number,
            size_sectors: p.size_sectors,
        }
    }
}

// ---- SMART ----

/// Full `smartctl -x` dump for one device, collected verbatim by the web.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartReport {
    pub device: BlockDev,
}

impl TryFrom<pb::SmartReport> for SmartReport {
    type Error = ConvertError;
    fn try_from(s: pb::SmartReport) -> Result<Self, ConvertError> {
        Ok(SmartReport {
            device: BlockDev::new(s.device)?,
        })
    }
}
impl From<SmartReport> for pb::SmartReport {
    fn from(s: SmartReport) -> Self {
        pb::SmartReport {
            device: s.device.as_str().to_owned(),
        }
    }
}

/// Per-device SMART health + temperature for a batch of devices (typed reply).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartHealth {
    pub devices: Vec<BlockDev>,
}

impl TryFrom<pb::SmartHealth> for SmartHealth {
    type Error = ConvertError;
    fn try_from(s: pb::SmartHealth) -> Result<Self, ConvertError> {
        Ok(SmartHealth {
            devices: map_new(s.devices, BlockDev::new)?,
        })
    }
}
impl From<SmartHealth> for pb::SmartHealth {
    fn from(s: SmartHealth) -> Self {
        pb::SmartHealth {
            devices: strs(&s.devices),
        }
    }
}

// ---- LVM ----

/// A privileged `vgs`/`lvs`/`pvs --reportformat json` read; the web collects
/// and parses lvm's own JSON, so this stays a task stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LvmReport {
    pub what: LvmReportKind,
}

impl TryFrom<pb::LvmReport> for LvmReport {
    type Error = ConvertError;
    fn try_from(l: pb::LvmReport) -> Result<Self, ConvertError> {
        Ok(LvmReport {
            what: dec_lvm_report(l.what)?,
        })
    }
}
impl From<LvmReport> for pb::LvmReport {
    fn from(l: LvmReport) -> Self {
        pb::LvmReport {
            what: pb::LvmReportKind::from(l.what) as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VgCreate {
    pub name: VgName,
    pub devices: Vec<DevicePath>,
}

impl TryFrom<pb::VgCreate> for VgCreate {
    type Error = ConvertError;
    fn try_from(v: pb::VgCreate) -> Result<Self, ConvertError> {
        Ok(VgCreate {
            name: VgName::new(v.name)?,
            devices: map_new(v.devices, DevicePath::new)?,
        })
    }
}
impl From<VgCreate> for pb::VgCreate {
    fn from(v: VgCreate) -> Self {
        pb::VgCreate {
            name: v.name.as_str().to_owned(),
            devices: strs(&v.devices),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VgExtend {
    pub vg: VgName,
    pub device: DevicePath,
}

impl TryFrom<pb::VgExtend> for VgExtend {
    type Error = ConvertError;
    fn try_from(v: pb::VgExtend) -> Result<Self, ConvertError> {
        Ok(VgExtend {
            vg: VgName::new(v.vg)?,
            device: DevicePath::new(v.device)?,
        })
    }
}
impl From<VgExtend> for pb::VgExtend {
    fn from(v: VgExtend) -> Self {
        pb::VgExtend {
            vg: v.vg.as_str().to_owned(),
            device: v.device.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VgReduce {
    pub vg: VgName,
    pub device: DevicePath,
}

impl TryFrom<pb::VgReduce> for VgReduce {
    type Error = ConvertError;
    fn try_from(v: pb::VgReduce) -> Result<Self, ConvertError> {
        Ok(VgReduce {
            vg: VgName::new(v.vg)?,
            device: DevicePath::new(v.device)?,
        })
    }
}
impl From<VgReduce> for pb::VgReduce {
    fn from(v: VgReduce) -> Self {
        pb::VgReduce {
            vg: v.vg.as_str().to_owned(),
            device: v.device.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VgRemove {
    pub vg: VgName,
}

impl TryFrom<pb::VgRemove> for VgRemove {
    type Error = ConvertError;
    fn try_from(v: pb::VgRemove) -> Result<Self, ConvertError> {
        Ok(VgRemove {
            vg: VgName::new(v.vg)?,
        })
    }
}
impl From<VgRemove> for pb::VgRemove {
    fn from(v: VgRemove) -> Self {
        pb::VgRemove {
            vg: v.vg.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvCreate {
    pub vg: VgName,
    pub name: LvName,
    pub size: u64,
}

impl TryFrom<pb::LvCreate> for LvCreate {
    type Error = ConvertError;
    fn try_from(l: pb::LvCreate) -> Result<Self, ConvertError> {
        Ok(LvCreate {
            vg: VgName::new(l.vg)?,
            name: LvName::new(l.name)?,
            size: l.size,
        })
    }
}
impl From<LvCreate> for pb::LvCreate {
    fn from(l: LvCreate) -> Self {
        pb::LvCreate {
            vg: l.vg.as_str().to_owned(),
            name: l.name.as_str().to_owned(),
            size: l.size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThinPoolCreate {
    pub vg: VgName,
    pub name: LvName,
    pub size: u64,
}

impl TryFrom<pb::ThinPoolCreate> for ThinPoolCreate {
    type Error = ConvertError;
    fn try_from(t: pb::ThinPoolCreate) -> Result<Self, ConvertError> {
        Ok(ThinPoolCreate {
            vg: VgName::new(t.vg)?,
            name: LvName::new(t.name)?,
            size: t.size,
        })
    }
}
impl From<ThinPoolCreate> for pb::ThinPoolCreate {
    fn from(t: ThinPoolCreate) -> Self {
        pb::ThinPoolCreate {
            vg: t.vg.as_str().to_owned(),
            name: t.name.as_str().to_owned(),
            size: t.size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThinLvCreate {
    pub vg: VgName,
    pub pool: LvName,
    pub name: LvName,
    pub virtual_size: u64,
}

impl TryFrom<pb::ThinLvCreate> for ThinLvCreate {
    type Error = ConvertError;
    fn try_from(t: pb::ThinLvCreate) -> Result<Self, ConvertError> {
        Ok(ThinLvCreate {
            vg: VgName::new(t.vg)?,
            pool: LvName::new(t.pool)?,
            name: LvName::new(t.name)?,
            virtual_size: t.virtual_size,
        })
    }
}
impl From<ThinLvCreate> for pb::ThinLvCreate {
    fn from(t: ThinLvCreate) -> Self {
        pb::ThinLvCreate {
            vg: t.vg.as_str().to_owned(),
            pool: t.pool.as_str().to_owned(),
            name: t.name.as_str().to_owned(),
            virtual_size: t.virtual_size,
        }
    }
}

/// Grow a logical volume (`lvextend`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvResize {
    pub vg: VgName,
    pub name: LvName,
    pub new_size: u64,
}

impl TryFrom<pb::LvResize> for LvResize {
    type Error = ConvertError;
    fn try_from(l: pb::LvResize) -> Result<Self, ConvertError> {
        Ok(LvResize {
            vg: VgName::new(l.vg)?,
            name: LvName::new(l.name)?,
            new_size: l.new_size,
        })
    }
}
impl From<LvResize> for pb::LvResize {
    fn from(l: LvResize) -> Self {
        pb::LvResize {
            vg: l.vg.as_str().to_owned(),
            name: l.name.as_str().to_owned(),
            new_size: l.new_size,
        }
    }
}

/// Shrink a logical volume (`lvreduce -f`; destructive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvShrink {
    pub vg: VgName,
    pub name: LvName,
    pub new_size: u64,
}

impl TryFrom<pb::LvShrink> for LvShrink {
    type Error = ConvertError;
    fn try_from(l: pb::LvShrink) -> Result<Self, ConvertError> {
        Ok(LvShrink {
            vg: VgName::new(l.vg)?,
            name: LvName::new(l.name)?,
            new_size: l.new_size,
        })
    }
}
impl From<LvShrink> for pb::LvShrink {
    fn from(l: LvShrink) -> Self {
        pb::LvShrink {
            vg: l.vg.as_str().to_owned(),
            name: l.name.as_str().to_owned(),
            new_size: l.new_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvRename {
    pub vg: VgName,
    pub name: LvName,
    pub new_name: LvName,
}

impl TryFrom<pb::LvRename> for LvRename {
    type Error = ConvertError;
    fn try_from(l: pb::LvRename) -> Result<Self, ConvertError> {
        Ok(LvRename {
            vg: VgName::new(l.vg)?,
            name: LvName::new(l.name)?,
            new_name: LvName::new(l.new_name)?,
        })
    }
}
impl From<LvRename> for pb::LvRename {
    fn from(l: LvRename) -> Self {
        pb::LvRename {
            vg: l.vg.as_str().to_owned(),
            name: l.name.as_str().to_owned(),
            new_name: l.new_name.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvDelete {
    pub vg: VgName,
    pub name: LvName,
}

impl TryFrom<pb::LvDelete> for LvDelete {
    type Error = ConvertError;
    fn try_from(l: pb::LvDelete) -> Result<Self, ConvertError> {
        Ok(LvDelete {
            vg: VgName::new(l.vg)?,
            name: LvName::new(l.name)?,
        })
    }
}
impl From<LvDelete> for pb::LvDelete {
    fn from(l: LvDelete) -> Self {
        pb::LvDelete {
            vg: l.vg.as_str().to_owned(),
            name: l.name.as_str().to_owned(),
        }
    }
}

// ---- System ----

/// Enable Soft-RoCE on `netdev` as one task: load the rxe kernel module
/// (skipped if already loaded), then add the rdma link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxeAdd {
    pub netdev: NetdevName,
}

impl TryFrom<pb::RxeAdd> for RxeAdd {
    type Error = ConvertError;
    fn try_from(r: pb::RxeAdd) -> Result<Self, ConvertError> {
        Ok(RxeAdd {
            netdev: NetdevName::new(r.netdev)?,
        })
    }
}
impl From<RxeAdd> for pb::RxeAdd {
    fn from(r: RxeAdd) -> Self {
        pb::RxeAdd {
            netdev: r.netdev.as_str().to_owned(),
        }
    }
}

/// Turn on hardware RoCE for `netdev`: the daemon detects the vendor, probes
/// its enable parameter, and (only if present and off) sets it and reloads the
/// device — the whole vendor-specific flow lives behind the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableRoce {
    pub netdev: NetdevName,
}

impl TryFrom<pb::EnableRoce> for EnableRoce {
    type Error = ConvertError;
    fn try_from(e: pb::EnableRoce) -> Result<Self, ConvertError> {
        Ok(EnableRoce {
            netdev: NetdevName::new(e.netdev)?,
        })
    }
}
impl From<EnableRoce> for pb::EnableRoce {
    fn from(e: EnableRoce) -> Self {
        pb::EnableRoce {
            netdev: e.netdev.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPackages {
    pub packages: Vec<PackageName>,
}

impl TryFrom<pb::InstallPackages> for InstallPackages {
    type Error = ConvertError;
    fn try_from(i: pb::InstallPackages) -> Result<Self, ConvertError> {
        Ok(InstallPackages {
            packages: map_new(i.packages, PackageName::new)?,
        })
    }
}
impl From<InstallPackages> for pb::InstallPackages {
    fn from(i: InstallPackages) -> Self {
        pb::InstallPackages {
            packages: strs(&i.packages),
        }
    }
}

// ---- CSI exports ----
//
// Imperative, idempotent, and scoped by type: every subsystem these ops can
// name is a `CsiNqn`, whose prefix is a sibling of (not nested under) the
// web-managed prefix — reconcile treats CSI subsystems as foreign, so the two
// owners never fight over the same configfs objects.

/// Idempotent upsert of one CSI export: subsystem (`allow_any_host=0`),
/// namespace 1 with the pinned `device_uuid` (written before enable, so the
/// initiator's `/dev/disk/by-id` path is deterministic and no read-back rpc is
/// needed), the dedicated CSI port ensured, and the subsystem linked to it.
/// Never touches `allowed_hosts`: grants survive re-apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiNvmeApply {
    pub nqn: CsiNqn,
    pub device_path: DevicePath,
    pub device_uuid: NsUuid,
    pub traddr: IpAddr,
    pub trsvcid: u16,
    pub transport: Transport,
}

impl TryFrom<pb::CsiNvmeApply> for CsiNvmeApply {
    type Error = ConvertError;
    fn try_from(a: pb::CsiNvmeApply) -> Result<Self, ConvertError> {
        Ok(CsiNvmeApply {
            nqn: CsiNqn::new(a.nqn)?,
            device_path: DevicePath::new(a.device_path)?,
            device_uuid: NsUuid::new(a.device_uuid)?,
            traddr: parse_ip(&a.traddr)?,
            trsvcid: to_u16(a.trsvcid, "trsvcid")?,
            transport: dec_transport(a.transport)?,
        })
    }
}
impl From<CsiNvmeApply> for pb::CsiNvmeApply {
    fn from(a: CsiNvmeApply) -> Self {
        pb::CsiNvmeApply {
            nqn: a.nqn.as_str().to_owned(),
            device_path: a.device_path.as_str().to_owned(),
            device_uuid: a.device_uuid.as_str().to_owned(),
            traddr: a.traddr.to_string(),
            trsvcid: u32::from(a.trsvcid),
            transport: pb::Transport::from(a.transport) as i32,
        }
    }
}

/// Absent-tolerant teardown; also reaps the CSI port once its last link is
/// gone (an empty port's id would otherwise be reclaimable by the renderer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiNvmeDelete {
    pub nqn: CsiNqn,
}

impl TryFrom<pb::CsiNvmeDelete> for CsiNvmeDelete {
    type Error = ConvertError;
    fn try_from(d: pb::CsiNvmeDelete) -> Result<Self, ConvertError> {
        Ok(CsiNvmeDelete {
            nqn: CsiNqn::new(d.nqn)?,
        })
    }
}
impl From<CsiNvmeDelete> for pb::CsiNvmeDelete {
    fn from(d: CsiNvmeDelete) -> Self {
        pb::CsiNvmeDelete {
            nqn: d.nqn.as_str().to_owned(),
        }
    }
}

/// Add one initiator NQN to the subsystem's `allowed_hosts` (the attach ACL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiHostGrant {
    pub nqn: CsiNqn,
    pub hostnqn: Nqn,
}

impl TryFrom<pb::CsiHostGrant> for CsiHostGrant {
    type Error = ConvertError;
    fn try_from(g: pb::CsiHostGrant) -> Result<Self, ConvertError> {
        Ok(CsiHostGrant {
            nqn: CsiNqn::new(g.nqn)?,
            hostnqn: Nqn::new(g.hostnqn)?,
        })
    }
}
impl From<CsiHostGrant> for pb::CsiHostGrant {
    fn from(g: CsiHostGrant) -> Self {
        pb::CsiHostGrant {
            nqn: g.nqn.as_str().to_owned(),
            hostnqn: g.hostnqn.as_str().to_owned(),
        }
    }
}

/// The fence, three steps in strict order: drop the host from `allowed_hosts`
/// (closes the door — the kernel rejects its reconnect with DNR, so the
/// initiator deletes its own controller), unlink the subsystem from the CSI
/// port (severs live controllers), relink. The ACL edit precedes the relink
/// so the fenced host cannot slip back in through the reopened port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiHostRevoke {
    pub nqn: CsiNqn,
    pub hostnqn: Nqn,
}

impl TryFrom<pb::CsiHostRevoke> for CsiHostRevoke {
    type Error = ConvertError;
    fn try_from(r: pb::CsiHostRevoke) -> Result<Self, ConvertError> {
        Ok(CsiHostRevoke {
            nqn: CsiNqn::new(r.nqn)?,
            hostnqn: Nqn::new(r.hostnqn)?,
        })
    }
}
impl From<CsiHostRevoke> for pb::CsiHostRevoke {
    fn from(r: CsiHostRevoke) -> Self {
        pb::CsiHostRevoke {
            nqn: r.nqn.as_str().to_owned(),
            hostnqn: r.hostnqn.as_str().to_owned(),
        }
    }
}

/// Target-side volume expansion as one intent: resize the zvol backing
/// namespace 1 (the dataset is derived from the subsystem's own
/// `device_path`, so the `CsiNqn` scopes what can be resized), then
/// revalidate the namespace size so initiators see the new capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsiVolumeExpand {
    pub nqn: CsiNqn,
    pub new_size: u64,
}

impl TryFrom<pb::CsiVolumeExpand> for CsiVolumeExpand {
    type Error = ConvertError;
    fn try_from(e: pb::CsiVolumeExpand) -> Result<Self, ConvertError> {
        Ok(CsiVolumeExpand {
            nqn: CsiNqn::new(e.nqn)?,
            new_size: e.new_size,
        })
    }
}
impl From<CsiVolumeExpand> for pb::CsiVolumeExpand {
    fn from(e: CsiVolumeExpand) -> Self {
        pb::CsiVolumeExpand {
            nqn: e.nqn.as_str().to_owned(),
            new_size: e.new_size,
        }
    }
}

// ---- SSH pipe keys ----

/// The longest paste accepted before parsing. An RSA-4096 public key line is
/// under 800 bytes; the ceiling exists so a hostile paste cannot make the
/// parser chew megabytes.
const MAX_PUBLIC_KEY_LEN: usize = 16 * 1024;
/// Comment (label) ceiling — it is echoed back on the page and written to
/// `authorized_keys`.
const MAX_COMMENT_LEN: usize = 200;

/// An OpenSSH public key, parsed and re-serialized into its canonical
/// one-line form. Constructing this is the ingress choke point for
/// [`PipeKeyAdd`]: nothing the admin pasted reaches `authorized_keys`
/// verbatim, so a newline, a quote, a CRLF, a NUL, or an options prefix
/// cannot smuggle a second entry — or a shell — into the file.
///
/// The daemon, never the caller, prepends the `command="…",restrict` options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKeyLine {
    canonical: String,
    algorithm: String,
    comment: String,
    fingerprint: SshFingerprint,
}

impl SshPublicKeyLine {
    pub fn new(input: impl Into<String>) -> Result<Self, ValidationError> {
        let input = input.into();
        // The raw paste is never echoed back: a rejected value may be a
        // private key someone pasted into the wrong box.
        let invalid = || ValidationError {
            what: "SSH public key",
            value: String::new(),
        };
        if input.len() > MAX_PUBLIC_KEY_LEN {
            return Err(invalid());
        }
        // Surrounding whitespace is what a copy-paste carries; a line break
        // *inside* the key is an attempt at a second authorized_keys entry.
        let input = input.trim();
        if input.contains(['\n', '\r', '\0']) {
            return Err(invalid());
        }
        let mut key = ssh_key::PublicKey::from_openssh(input).map_err(|_| invalid())?;
        // The comment is the only attacker-controlled text that survives into
        // the file; keep it to printable ASCII, and drop the characters that
        // delimit an authorized_keys options field.
        let comment: String = key
            .comment()
            .chars()
            .filter(|c| (c.is_ascii_graphic() || *c == ' ') && !"\"\\".contains(*c))
            .take(MAX_COMMENT_LEN)
            .collect();
        key.set_comment(comment.trim());
        let canonical = key.to_openssh().map_err(|_| invalid())?;
        if canonical.contains(['\n', '\r', '\0']) {
            return Err(invalid());
        }
        let fingerprint =
            SshFingerprint::new(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
                .map_err(|_| invalid())?;
        Ok(Self {
            canonical,
            algorithm: key.algorithm().as_str().to_owned(),
            comment: key.comment().to_owned(),
            fingerprint,
        })
    }

    /// The `<algorithm> <base64> [comment]` line, safe to write verbatim.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Just `<algorithm> <base64>` — a `known_hosts` entry carries no comment.
    pub fn key_only(&self) -> &str {
        let mut spaces = self.canonical.match_indices(' ').map(|(i, _)| i);
        match (spaces.next(), spaces.next()) {
            (Some(_), Some(second)) => &self.canonical[..second],
            _ => &self.canonical,
        }
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The sanitized comment — the key's human label.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    pub fn fingerprint(&self) -> &SshFingerprint {
        &self.fingerprint
    }
}

/// Authorize a public key to open a `greendotctl pipe` session as the
/// packaged SSH user. The request carries only the key: the daemon
/// synthesizes the forced command, so a compromised web cannot widen the
/// grant to a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeKeyAdd {
    pub public_key: SshPublicKeyLine,
}

impl TryFrom<pb::PipeKeyAdd> for PipeKeyAdd {
    type Error = ConvertError;
    fn try_from(a: pb::PipeKeyAdd) -> Result<Self, ConvertError> {
        Ok(PipeKeyAdd {
            public_key: SshPublicKeyLine::new(a.public_key)?,
        })
    }
}
impl From<PipeKeyAdd> for pb::PipeKeyAdd {
    fn from(a: PipeKeyAdd) -> Self {
        pb::PipeKeyAdd {
            public_key: a.public_key.canonical,
        }
    }
}

/// Revoke a key by fingerprint — the stable id, so a line this UI never wrote
/// can still be removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeKeyRevoke {
    pub fingerprint: SshFingerprint,
}

impl TryFrom<pb::PipeKeyRevoke> for PipeKeyRevoke {
    type Error = ConvertError;
    fn try_from(r: pb::PipeKeyRevoke) -> Result<Self, ConvertError> {
        Ok(PipeKeyRevoke {
            fingerprint: SshFingerprint::new(r.fingerprint)?,
        })
    }
}
impl From<PipeKeyRevoke> for pb::PipeKeyRevoke {
    fn from(r: PipeKeyRevoke) -> Self {
        pb::PipeKeyRevoke {
            fingerprint: r.fingerprint.as_str().to_owned(),
        }
    }
}

// ---- Fieldless ops ----

unit_op!(
    /// Every fact the SSH-access page and its diagnostic need: the packaged
    /// user, its `.ssh` permissions, the authorized keys, and the box's own
    /// host keys. Typed reply.
    PipeAccessReport, pb::Empty);
unit_op!(
    /// The full desired-state reconcile pass, one subtask per area. Carries
    /// nothing: the daemon reconciles against its own `--config`, so the peer
    /// cannot name a file for root to read.
    Reconcile, pb::Reconcile);
unit_op!(
    /// Live RDMA connections (`rdma -j resource show cm_id`), streamed as the
    /// tool's own JSON for the web to parse.
    RdmaResources, pb::Empty);
unit_op!(
    /// NFS actual state (`exportfs -s` + the nfsd portlist), typed reply.
    NfsReport, pb::Empty);
unit_op!(
    /// The nvmet configfs tree, typed reply.
    NvmetReport, pb::Empty);
unit_op!(
    /// The LIO configfs tree, typed reply.
    LioReport, pb::Empty);
unit_op!(
    /// Live iSCSI sessions, typed reply.
    LioSessions, pb::Empty);
unit_op!(
    /// RDMA devices from sysfs, typed reply.
    RdmaDevices, pb::Empty);
unit_op!(
    /// The live PCI-address → IPs map, typed reply.
    NicPciAddrs, pb::Empty);
unit_op!(
    /// Every NIC's RDMA status (structural classification + vendor overlay,
    /// combined daemon-side so the web stays vendor-free), typed reply.
    NicInterfaces, pb::Empty);
unit_op!(
    /// The RoCE-capable NIC inventory (vendor classification), typed reply.
    RoceCapableNics, pb::Empty);
unit_op!(
    /// Per-NIC RDMA advisories (opaque vendor-aware diagnostics), typed reply.
    NicRdmaAdvice, pb::Empty);
unit_op!(
    /// The desired-vs-actual drift pre-check (no apply), typed reply.
    ReconcileDryRun, pb::Empty);

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// domain -> pb -> wire bytes -> pb -> domain must be the identity, through
    /// the real prost encode/decode. One macro arm per op keeps the corpus in a
    /// single test without re-spelling the plumbing.
    macro_rules! roundtrip {
        ($op:expr => $wire:ty) => {{
            let op = $op;
            let bytes = <$wire>::from(op.clone()).encode_to_vec();
            let decoded = <$wire>::decode(bytes.as_slice()).unwrap();
            assert_eq!(TryInto::try_into(decoded), Ok(op));
        }};
    }

    #[test]
    fn ops_wire_roundtrip() {
        roundtrip!(ZvolCreate {
            dataset: DatasetName::new("tank/vols/vm1").unwrap(),
            size: 10 << 30,
            volblocksize: Some(16384),
            sparse: true,
        } => pb::ZvolCreate);
        roundtrip!(ZvolCreate {
            dataset: DatasetName::new("tank/vols/vm1").unwrap(),
            size: 10 << 30,
            volblocksize: None,
            sparse: false,
        } => pb::ZvolCreate);
        roundtrip!(ZvolDelete { dataset: DatasetName::new("tank/x").unwrap() } => pb::ZvolDelete);
        roundtrip!(ZvolResize { dataset: DatasetName::new("tank/x").unwrap(), new_size: 7 << 30 } => pb::ZvolResize);
        roundtrip!(SnapshotCreate {
            dataset: DatasetName::new("tank/x").unwrap(),
            snap: SnapName::new("daily").unwrap(),
        } => pb::SnapshotCreate);
        roundtrip!(SnapshotDestroy {
            dataset: DatasetName::new("tank/x").unwrap(),
            snap: SnapName::new("daily").unwrap(),
        } => pb::SnapshotDestroy);
        roundtrip!(ZfsFsCreate {
            dataset: DatasetName::new("tank/share").unwrap(),
            mountpoint: Some(MountPoint::new("/srv/share").unwrap()),
        } => pb::ZfsFsCreate);
        roundtrip!(ZfsSetMountpoint {
            dataset: DatasetName::new("tank/share").unwrap(),
            mountpoint: MountPoint::new("/srv/share").unwrap(),
        } => pb::ZfsSetMountpoint);
        roundtrip!(ZfsMount { dataset: DatasetName::new("tank/share").unwrap() } => pb::ZfsMount);
        roundtrip!(ZfsUnmount { dataset: DatasetName::new("tank/share").unwrap() } => pb::ZfsUnmount);
        roundtrip!(ZfsDestroy { dataset: DatasetName::new("tank/share").unwrap(), recursive: true } => pb::ZfsDestroy);
        roundtrip!(PoolCreate {
            name: PoolName::new("tank").unwrap(),
            vdev: VdevLayout::Mirror,
            devices: vec![
                DevicePath::new("/dev/sdb").unwrap(),
                DevicePath::new("/dev/sdc").unwrap(),
            ],
            ashift: Some(12),
        } => pb::PoolCreate);
        roundtrip!(PoolDeviceAdd {
            pool: PoolName::new("tank").unwrap(),
            device: DevicePath::new("/dev/sdd").unwrap(),
        } => pb::PoolDeviceAdd);
        roundtrip!(PoolDeviceRemove {
            pool: PoolName::new("tank").unwrap(),
            target: VdevTarget::new("mirror-0").unwrap(),
        } => pb::PoolDeviceRemove);
        roundtrip!(PoolDeviceRemove {
            pool: PoolName::new("tank").unwrap(),
            target: VdevTarget::new("/dev/sdd").unwrap(),
        } => pb::PoolDeviceRemove);
        roundtrip!(PoolDeviceDetach {
            pool: PoolName::new("tank").unwrap(),
            device: DevicePath::new("/dev/sdc").unwrap(),
        } => pb::PoolDeviceDetach);
        roundtrip!(PartitionTableCreate { disk: BlockDev::new("sdb").unwrap() } => pb::PartitionTableCreate);
        roundtrip!(PartitionCreate {
            disk: BlockDev::new("sdb").unwrap(),
            start_sector: None,
            size_sectors: Some(2097152),
            label: PartLabel::new("data").unwrap(),
        } => pb::PartitionCreate);
        roundtrip!(PartitionDelete { disk: BlockDev::new("sdb").unwrap(), number: 2 } => pb::PartitionDelete);
        roundtrip!(PartitionShrink {
            disk: BlockDev::new("sdb").unwrap(),
            number: 2,
            size_sectors: 2097152,
        } => pb::PartitionShrink);
        roundtrip!(SmartReport { device: BlockDev::new("sda").unwrap() } => pb::SmartReport);
        roundtrip!(SmartHealth {
            devices: vec![BlockDev::new("sda").unwrap(), BlockDev::new("nvme0n1").unwrap()],
        } => pb::SmartHealth);
        roundtrip!(LvmReport { what: LvmReportKind::Lvs } => pb::LvmReport);
        roundtrip!(VgCreate {
            name: VgName::new("vg0").unwrap(),
            devices: vec![DevicePath::new("/dev/sdb").unwrap()],
        } => pb::VgCreate);
        roundtrip!(VgExtend {
            vg: VgName::new("vg0").unwrap(),
            device: DevicePath::new("/dev/sdc").unwrap(),
        } => pb::VgExtend);
        roundtrip!(VgReduce {
            vg: VgName::new("vg0").unwrap(),
            device: DevicePath::new("/dev/sdc").unwrap(),
        } => pb::VgReduce);
        roundtrip!(VgRemove { vg: VgName::new("vg0").unwrap() } => pb::VgRemove);
        roundtrip!(LvCreate {
            vg: VgName::new("vg0").unwrap(),
            name: LvName::new("data").unwrap(),
            size: 10 << 30,
        } => pb::LvCreate);
        roundtrip!(ThinPoolCreate {
            vg: VgName::new("vg0").unwrap(),
            name: LvName::new("pool0").unwrap(),
            size: 50 << 30,
        } => pb::ThinPoolCreate);
        roundtrip!(ThinLvCreate {
            vg: VgName::new("vg0").unwrap(),
            pool: LvName::new("pool0").unwrap(),
            name: LvName::new("vm1").unwrap(),
            virtual_size: 20 << 30,
        } => pb::ThinLvCreate);
        roundtrip!(LvResize {
            vg: VgName::new("vg0").unwrap(),
            name: LvName::new("data").unwrap(),
            new_size: 12 << 30,
        } => pb::LvResize);
        roundtrip!(LvShrink {
            vg: VgName::new("vg0").unwrap(),
            name: LvName::new("data").unwrap(),
            new_size: 8 << 30,
        } => pb::LvShrink);
        roundtrip!(LvRename {
            vg: VgName::new("vg0").unwrap(),
            name: LvName::new("data").unwrap(),
            new_name: LvName::new("archive").unwrap(),
        } => pb::LvRename);
        roundtrip!(LvDelete {
            vg: VgName::new("vg0").unwrap(),
            name: LvName::new("data").unwrap(),
        } => pb::LvDelete);
        roundtrip!(RxeAdd { netdev: NetdevName::new("eth0").unwrap() } => pb::RxeAdd);
        roundtrip!(EnableRoce { netdev: NetdevName::new("ens16").unwrap() } => pb::EnableRoce);
        roundtrip!(InstallPackages {
            packages: vec![PackageName::new("nvme-cli").unwrap()],
        } => pb::InstallPackages);
        roundtrip!(Reconcile => pb::Reconcile);
        roundtrip!(Authenticate {
            username: Username::new("alice").unwrap(),
            password: Secret("hunter2".into()),
        } => pb::Authenticate);
        roundtrip!(ZfsClone {
            dataset: DatasetName::new("tank/csi/pvc-1").unwrap(),
            snap: SnapName::new("csi-snap-1").unwrap(),
            target: DatasetName::new("tank/csi/pvc-2").unwrap(),
            new_size: Some(20 << 30),
        } => pb::ZfsClone);
        roundtrip!(ZfsClone {
            dataset: DatasetName::new("tank/csi/pvc-1").unwrap(),
            snap: SnapName::new("csi-snap-1").unwrap(),
            target: DatasetName::new("tank/csi/pvc-2").unwrap(),
            new_size: None,
        } => pb::ZfsClone);
        roundtrip!(ZvolInfo { dataset: DatasetName::new("tank/csi/pvc-1").unwrap() } => pb::ZvolInfo);
        roundtrip!(CsiNvmeApply {
            nqn: CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap(),
            device_path: DevicePath::new("/dev/zvol/tank/csi/pvc-1").unwrap(),
            device_uuid: NsUuid::new("58668891-c3e4-45d0-b90e-824525c16080").unwrap(),
            traddr: "10.0.0.5".parse().unwrap(),
            trsvcid: 4421,
            transport: Transport::Rdma,
        } => pb::CsiNvmeApply);
        roundtrip!(CsiNvmeDelete {
            nqn: CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap(),
        } => pb::CsiNvmeDelete);
        roundtrip!(CsiHostGrant {
            nqn: CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap(),
            hostnqn: Nqn::new("nqn.2014-08.org.nvmexpress:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap(),
        } => pb::CsiHostGrant);
        roundtrip!(CsiHostRevoke {
            nqn: CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap(),
            hostnqn: Nqn::new("nqn.2014-08.org.nvmexpress:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap(),
        } => pb::CsiHostRevoke);
        roundtrip!(CsiVolumeExpand {
            nqn: CsiNqn::new("nqn.2026-06.io.greendot.csi:pvc-1").unwrap(),
            new_size: 30 << 30,
        } => pb::CsiVolumeExpand);
        roundtrip!(PipeKeyAdd {
            public_key: SshPublicKeyLine::new(ED25519_KEY).unwrap(),
        } => pb::PipeKeyAdd);
        roundtrip!(PipeKeyRevoke {
            fingerprint: SshFingerprint::new(ED25519_FP).unwrap(),
        } => pb::PipeKeyRevoke);
    }

    const ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 admin@laptop";
    const ED25519_FP: &str = "SHA256:NEU/y0JmR4RY7ck8XRGElQSKmEzy2SirhXgqbFWxZ00";

    /// A pasted key is parsed, fingerprinted, and re-serialized canonically —
    /// what lands in `authorized_keys` is our bytes, never the admin's.
    #[test]
    fn public_key_is_canonicalized_and_fingerprinted() {
        let key = SshPublicKeyLine::new(format!("  {ED25519_KEY}  \n")).unwrap();
        assert_eq!(key.canonical(), ED25519_KEY);
        assert_eq!(key.fingerprint().as_str(), ED25519_FP);
        assert_eq!(key.algorithm(), "ssh-ed25519");
        // The comment is the only free text that survives; quotes and
        // backslashes — the authorized_keys options delimiters — are dropped.
        let base = ED25519_KEY.rsplit_once(' ').unwrap().0;
        let key = SshPublicKeyLine::new(format!(r#"{base} we"ird\ label"#)).unwrap();
        assert_eq!(key.canonical(), format!("{base} weird label"));
    }

    /// Every way a paste could smuggle a second `authorized_keys` line — or a
    /// shell — past the daemon. All must fail before the key is ever written.
    #[rstest::rstest]
    #[case::empty("")]
    #[case::not_a_key("hello")]
    #[case::newline_second_line(concat!(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 a\n",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 b"))]
    #[case::crlf(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26\r\nx"
    )]
    #[case::nul(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26\0"
    )]
    // An options prefix is not an algorithm id: options can only come from the daemon.
    #[case::options_prefix(concat!(
        r#"command="/bin/sh" "#,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26"))]
    // The algorithm id must match the algorithm inside the base64 blob.
    #[case::algorithm_mismatch(
        "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26"
    )]
    #[case::not_base64("ssh-ed25519 not-base64 admin@laptop")]
    #[case::private_key("-----BEGIN OPENSSH PRIVATE KEY-----")]
    fn hostile_pastes_are_rejected(#[case] paste: &str) {
        assert!(SshPublicKeyLine::new(paste).is_err());
        assert!(
            PipeKeyAdd::try_from(pb::PipeKeyAdd {
                public_key: paste.into()
            })
            .is_err()
        );
    }

    #[test]
    fn oversized_paste_is_rejected_before_parsing() {
        assert!(SshPublicKeyLine::new("A".repeat(MAX_PUBLIC_KEY_LEN + 1)).is_err());
    }

    /// A rejected paste may be a private key someone put in the wrong box; the
    /// error must not carry it.
    #[test]
    fn rejection_does_not_echo_the_paste() {
        let err = SshPublicKeyLine::new("super-secret").unwrap_err();
        assert_eq!(err.value, "");
    }

    /// Ingress `TryFrom` rejects invalid payloads built directly on the wire
    /// types (as a malicious/buggy client could) — validation must still run
    /// at the proto->domain boundary, prost does not run it for us.
    #[test]
    fn invalid_payloads_are_rejected_on_ingress() {
        assert!(
            ZvolDelete::try_from(pb::ZvolDelete {
                dataset: "../../etc".into(),
            })
            .is_err()
        );
        assert!(
            RxeAdd::try_from(pb::RxeAdd {
                netdev: "eth0/../x".into(),
            })
            .is_err()
        );
        assert!(
            InstallPackages::try_from(pb::InstallPackages {
                packages: vec!["foo;rm -rf".into()],
            })
            .is_err()
        );
        assert!(
            PoolCreate::try_from(pb::PoolCreate {
                name: "mirror".into(), // reserved vdev keyword
                vdev: pb::VdevLayout::Stripe as i32,
                devices: vec!["/dev/sdb".into()],
                ashift: None,
            })
            .is_err()
        );
        assert!(
            PoolCreate::try_from(pb::PoolCreate {
                name: "tank".into(),
                vdev: 0, // VDEV_LAYOUT_UNSPECIFIED
                devices: vec!["/dev/sdb".into()],
                ashift: None,
            })
            .is_err()
        );
        assert!(
            LvDelete::try_from(pb::LvDelete {
                vg: "vg0".into(),
                name: "../x".into(),
            })
            .is_err()
        );
        assert!(
            VgCreate::try_from(pb::VgCreate {
                name: "-bad".into(),
                devices: vec!["/dev/sdb".into()],
            })
            .is_err()
        );
        assert!(
            PartitionShrink::try_from(pb::PartitionShrink {
                disk: "../sda".into(),
                number: 1,
                size_sectors: 1024,
            })
            .is_err()
        );
        assert!(
            EnableRoce::try_from(pb::EnableRoce {
                netdev: "eth0 ; reboot".into(),
            })
            .is_err()
        );
        assert!(
            ZfsMount::try_from(pb::ZfsMount {
                dataset: "../../etc".into(),
            })
            .is_err()
        );
        assert!(
            ZfsSetMountpoint::try_from(pb::ZfsSetMountpoint {
                dataset: "tank/share".into(),
                mountpoint: "/tank/../etc".into(),
            })
            .is_err()
        );
        assert!(
            Authenticate::try_from(pb::Authenticate {
                username: "root; reboot".into(),
                password: "x".into(),
            })
            .is_err()
        );
        assert!(
            PoolDeviceRemove::try_from(pb::PoolDeviceRemove {
                pool: "tank".into(),
                target: "mirror".into(), // bare keyword, not a vdev name
            })
            .is_err()
        );
        assert!(
            PoolDeviceRemove::try_from(pb::PoolDeviceRemove {
                pool: "tank".into(),
                target: "sdd; reboot".into(),
            })
            .is_err()
        );
        assert!(
            PoolDeviceDetach::try_from(pb::PoolDeviceDetach {
                pool: "tank".into(),
                device: "mirror-0".into(), // containers are not detachable
            })
            .is_err()
        );
        // The CSI ops must reject: a web-prefix NQN (the ownership boundary),
        // a malformed uuid, a traversal device path, a bad host NQN, and a
        // bad clone target — each through the same ingress choke point.
        let csi_ok = "nqn.2026-06.io.greendot.csi:pvc-1";
        let apply_ok = pb::CsiNvmeApply {
            nqn: csi_ok.into(),
            device_path: "/dev/zvol/tank/csi/pvc-1".into(),
            device_uuid: "58668891-c3e4-45d0-b90e-824525c16080".into(),
            traddr: "10.0.0.5".into(),
            trsvcid: 4421,
            transport: pb::Transport::Rdma as i32,
        };
        assert!(CsiNvmeApply::try_from(apply_ok.clone()).is_ok());
        for bad in [
            pb::CsiNvmeApply {
                nqn: "nqn.2026-06.io.greendot:vm1".into(), // web-managed prefix
                ..apply_ok.clone()
            },
            pb::CsiNvmeApply {
                nqn: "nqn.2026-06.io.greendot.csi:".into(), // empty suffix
                ..apply_ok.clone()
            },
            pb::CsiNvmeApply {
                device_uuid: "58668891-C3E4-45D0-B90E-824525C16080".into(), // uppercase
                ..apply_ok.clone()
            },
            pb::CsiNvmeApply {
                device_path: "/dev/zvol/../sda".into(),
                ..apply_ok.clone()
            },
            pb::CsiNvmeApply {
                traddr: "not-an-ip".into(),
                ..apply_ok.clone()
            },
            pb::CsiNvmeApply {
                trsvcid: 70000, // out of u16 range
                ..apply_ok.clone()
            },
            pb::CsiNvmeApply {
                transport: 0, // TRANSPORT_UNSPECIFIED
                ..apply_ok.clone()
            },
        ] {
            assert!(CsiNvmeApply::try_from(bad.clone()).is_err(), "{bad:?}");
        }
        assert!(
            CsiHostGrant::try_from(pb::CsiHostGrant {
                nqn: csi_ok.into(),
                hostnqn: "nqn.2014-08.org/evil".into(), // slash
            })
            .is_err()
        );
        assert!(
            CsiHostRevoke::try_from(pb::CsiHostRevoke {
                nqn: "nqn.2000-01.com.example:manual".into(), // foreign prefix
                hostnqn: "nqn.2014-08.org.nvmexpress:host1".into(),
            })
            .is_err()
        );
        assert!(
            ZfsClone::try_from(pb::ZfsClone {
                dataset: "tank/csi/pvc-1".into(),
                snap: "tank@daily".into(), // '@' is not part of a snap name
                target: "tank/csi/pvc-2".into(),
                new_size: None,
            })
            .is_err()
        );
        assert!(
            ZfsClone::try_from(pb::ZfsClone {
                dataset: "tank/csi/pvc-1".into(),
                snap: "daily".into(),
                target: "../../etc".into(),
                new_size: None,
            })
            .is_err()
        );
        assert!(
            ZvolInfo::try_from(pb::ZvolInfo {
                dataset: "tank/$(reboot)".into(),
            })
            .is_err()
        );
    }
}
