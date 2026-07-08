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

use crate::convert::{dec_lvm_report, dec_vdev, map_new, strs, to_u8};
use crate::pb;
use crate::{
    BlockDev, ConvertError, DatasetName, DevicePath, LvName, LvmReport as LvmReportKind,
    MountPoint, NetdevName, PackageName, PartLabel, PoolName, Secret, SnapName, Username,
    VdevLayout, VdevTarget, VgName,
};

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

// ---- Fieldless ops ----

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
    }
}
