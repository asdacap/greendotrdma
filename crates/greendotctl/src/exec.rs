//! The privileged-operation allowlist: one [`TaskOp`] impl per task rpc and
//! one [`ReadOp`] impl per typed read. The generic middleware in `main.rs`
//! drives these — validation (`TryFrom<Wire>`, required by bound), the mutate
//! lock, task framing, and panic folding all live there, written once.
//!
//! An op exists here iff it is one allowlisted user-level intent; an op whose
//! only caller would be a client-side sequence belongs inside an existing
//! impl (see [`ops::PartitionShrink`] / `fs::shrink`).

use crate::cmd::TaskSpec;
use crate::pipe_keys::PipeKeyConfig;
use crate::{
    cmd, fs, hardware, install, lvm, modules, nfs, nvmet, partition, pipe_keys, reconcile, smart,
    zfs,
};
use greendot_proto::actual::nic::NicAdvice;
use greendot_proto::{ConvertError, SubStatus, Task, ops, pb};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Mutex;

/// LIO configfs root (matches the config default; the daemon owns the path).
const LIO_ROOT: &str = "/sys/kernel/config/target";
/// RDMA device class root.
const IB_ROOT: &str = "/sys/class/infiniband";

pub struct Ctx {
    pub auth: crate::pam::AuthConfig,
    pub auth_limiter: Mutex<crate::pam::RateLimiter>,
    /// Serializes task execution so configfs/zfs changes never interleave.
    pub mutate_lock: Mutex<()>,
    /// The daemon's own config TOML path for `Reconcile` (`--config`; `None` =
    /// built-in defaults). The request deliberately carries no path, so the
    /// peer cannot name a file for root to read.
    pub reconcile_config: Option<String>,
    /// The nvmet configfs root the CSI ops and `NvmetReport` run against
    /// (`--nvmet-root` overrides it in the integration tests).
    pub nvmet_root: std::path::PathBuf,
    /// Where the pipe keys live, and the forced command they are granted —
    /// resolved once at startup, never taken from a request.
    pub pipe_keys: PipeKeyConfig,
    /// Whether applies load their required kernel modules themselves
    /// (`autoload_modules` in the config, resolved once at startup).
    pub autoload_modules: bool,
}

/// A task rpc: executes as a recorded stream of subtasks. The
/// `TryFrom<Self::Wire>` supertrait is the ingress validation choke point —
/// the middleware cannot run an op without converting through it.
pub trait TaskOp: TryFrom<Self::Wire, Error = ConvertError> + Send + Sized + 'static {
    type Wire: Send + 'static;
    /// Whether the middleware holds the daemon-wide mutate lock for the whole
    /// run. Only `Reconcile` opts out — it takes the lock itself, around its
    /// entire pass including the config load.
    const MUTATES: bool = true;
    /// `Err` only on a sink failure (the client is gone); operational failures
    /// are recorded on the task.
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()>;
}

/// A typed-read rpc: no recorded task, no mutate lock, one reply message. The
/// producers degrade to empty DTOs on read failure (the web renders that as
/// drift/unknown), so `read` is infallible.
pub trait ReadOp: TryFrom<Self::Wire, Error = ConvertError> + Send + Sized + 'static {
    type Wire: Send + 'static;
    type Reply: Send + 'static;
    fn read(self, ctx: &Ctx) -> Self::Reply;
}

/// Runs one command as this op's whole task.
fn run_spec(task: &mut Task, spec: TaskSpec) -> io::Result<()> {
    cmd::run(task, spec.command.clone(), &spec)?;
    Ok(())
}

/// The single-command ops: `exec` runs exactly the spec its builder produces.
macro_rules! spec_op {
    ($($op:ty = $wire:ty, |$s:ident| $spec:expr;)*) => {$(
        impl TaskOp for $op {
            type Wire = $wire;
            fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
                let $s = self;
                run_spec(task, $spec)
            }
        }
    )*};
}

spec_op! {
    ops::ZvolCreate = pb::ZvolCreate,
        |o| zfs::zvol_create(&o.dataset, o.size, o.volblocksize, o.sparse);
    ops::ZvolDelete = pb::ZvolDelete, |o| zfs::zvol_delete(&o.dataset);
    ops::ZvolResize = pb::ZvolResize, |o| zfs::zvol_resize(&o.dataset, o.new_size);
    ops::SnapshotCreate = pb::SnapshotCreate, |o| zfs::snapshot_create(&o.dataset, &o.snap);
    ops::SnapshotDestroy = pb::SnapshotDestroy, |o| zfs::snapshot_destroy(&o.dataset, &o.snap);
    ops::ZfsFsCreate = pb::ZfsFsCreate, |o| zfs::zfs_fs_create(&o.dataset, o.mountpoint.as_ref());
    ops::ZfsSetMountpoint = pb::ZfsSetMountpoint,
        |o| zfs::zfs_set_mountpoint(&o.dataset, &o.mountpoint);
    ops::ZfsMount = pb::ZfsMount, |o| zfs::zfs_mount(&o.dataset);
    ops::ZfsUnmount = pb::ZfsUnmount, |o| zfs::zfs_unmount(&o.dataset);
    ops::ZfsDestroy = pb::ZfsDestroy, |o| zfs::zfs_destroy(&o.dataset, o.recursive);
    ops::PoolCreate = pb::PoolCreate,
        |o| zfs::pool_create(&o.name, o.vdev, &o.devices, o.ashift);
    ops::PoolDeviceAdd = pb::PoolDeviceAdd, |o| zfs::pool_device_add(&o.pool, &o.device);
    ops::PoolDeviceDetach = pb::PoolDeviceDetach,
        |o| zfs::pool_device_detach(&o.pool, &o.device);
    ops::PartitionTableCreate = pb::PartitionTableCreate, |o| partition::table_create(&o.disk);
    ops::PartitionCreate = pb::PartitionCreate,
        |o| partition::partition_create(&o.disk, o.start_sector, o.size_sectors, &o.label);
    ops::PartitionDelete = pb::PartitionDelete,
        |o| partition::partition_delete(&o.disk, o.number);
    ops::LvmReport = pb::LvmReport, |o| lvm::report(o.what);
    ops::VgCreate = pb::VgCreate, |o| lvm::vg_create(&o.name, &o.devices);
    ops::VgExtend = pb::VgExtend, |o| lvm::vg_extend(&o.vg, &o.device);
    ops::VgReduce = pb::VgReduce, |o| lvm::vg_reduce(&o.vg, &o.device);
    ops::VgRemove = pb::VgRemove, |o| lvm::vg_remove(&o.vg);
    ops::LvCreate = pb::LvCreate, |o| lvm::lv_create(&o.vg, &o.name, o.size);
    ops::ThinPoolCreate = pb::ThinPoolCreate, |o| lvm::thin_pool_create(&o.vg, &o.name, o.size);
    ops::ThinLvCreate = pb::ThinLvCreate,
        |o| lvm::thin_lv_create(&o.vg, &o.pool, &o.name, o.virtual_size);
    ops::LvResize = pb::LvResize, |o| lvm::lv_resize(&o.vg, &o.name, o.new_size);
    ops::LvShrink = pb::LvShrink, |o| lvm::lv_shrink(&o.vg, &o.name, o.new_size);
    ops::LvRename = pb::LvRename, |o| lvm::lv_rename(&o.vg, &o.name, &o.new_name);
    ops::LvDelete = pb::LvDelete, |o| lvm::lv_delete(&o.vg, &o.name);
    ops::SmartReport = pb::SmartReport, |o| smart::report(&o.device);
    ops::RdmaResources = pb::Empty, |_o| modules::rdma_resources();
}

// ---- Compound / special task ops ----

impl TaskOp for ops::PoolDeviceRemove {
    type Wire = pb::PoolDeviceRemove;
    fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        zfs::pool_device_remove_and_wait(task, &self.pool, &self.target)
    }
}

impl TaskOp for ops::Reconcile {
    type Wire = pb::Reconcile;
    /// The driver loads the config and takes the mutate lock itself, for the
    /// whole pass.
    const MUTATES: bool = false;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        reconcile::run(ctx.reconcile_config.clone(), &ctx.mutate_lock, task)
    }
}

impl TaskOp for ops::PartitionShrink {
    type Wire = pb::PartitionShrink;
    fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        fs::shrink(task, &self.disk, self.number, self.size_sectors)
    }
}

impl TaskOp for ops::RxeAdd {
    type Wire = pb::RxeAdd;
    fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        modules::rxe_add(task, &self.netdev)
    }
}

impl TaskOp for ops::EnableRoce {
    type Wire = pb::EnableRoce;
    fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        let mut sub = task.begin_subtask(format!("Enable RoCE on {}", self.netdev));
        let status = hardware::enable_into(Path::new(hardware::NET_ROOT), &self.netdev, &mut sub)?;
        sub.complete(status);
        Ok(())
    }
}

impl TaskOp for ops::ZfsClone {
    type Wire = pb::ZfsClone;
    fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        zfs::zfs_clone_and_resize(task, &self.dataset, &self.snap, &self.target, self.new_size)
    }
}

impl TaskOp for ops::CsiNvmeApply {
    type Wire = pb::CsiNvmeApply;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        // Nothing loads the nvmet modules for the CSI path but us — the
        // reconcile's module area only covers the web's own exports.
        if ctx.autoload_modules
            && let Some(spec) = modules::ensure(
                &[modules::transport_module(self.transport)],
                &hardware::rdma_driver_modules(Path::new(hardware::NET_ROOT)),
            )
            && cmd::run(task, "Load kernel modules", &spec)? != SubStatus::Success
        {
            return Ok(());
        }
        // `zfs create` returns before udev materializes the zvol's device
        // node, and enabling the nvmet namespace opens that node — so a fresh
        // volume's first apply can race into an ENOENT. Wait briefly, as a
        // visible subtask, only when the node isn't there yet.
        if !Path::new(self.device_path.as_str()).exists() {
            let sub = task.begin_subtask(format!("Wait for {}", self.device_path));
            let appeared = (0..100).any(|_| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                Path::new(self.device_path.as_str()).exists()
            });
            if !appeared {
                sub.fail(format!(
                    "device node {} did not appear — does the backing volume exist?",
                    self.device_path
                ));
                return Ok(());
            }
        }
        nvmet::csi_apply(&ctx.nvmet_root, &self, task)
    }
}

impl TaskOp for ops::CsiNvmeDelete {
    type Wire = pb::CsiNvmeDelete;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        nvmet::csi_delete(&ctx.nvmet_root, &self.nqn, task)
    }
}

impl TaskOp for ops::CsiHostGrant {
    type Wire = pb::CsiHostGrant;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        nvmet::csi_host_grant(&ctx.nvmet_root, &self.nqn, &self.hostnqn, task)
    }
}

impl TaskOp for ops::CsiHostRevoke {
    type Wire = pb::CsiHostRevoke;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        nvmet::csi_host_revoke(&ctx.nvmet_root, &self.nqn, &self.hostnqn, task)
    }
}

impl TaskOp for ops::CsiVolumeExpand {
    type Wire = pb::CsiVolumeExpand;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        nvmet::csi_expand(&ctx.nvmet_root, &self.nqn, self.new_size, task)
    }
}

impl TaskOp for ops::PipeKeyAdd {
    type Wire = pb::PipeKeyAdd;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        pipe_keys::add(&ctx.pipe_keys, &self, task)
    }
}

impl TaskOp for ops::PipeKeyRevoke {
    type Wire = pb::PipeKeyRevoke;
    fn exec(self, ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        pipe_keys::revoke(&ctx.pipe_keys, &self.fingerprint, task)
    }
}

impl TaskOp for ops::InstallPackages {
    type Wire = pb::InstallPackages;
    fn exec(self, _ctx: &Ctx, task: &mut Task) -> io::Result<()> {
        match install::install(&self.packages, &greendot_proto::os::detect()) {
            Ok(Some(spec)) => run_spec(task, spec),
            // An empty set is a successful no-op, not a failed task.
            Ok(None) => {
                task.begin_subtask("Apply").complete(SubStatus::Success);
                Ok(())
            }
            // A refused install (unsupported distro) recorded with its reason,
            // so it reaches the UI.
            Err(msg) => {
                task.begin_subtask("install").fail(msg);
                Ok(())
            }
        }
    }
}

// ---- Typed reads ----

impl ReadOp for ops::NfsReport {
    type Wire = pb::Empty;
    type Reply = pb::NfsReportReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        greendot_proto::actual::nfs::from_report(&nfs::report(
            Path::new(nfs::NFSD_PORTLIST),
            Path::new(nfs::NFS_EXPORTS_FILE),
        ))
        .into()
    }
}

impl ReadOp for ops::NvmetReport {
    type Wire = pb::Empty;
    type Reply = pb::NvmetReportReply;
    fn read(self, ctx: &Ctx) -> Self::Reply {
        crate::actual::nvmet::read(&ctx.nvmet_root).into()
    }
}

impl ReadOp for ops::PipeAccessReport {
    type Wire = pb::Empty;
    type Reply = pb::PipeAccessReportReply;
    fn read(self, ctx: &Ctx) -> Self::Reply {
        pipe_keys::report(&ctx.pipe_keys)
    }
}

impl ReadOp for ops::ZvolInfo {
    type Wire = pb::ZvolInfo;
    type Reply = pb::ZvolInfoReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        let (exists, size_bytes) = zfs::zvol_info(
            Path::new("/dev/zvol"),
            Path::new("/sys/class/block"),
            &self.dataset,
        );
        pb::ZvolInfoReply { exists, size_bytes }
    }
}

impl ReadOp for ops::LioReport {
    type Wire = pb::Empty;
    type Reply = pb::LioReportReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        crate::actual::lio::read(Path::new(LIO_ROOT)).into()
    }
}

impl ReadOp for ops::LioSessions {
    type Wire = pb::Empty;
    type Reply = pb::LioSessionsReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        crate::actual::lio::sessions(Path::new(LIO_ROOT)).into()
    }
}

impl ReadOp for ops::RdmaDevices {
    type Wire = pb::Empty;
    type Reply = pb::RdmaDevicesReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        crate::actual::rdma::devices().into()
    }
}

impl ReadOp for ops::NicPciAddrs {
    type Wire = pb::Empty;
    type Reply = pb::NicPciAddrsReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        crate::actual::nic::pci_addrs().into()
    }
}

impl ReadOp for ops::NicInterfaces {
    type Wire = pb::Empty;
    type Reply = pb::NicInterfacesReply;
    /// The structural sysfs classification overlaid with the vendor
    /// RoCE-capable map, combined here so the web renders one opaque list and
    /// carries no vendor knowledge.
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        let roce_hw: HashMap<String, String> =
            hardware::roce_capable(Path::new(hardware::NET_ROOT))
                .into_iter()
                .map(|(netdev, vendor)| (netdev, vendor.to_owned()))
                .collect();
        let netdev_addrs = crate::actual::rdma::netdev_addrs();
        crate::actual::nic::classify(
            Path::new(hardware::NET_ROOT),
            Path::new(IB_ROOT),
            &netdev_addrs,
            &roce_hw,
        )
        .into()
    }
}

impl ReadOp for ops::RoceCapableNics {
    type Wire = pb::Empty;
    type Reply = pb::RoceCapableNicsReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        hardware::roce_capable(Path::new(hardware::NET_ROOT))
            .into_iter()
            .map(|(netdev, vendor)| (netdev, vendor.to_owned()))
            .collect::<HashMap<String, String>>()
            .into()
    }
}

impl ReadOp for ops::NicRdmaAdvice {
    type Wire = pb::Empty;
    type Reply = pb::NicRdmaAdviceReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        hardware::nic_rdma_advice(Path::new(hardware::NET_ROOT))
            .into_iter()
            .map(|(netdev, label, detail)| {
                (
                    netdev,
                    NicAdvice {
                        label: label.into(),
                        detail: detail.into(),
                    },
                )
            })
            .collect::<HashMap<String, NicAdvice>>()
            .into()
    }
}

impl ReadOp for ops::SmartHealth {
    type Wire = pb::SmartHealth;
    type Reply = pb::SmartHealthReply;
    fn read(self, _ctx: &Ctx) -> Self::Reply {
        pb::SmartHealthReply {
            devices: self
                .devices
                .iter()
                .map(|device| {
                    let (passed, temp_c) = smart::health(device);
                    pb::SmartHealthMsg {
                        device: device.as_str().to_owned(),
                        passed,
                        temp_c,
                    }
                })
                .collect(),
        }
    }
}

impl ReadOp for ops::ReconcileDryRun {
    type Wire = pb::Empty;
    type Reply = pb::ReconcileDryRunReply;
    fn read(self, ctx: &Ctx) -> Self::Reply {
        let (nvmet_ok, lio_ok, nfs_ok) = reconcile::drift(ctx.reconcile_config.clone());
        pb::ReconcileDryRunReply {
            nvmet_ok,
            lio_ok,
            nfs_ok,
        }
    }
}
