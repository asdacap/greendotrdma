//! The privileged-operation allowlist. [`plan`] resolves each task op to exactly
//! one command (a [`TaskSpec`]) or special arm; [`plan_call`] answers the two
//! one-shot ops, which are never recorded as tasks (auth would store the
//! password). Only `plan_call` needs the [`Ctx`] — task planning is pure.

use crate::cmd::TaskSpec;
use crate::{install, lio, lvm, modules, pam, partition, smart, zfs};
use greendot_proto::{
    BlockDev, CallRequest, NetdevName, NfsDesired, NvmetDesired, Response, TaskRequest,
};
use std::sync::Mutex;

pub struct Ctx {
    pub auth: pam::AuthConfig,
    pub auth_limiter: Mutex<pam::RateLimiter>,
    /// Serializes task execution so configfs/zfs changes never interleave.
    pub mutate_lock: Mutex<()>,
    /// The daemon's own config TOML path for `TaskRequest::Reconcile` (`--config`;
    /// `None` = built-in defaults). The request deliberately carries no path,
    /// so the peer cannot name a file for root to read.
    pub reconcile_config: Option<String>,
}

pub enum Dispatch {
    /// Nothing to run: the op resolved to a no-op (an empty module or package
    /// set). `RunTask` folds this into a one-subtask task carrying the reply.
    OneShot(Response),
    /// One command to run as a streamed task.
    Task(TaskSpec),
    /// Apply NVMe-oF state by writing configfs directly (no external CLI),
    /// streamed as a task like any command.
    NvmetApply(NvmetDesired),
    /// Apply NFS state: write our exports file + surgical `exportfs` + assert
    /// the RDMA listener, streamed as a task.
    NfsApply(NfsDesired),
    /// Privileged read of NFS actual state (`exportfs -s` + portlist), streamed
    /// as a task; collected by the web, never recorded.
    NfsReport,
    /// Run the full desired-state reconcile inline (render, drift check, and
    /// the area applies all in this process), streamed as one task with a
    /// subtask per area. The config comes from `Ctx::reconcile_config`.
    Reconcile,
    /// Privileged read of the RoCE-capable NIC inventory (vendor classification
    /// via the `NetworkHardware` registry), streamed as JSON like `NfsReport`.
    RoceCapableNics,
    /// Privileged read of per-NIC RDMA advisories (vendor-specific diagnostic
    /// text), streamed as JSON like `RoceCapableNics`.
    NicRdmaAdvice,
    /// Privileged batch read of per-device SMART health+temp, streamed as JSON
    /// like `RoceCapableNics` (runs `smartctl` once per device and merges).
    SmartHealth(Vec<BlockDev>),
    /// Turn on hardware RoCE for a NIC: vendor-detect, probe, then set+reload —
    /// the multi-step vendor-specific flow streamed as one task.
    EnableRoce(NetdevName),
    /// Enable Soft-RoCE: load the rxe module, then add the rdma link — two
    /// ordered commands streamed as one task (see `modules::rxe_add`).
    RxeAdd(NetdevName),
    /// Shrink a partition and its filesystem as one multi-step task: probe,
    /// filesystem shrink (fs-specific flow in `fs::shrink`), partition resize —
    /// the filesystem always before the partition boundary.
    PartitionShrink {
        disk: BlockDev,
        number: u32,
        size_sectors: u64,
    },
    /// A refused operation recorded as a failed task carrying the subtask
    /// label and the reason (e.g. install on an unsupported distro), so the
    /// reason reaches the UI.
    FailedTask {
        label: &'static str,
        message: String,
    },
    /// Structural/privileged reads the web collects as JSON (like `NfsReport`),
    /// each serializing a shared `actual::*` DTO the web deserializes.
    NvmetReport,
    LioReport,
    LioSessions,
    RdmaDevices,
    NicPciAddrs,
    NicInterfaces,
    /// The desired-vs-actual drift pre-check (renders + reads + diffs, no apply).
    ReconcileDryRun,
}

/// Answer a one-shot op. `Authenticate` runs PAM, so this blocks.
pub fn plan_call(ctx: &Ctx, req: CallRequest) -> Response {
    match req {
        CallRequest::Ping => Response::Ok,
        CallRequest::Authenticate { username, password } => {
            pam::authenticate(&ctx.auth, &ctx.auth_limiter, &username, &password)
        }
    }
}

pub fn plan(req: TaskRequest) -> Dispatch {
    match req {
        TaskRequest::ZvolCreate {
            dataset,
            size,
            volblocksize,
            sparse,
        } => Dispatch::Task(zfs::zvol_create(&dataset, size, volblocksize, sparse)),
        TaskRequest::ZvolDelete { dataset } => Dispatch::Task(zfs::zvol_delete(&dataset)),
        TaskRequest::ZvolResize { dataset, new_size } => {
            Dispatch::Task(zfs::zvol_resize(&dataset, new_size))
        }
        TaskRequest::SnapshotCreate { dataset, snap } => {
            Dispatch::Task(zfs::snapshot_create(&dataset, &snap))
        }
        TaskRequest::SnapshotDestroy { dataset, snap } => {
            Dispatch::Task(zfs::snapshot_destroy(&dataset, &snap))
        }

        TaskRequest::ZfsFsCreate {
            dataset,
            mountpoint,
        } => Dispatch::Task(zfs::zfs_fs_create(&dataset, mountpoint.as_ref())),
        TaskRequest::ZfsSetMountpoint {
            dataset,
            mountpoint,
        } => Dispatch::Task(zfs::zfs_set_mountpoint(&dataset, &mountpoint)),
        TaskRequest::ZfsMount { dataset } => Dispatch::Task(zfs::zfs_mount(&dataset)),
        TaskRequest::ZfsUnmount { dataset } => Dispatch::Task(zfs::zfs_unmount(&dataset)),
        TaskRequest::ZfsDestroy { dataset, recursive } => {
            Dispatch::Task(zfs::zfs_destroy(&dataset, recursive))
        }

        TaskRequest::NvmetApply { desired } => Dispatch::NvmetApply(desired),
        TaskRequest::LioApply { desired } => Dispatch::Task(lio::apply_spec(&desired)),
        TaskRequest::NfsApply { desired } => Dispatch::NfsApply(desired),
        TaskRequest::NfsReport => Dispatch::NfsReport,
        TaskRequest::Reconcile => Dispatch::Reconcile,
        TaskRequest::NvmetReport => Dispatch::NvmetReport,
        TaskRequest::LioReport => Dispatch::LioReport,
        TaskRequest::LioSessions => Dispatch::LioSessions,
        TaskRequest::RdmaDevices => Dispatch::RdmaDevices,
        TaskRequest::NicPciAddrs => Dispatch::NicPciAddrs,
        TaskRequest::NicInterfaces => Dispatch::NicInterfaces,
        TaskRequest::ReconcileDryRun => Dispatch::ReconcileDryRun,

        TaskRequest::RxeAdd { netdev } => Dispatch::RxeAdd(netdev),
        TaskRequest::RoceCapableNics => Dispatch::RoceCapableNics,
        TaskRequest::NicRdmaAdvice => Dispatch::NicRdmaAdvice,
        TaskRequest::EnableRoce { netdev } => Dispatch::EnableRoce(netdev),
        TaskRequest::RdmaResources => Dispatch::Task(modules::rdma_resources()),

        TaskRequest::PartitionTableCreate { disk } => {
            Dispatch::Task(partition::table_create(&disk))
        }
        TaskRequest::PartitionCreate {
            disk,
            start_sector,
            size_sectors,
            label,
        } => Dispatch::Task(partition::partition_create(
            &disk,
            start_sector,
            size_sectors,
            &label,
        )),
        TaskRequest::PartitionDelete { disk, number } => {
            Dispatch::Task(partition::partition_delete(&disk, number))
        }
        TaskRequest::PartitionShrink {
            disk,
            number,
            size_sectors,
        } => Dispatch::PartitionShrink {
            disk,
            number,
            size_sectors,
        },

        TaskRequest::PoolCreate {
            name,
            vdev,
            devices,
            ashift,
        } => Dispatch::Task(zfs::pool_create(&name, vdev, &devices, ashift)),
        TaskRequest::PoolDeviceAdd { pool, device } => {
            Dispatch::Task(zfs::pool_device_add(&pool, &device))
        }

        TaskRequest::SmartReport { device } => Dispatch::Task(smart::report(&device)),
        TaskRequest::SmartHealth { devices } => Dispatch::SmartHealth(devices),

        TaskRequest::LvmReport { what } => Dispatch::Task(lvm::report(what)),
        TaskRequest::VgCreate { name, devices } => Dispatch::Task(lvm::vg_create(&name, &devices)),
        TaskRequest::VgExtend { vg, device } => Dispatch::Task(lvm::vg_extend(&vg, &device)),
        TaskRequest::VgReduce { vg, device } => Dispatch::Task(lvm::vg_reduce(&vg, &device)),
        TaskRequest::VgRemove { vg } => Dispatch::Task(lvm::vg_remove(&vg)),
        TaskRequest::LvCreate { vg, name, size } => {
            Dispatch::Task(lvm::lv_create(&vg, &name, size))
        }
        TaskRequest::ThinPoolCreate { vg, name, size } => {
            Dispatch::Task(lvm::thin_pool_create(&vg, &name, size))
        }
        TaskRequest::ThinLvCreate {
            vg,
            pool,
            name,
            virtual_size,
        } => Dispatch::Task(lvm::thin_lv_create(&vg, &pool, &name, virtual_size)),
        TaskRequest::LvResize { vg, name, new_size } => {
            Dispatch::Task(lvm::lv_resize(&vg, &name, new_size))
        }
        TaskRequest::LvShrink { vg, name, new_size } => {
            Dispatch::Task(lvm::lv_shrink(&vg, &name, new_size))
        }
        TaskRequest::LvRename { vg, name, new_name } => {
            Dispatch::Task(lvm::lv_rename(&vg, &name, &new_name))
        }
        TaskRequest::LvDelete { vg, name } => Dispatch::Task(lvm::lv_delete(&vg, &name)),

        TaskRequest::InstallPackages { packages } => {
            match install::install(&packages, &greendot_proto::os::detect()) {
                Ok(Some(spec)) => Dispatch::Task(spec),
                Ok(None) => Dispatch::OneShot(Response::Ok),
                Err(msg) => Dispatch::FailedTask {
                    label: "install",
                    message: msg,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::TaskSpec;
    use greendot_proto::*;
    use rstest::rstest;
    use std::time::Instant;

    fn ctx() -> Ctx {
        Ctx {
            auth: pam::AuthConfig {
                pam_service: "greendot".into(),
                admin_group: "wheel".into(),
            },
            // Capacity 0 ⇒ every attempt is denied, so the `Authenticate` arm
            // exercises the rate-limit path without ever touching real PAM.
            auth_limiter: Mutex::new(pam::RateLimiter::new(0, 60.0, Instant::now())),
            mutate_lock: Mutex::new(()),
            reconcile_config: None,
        }
    }

    fn task(d: Dispatch) -> TaskSpec {
        match d {
            Dispatch::Task(spec) => spec,
            _ => panic!("expected a Task dispatch"),
        }
    }

    // Validated-newtype constructors, kept terse for the case table below.
    fn ds(s: &str) -> DatasetName {
        DatasetName::new(s).unwrap()
    }
    fn sn(s: &str) -> SnapName {
        SnapName::new(s).unwrap()
    }
    fn dev(s: &str) -> DevicePath {
        DevicePath::new(s).unwrap()
    }
    fn vg(s: &str) -> VgName {
        VgName::new(s).unwrap()
    }
    fn lv(s: &str) -> LvName {
        LvName::new(s).unwrap()
    }
    fn disk(s: &str) -> BlockDev {
        BlockDev::new(s).unwrap()
    }

    /// Each task request must route to exactly the command its dedicated builder
    /// produces; the builder is the oracle, so a mis-wired arm (wrong function or
    /// wrong field) is caught without re-spelling the command line here.
    #[rstest]
    #[case::zvol_create(
        TaskRequest::ZvolCreate { dataset: ds("tank/vm1"), size: 5 << 30, volblocksize: Some(8192), sparse: true },
        zfs::zvol_create(&ds("tank/vm1"), 5 << 30, Some(8192), true))]
    #[case::zvol_delete(
        TaskRequest::ZvolDelete { dataset: ds("tank/vm1") },
        zfs::zvol_delete(&ds("tank/vm1")))]
    #[case::zvol_resize(
        TaskRequest::ZvolResize { dataset: ds("tank/vm1"), new_size: 7 << 30 },
        zfs::zvol_resize(&ds("tank/vm1"), 7 << 30))]
    #[case::snapshot_create(
        TaskRequest::SnapshotCreate { dataset: ds("tank/vm1"), snap: sn("daily") },
        zfs::snapshot_create(&ds("tank/vm1"), &sn("daily")))]
    #[case::snapshot_destroy(
        TaskRequest::SnapshotDestroy { dataset: ds("tank/vm1"), snap: sn("daily") },
        zfs::snapshot_destroy(&ds("tank/vm1"), &sn("daily")))]
    #[case::zfs_fs_create(
        TaskRequest::ZfsFsCreate { dataset: ds("tank/share"), mountpoint: Some(MountPoint::new("/srv/share").unwrap()) },
        zfs::zfs_fs_create(&ds("tank/share"), Some(&MountPoint::new("/srv/share").unwrap())))]
    #[case::zfs_set_mountpoint(
        TaskRequest::ZfsSetMountpoint { dataset: ds("tank/share"), mountpoint: MountPoint::new("/srv/share").unwrap() },
        zfs::zfs_set_mountpoint(&ds("tank/share"), &MountPoint::new("/srv/share").unwrap()))]
    #[case::zfs_mount(
        TaskRequest::ZfsMount { dataset: ds("tank/share") },
        zfs::zfs_mount(&ds("tank/share")))]
    #[case::zfs_unmount(
        TaskRequest::ZfsUnmount { dataset: ds("tank/share") },
        zfs::zfs_unmount(&ds("tank/share")))]
    #[case::zfs_destroy(
        TaskRequest::ZfsDestroy { dataset: ds("tank/share"), recursive: true },
        zfs::zfs_destroy(&ds("tank/share"), true))]
    #[case::pool_create(
        TaskRequest::PoolCreate { name: PoolName::new("tank").unwrap(), vdev: VdevLayout::Mirror, devices: vec![dev("/dev/sdb"), dev("/dev/sdc")], ashift: Some(12) },
        zfs::pool_create(&PoolName::new("tank").unwrap(), VdevLayout::Mirror, &[dev("/dev/sdb"), dev("/dev/sdc")], Some(12)))]
    #[case::pool_device_add(
        TaskRequest::PoolDeviceAdd { pool: PoolName::new("tank").unwrap(), device: dev("/dev/sdd") },
        zfs::pool_device_add(&PoolName::new("tank").unwrap(), &dev("/dev/sdd")))]
    #[case::smart_report(
        TaskRequest::SmartReport { device: disk("sda") },
        smart::report(&disk("sda")))]
    #[case::lio_apply(
        TaskRequest::LioApply { desired: LioDesired::default() },
        lio::apply_spec(&LioDesired::default()))]
    #[case::partition_table_create(
        TaskRequest::PartitionTableCreate { disk: disk("sdb") },
        partition::table_create(&disk("sdb")))]
    #[case::partition_create(
        TaskRequest::PartitionCreate { disk: disk("sdb"), start_sector: Some(2048), size_sectors: Some(1 << 20), label: PartLabel::new("data").unwrap() },
        partition::partition_create(&disk("sdb"), Some(2048), Some(1 << 20), &PartLabel::new("data").unwrap()))]
    #[case::partition_delete(
        TaskRequest::PartitionDelete { disk: disk("sdb"), number: 2 },
        partition::partition_delete(&disk("sdb"), 2))]
    #[case::lvm_report(
        TaskRequest::LvmReport { what: LvmReport::Vgs },
        lvm::report(LvmReport::Vgs))]
    #[case::vg_create(
        TaskRequest::VgCreate { name: vg("vg0"), devices: vec![dev("/dev/sdb")] },
        lvm::vg_create(&vg("vg0"), &[dev("/dev/sdb")]))]
    #[case::vg_extend(
        TaskRequest::VgExtend { vg: vg("vg0"), device: dev("/dev/sdc") },
        lvm::vg_extend(&vg("vg0"), &dev("/dev/sdc")))]
    #[case::vg_reduce(
        TaskRequest::VgReduce { vg: vg("vg0"), device: dev("/dev/sdc") },
        lvm::vg_reduce(&vg("vg0"), &dev("/dev/sdc")))]
    #[case::vg_remove(
        TaskRequest::VgRemove { vg: vg("vg0") },
        lvm::vg_remove(&vg("vg0")))]
    #[case::lv_create(
        TaskRequest::LvCreate { vg: vg("vg0"), name: lv("data"), size: 10 << 30 },
        lvm::lv_create(&vg("vg0"), &lv("data"), 10 << 30))]
    #[case::thin_pool_create(
        TaskRequest::ThinPoolCreate { vg: vg("vg0"), name: lv("pool0"), size: 50 << 30 },
        lvm::thin_pool_create(&vg("vg0"), &lv("pool0"), 50 << 30))]
    #[case::thin_lv_create(
        TaskRequest::ThinLvCreate { vg: vg("vg0"), pool: lv("pool0"), name: lv("vm1"), virtual_size: 20 << 30 },
        lvm::thin_lv_create(&vg("vg0"), &lv("pool0"), &lv("vm1"), 20 << 30))]
    #[case::lv_resize(
        TaskRequest::LvResize { vg: vg("vg0"), name: lv("data"), new_size: 12 << 30 },
        lvm::lv_resize(&vg("vg0"), &lv("data"), 12 << 30))]
    #[case::lv_shrink(
        TaskRequest::LvShrink { vg: vg("vg0"), name: lv("data"), new_size: 8 << 30 },
        lvm::lv_shrink(&vg("vg0"), &lv("data"), 8 << 30))]
    #[case::lv_rename(
        TaskRequest::LvRename { vg: vg("vg0"), name: lv("data"), new_name: lv("archive") },
        lvm::lv_rename(&vg("vg0"), &lv("data"), &lv("archive")))]
    #[case::lv_delete(
        TaskRequest::LvDelete { vg: vg("vg0"), name: lv("data") },
        lvm::lv_delete(&vg("vg0"), &lv("data")))]
    fn task_requests_route_to_their_builder(#[case] req: TaskRequest, #[case] expected: TaskSpec) {
        assert_eq!(task(plan(req)), expected);
    }

    /// The two one-shot ops, which never become tasks.
    #[test]
    fn call_ops_reply_immediately() {
        let ctx = ctx();
        assert_eq!(plan_call(&ctx, CallRequest::Ping), Response::Ok);
        // Rate limiter is exhausted, so the reply is Busy (not real PAM auth).
        assert!(matches!(
            plan_call(
                &ctx,
                CallRequest::Authenticate {
                    username: Username::new("alice").unwrap(),
                    password: Secret("secret".into()),
                }
            ),
            Response::Err {
                kind: ErrKind::Busy,
                ..
            }
        ));
    }

    /// The non-task arms: configfs apply, privileged reads, and the empty-set
    /// shortcuts that need no command at all.
    #[test]
    fn oneshot_and_special_arms() {
        // An empty package set resolves to a no-op reply, not a task.
        assert!(matches!(
            plan(TaskRequest::InstallPackages { packages: vec![] }),
            Dispatch::OneShot(Response::Ok)
        ));
        // NVMe-oF apply is carried through verbatim for the helper to write.
        let desired = NvmetDesired::default();
        assert!(matches!(
            plan(TaskRequest::NvmetApply { desired: desired.clone() }),
            Dispatch::NvmetApply(d) if d == desired
        ));
        // NFS apply/report route to their special arms.
        let nfs = NfsDesired::default();
        assert!(matches!(
            plan(TaskRequest::NfsApply { desired: nfs.clone() }),
            Dispatch::NfsApply(d) if d == nfs
        ));
        assert!(matches!(plan(TaskRequest::NfsReport), Dispatch::NfsReport));
        // RoCE hardware read + enable route to their special arms (the
        // vendor-specific work lives in `hardware`, not a single TaskSpec).
        assert!(matches!(
            plan(TaskRequest::RoceCapableNics),
            Dispatch::RoceCapableNics
        ));
        assert!(matches!(
            plan(TaskRequest::NicRdmaAdvice),
            Dispatch::NicRdmaAdvice
        ));
        assert!(matches!(
            plan(TaskRequest::EnableRoce { netdev: NetdevName::new("ens16").unwrap() }),
            Dispatch::EnableRoce(nd) if nd.as_str() == "ens16"
        ));
        // The two helper-sequenced compound ops route to their special arms
        // (multiple commands, one task — a single TaskSpec can't express them).
        assert!(matches!(
            plan(TaskRequest::RxeAdd { netdev: NetdevName::new("eth0").unwrap() }),
            Dispatch::RxeAdd(nd) if nd.as_str() == "eth0"
        ));
        assert!(matches!(
            plan(TaskRequest::PartitionShrink { disk: disk("sdb"), number: 2, size_sectors: 1 << 21 }),
            Dispatch::PartitionShrink { disk: d, number: 2, size_sectors } if d.as_str() == "sdb" && size_sectors == 1 << 21
        ));
        // SMART health is a batch read routed to its own arm (one TaskSpec can't
        // express "run smartctl per device and merge").
        assert!(matches!(
            plan(TaskRequest::SmartHealth { devices: vec![disk("sda")] }),
            Dispatch::SmartHealth(d) if d.len() == 1 && d[0].as_str() == "sda"
        ));
    }
}
