//! The privileged-operation allowlist. Each task op resolves to exactly one
//! command (a [`TaskSpec`]); `Ping`/`Authenticate` are one-shot replies and
//! are never recorded as tasks (auth would store the password).

use crate::cmd::TaskSpec;
use crate::{fs, install, lio, lvm, modules, pam, partition, zfs};
use greendot_proto::{NvmetDesired, Request, Response};
use std::sync::Mutex;

pub struct Ctx {
    pub auth: pam::AuthConfig,
    pub auth_limiter: Mutex<pam::RateLimiter>,
    /// Serializes task execution so configfs/zfs changes never interleave.
    pub mutate_lock: Mutex<()>,
}

pub enum Dispatch {
    /// Immediate reply (ping, authentication) — not a task.
    OneShot(Response),
    /// One command to run as a streamed task.
    Task(TaskSpec),
    /// Apply NVMe-oF state by writing configfs directly (no external CLI),
    /// streamed as a task like any command.
    NvmetApply(NvmetDesired),
    /// A refused operation recorded as a failed task carrying this message
    /// (e.g. install on an unsupported distro), so the reason reaches the UI.
    FailedTask(String),
}

pub fn plan(ctx: &Ctx, req: Request) -> Dispatch {
    match req {
        Request::Ping => Dispatch::OneShot(Response::Ok),
        Request::Authenticate { username, password } => Dispatch::OneShot(pam::authenticate(
            &ctx.auth,
            &ctx.auth_limiter,
            &username,
            &password,
        )),

        Request::ZvolCreate {
            dataset,
            size,
            volblocksize,
            sparse,
        } => Dispatch::Task(zfs::zvol_create(&dataset, size, volblocksize, sparse)),
        Request::ZvolDelete { dataset } => Dispatch::Task(zfs::zvol_delete(&dataset)),
        Request::ZvolResize { dataset, new_size } => {
            Dispatch::Task(zfs::zvol_resize(&dataset, new_size))
        }
        Request::SnapshotCreate { dataset, snap } => {
            Dispatch::Task(zfs::snapshot_create(&dataset, &snap))
        }
        Request::SnapshotDestroy { dataset, snap } => {
            Dispatch::Task(zfs::snapshot_destroy(&dataset, &snap))
        }

        Request::NvmetApply { desired } => Dispatch::NvmetApply(desired),
        Request::LioApply { desired } => Dispatch::Task(lio::apply_spec(&desired)),

        Request::EnsureModules { modules: list } => match modules::ensure(&list) {
            Some(spec) => Dispatch::Task(spec),
            None => Dispatch::OneShot(Response::Ok),
        },
        Request::RxeLinkAdd { netdev } => Dispatch::Task(modules::rxe_link_add(&netdev)),
        Request::DevlinkParams { pci } => Dispatch::Task(modules::devlink_params(&pci)),
        Request::RoceEnableParam { pci } => Dispatch::Task(modules::devlink_roce_enable(&pci)),
        Request::DevlinkReload { pci } => Dispatch::Task(modules::devlink_reload(&pci)),

        Request::PartitionTableCreate { disk } => Dispatch::Task(partition::table_create(&disk)),
        Request::PartitionCreate {
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
        Request::PartitionDelete { disk, number } => {
            Dispatch::Task(partition::partition_delete(&disk, number))
        }
        Request::PartitionResize {
            disk,
            number,
            size_sectors,
        } => Dispatch::Task(partition::partition_resize(&disk, number, size_sectors)),

        Request::Fsck { device } => Dispatch::Task(fs::fsck(&device)),
        Request::ResizeExt {
            device,
            new_size_sectors,
        } => Dispatch::Task(fs::resize_ext(&device, new_size_sectors)),
        Request::BtrfsMount { device, mount_path } => {
            Dispatch::Task(fs::btrfs_mount(&device, &mount_path))
        }
        Request::BtrfsResize {
            mount_path,
            new_size,
        } => Dispatch::Task(fs::btrfs_resize(&mount_path, new_size)),
        Request::Umount { mount_path } => Dispatch::Task(fs::umount(&mount_path)),

        Request::PoolCreate {
            name,
            vdev,
            devices,
            ashift,
        } => Dispatch::Task(zfs::pool_create(&name, vdev, &devices, ashift)),
        Request::PoolDeviceAdd { pool, device } => {
            Dispatch::Task(zfs::pool_device_add(&pool, &device))
        }

        Request::LvmReport { what } => Dispatch::Task(lvm::report(what)),
        Request::VgCreate { name, devices } => Dispatch::Task(lvm::vg_create(&name, &devices)),
        Request::VgExtend { vg, device } => Dispatch::Task(lvm::vg_extend(&vg, &device)),
        Request::VgReduce { vg, device } => Dispatch::Task(lvm::vg_reduce(&vg, &device)),
        Request::VgRemove { vg } => Dispatch::Task(lvm::vg_remove(&vg)),
        Request::LvCreate { vg, name, size } => Dispatch::Task(lvm::lv_create(&vg, &name, size)),
        Request::ThinPoolCreate { vg, name, size } => {
            Dispatch::Task(lvm::thin_pool_create(&vg, &name, size))
        }
        Request::ThinLvCreate {
            vg,
            pool,
            name,
            virtual_size,
        } => Dispatch::Task(lvm::thin_lv_create(&vg, &pool, &name, virtual_size)),
        Request::LvResize { vg, name, new_size } => {
            Dispatch::Task(lvm::lv_resize(&vg, &name, new_size))
        }
        Request::LvShrink { vg, name, new_size } => {
            Dispatch::Task(lvm::lv_shrink(&vg, &name, new_size))
        }
        Request::LvRename { vg, name, new_name } => {
            Dispatch::Task(lvm::lv_rename(&vg, &name, &new_name))
        }
        Request::LvDelete { vg, name } => Dispatch::Task(lvm::lv_delete(&vg, &name)),

        Request::InstallPackages { packages } => {
            match install::install(&packages, &greendot_proto::detect()) {
                Ok(Some(spec)) => Dispatch::Task(spec),
                Ok(None) => Dispatch::OneShot(Response::Ok),
                Err(msg) => Dispatch::FailedTask(msg),
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
    fn mp(s: &str) -> MountPath {
        MountPath::new(s).unwrap()
    }
    fn pci(s: &str) -> PciAddress {
        PciAddress::new(s).unwrap()
    }

    /// Each task request must route to exactly the command its dedicated builder
    /// produces; the builder is the oracle, so a mis-wired arm (wrong function or
    /// wrong field) is caught without re-spelling the command line here.
    #[rstest]
    #[case::zvol_create(
        Request::ZvolCreate { dataset: ds("tank/vm1"), size: 5 << 30, volblocksize: Some(8192), sparse: true },
        zfs::zvol_create(&ds("tank/vm1"), 5 << 30, Some(8192), true))]
    #[case::zvol_delete(
        Request::ZvolDelete { dataset: ds("tank/vm1") },
        zfs::zvol_delete(&ds("tank/vm1")))]
    #[case::zvol_resize(
        Request::ZvolResize { dataset: ds("tank/vm1"), new_size: 7 << 30 },
        zfs::zvol_resize(&ds("tank/vm1"), 7 << 30))]
    #[case::snapshot_create(
        Request::SnapshotCreate { dataset: ds("tank/vm1"), snap: sn("daily") },
        zfs::snapshot_create(&ds("tank/vm1"), &sn("daily")))]
    #[case::snapshot_destroy(
        Request::SnapshotDestroy { dataset: ds("tank/vm1"), snap: sn("daily") },
        zfs::snapshot_destroy(&ds("tank/vm1"), &sn("daily")))]
    #[case::pool_create(
        Request::PoolCreate { name: PoolName::new("tank").unwrap(), vdev: VdevLayout::Mirror, devices: vec![dev("/dev/sdb"), dev("/dev/sdc")], ashift: Some(12) },
        zfs::pool_create(&PoolName::new("tank").unwrap(), VdevLayout::Mirror, &[dev("/dev/sdb"), dev("/dev/sdc")], Some(12)))]
    #[case::pool_device_add(
        Request::PoolDeviceAdd { pool: PoolName::new("tank").unwrap(), device: dev("/dev/sdd") },
        zfs::pool_device_add(&PoolName::new("tank").unwrap(), &dev("/dev/sdd")))]
    #[case::lio_apply(
        Request::LioApply { desired: LioDesired::default() },
        lio::apply_spec(&LioDesired::default()))]
    #[case::ensure_modules(
        Request::EnsureModules { modules: vec![KernelModule::Rxe] },
        modules::ensure(&[KernelModule::Rxe]).unwrap())]
    #[case::rxe_link_add(
        Request::RxeLinkAdd { netdev: NetdevName::new("eth0").unwrap() },
        modules::rxe_link_add(&NetdevName::new("eth0").unwrap()))]
    #[case::devlink_params(
        Request::DevlinkParams { pci: pci("0000:00:10.0") },
        modules::devlink_params(&pci("0000:00:10.0")))]
    #[case::roce_enable_param(
        Request::RoceEnableParam { pci: pci("0000:00:10.0") },
        modules::devlink_roce_enable(&pci("0000:00:10.0")))]
    #[case::devlink_reload(
        Request::DevlinkReload { pci: pci("0000:00:10.0") },
        modules::devlink_reload(&pci("0000:00:10.0")))]
    #[case::partition_table_create(
        Request::PartitionTableCreate { disk: disk("sdb") },
        partition::table_create(&disk("sdb")))]
    #[case::partition_create(
        Request::PartitionCreate { disk: disk("sdb"), start_sector: Some(2048), size_sectors: Some(1 << 20), label: PartLabel::new("data").unwrap() },
        partition::partition_create(&disk("sdb"), Some(2048), Some(1 << 20), &PartLabel::new("data").unwrap()))]
    #[case::partition_delete(
        Request::PartitionDelete { disk: disk("sdb"), number: 2 },
        partition::partition_delete(&disk("sdb"), 2))]
    #[case::partition_resize(
        Request::PartitionResize { disk: disk("sdb"), number: 2, size_sectors: 1 << 21 },
        partition::partition_resize(&disk("sdb"), 2, 1 << 21))]
    #[case::fsck(
        Request::Fsck { device: dev("/dev/sdb2") },
        fs::fsck(&dev("/dev/sdb2")))]
    #[case::resize_ext(
        Request::ResizeExt { device: dev("/dev/sdb2"), new_size_sectors: 1 << 21 },
        fs::resize_ext(&dev("/dev/sdb2"), 1 << 21))]
    #[case::btrfs_mount(
        Request::BtrfsMount { device: dev("/dev/sdb2"), mount_path: mp("/run/greendotrdma/btrfs-resize-sdb2") },
        fs::btrfs_mount(&dev("/dev/sdb2"), &mp("/run/greendotrdma/btrfs-resize-sdb2")))]
    #[case::btrfs_resize(
        Request::BtrfsResize { mount_path: mp("/run/greendotrdma/btrfs-resize-sdb2"), new_size: 1 << 30 },
        fs::btrfs_resize(&mp("/run/greendotrdma/btrfs-resize-sdb2"), 1 << 30))]
    #[case::umount(
        Request::Umount { mount_path: mp("/run/greendotrdma/btrfs-resize-sdb2") },
        fs::umount(&mp("/run/greendotrdma/btrfs-resize-sdb2")))]
    #[case::lvm_report(
        Request::LvmReport { what: LvmReport::Vgs },
        lvm::report(LvmReport::Vgs))]
    #[case::vg_create(
        Request::VgCreate { name: vg("vg0"), devices: vec![dev("/dev/sdb")] },
        lvm::vg_create(&vg("vg0"), &[dev("/dev/sdb")]))]
    #[case::vg_extend(
        Request::VgExtend { vg: vg("vg0"), device: dev("/dev/sdc") },
        lvm::vg_extend(&vg("vg0"), &dev("/dev/sdc")))]
    #[case::vg_reduce(
        Request::VgReduce { vg: vg("vg0"), device: dev("/dev/sdc") },
        lvm::vg_reduce(&vg("vg0"), &dev("/dev/sdc")))]
    #[case::vg_remove(
        Request::VgRemove { vg: vg("vg0") },
        lvm::vg_remove(&vg("vg0")))]
    #[case::lv_create(
        Request::LvCreate { vg: vg("vg0"), name: lv("data"), size: 10 << 30 },
        lvm::lv_create(&vg("vg0"), &lv("data"), 10 << 30))]
    #[case::thin_pool_create(
        Request::ThinPoolCreate { vg: vg("vg0"), name: lv("pool0"), size: 50 << 30 },
        lvm::thin_pool_create(&vg("vg0"), &lv("pool0"), 50 << 30))]
    #[case::thin_lv_create(
        Request::ThinLvCreate { vg: vg("vg0"), pool: lv("pool0"), name: lv("vm1"), virtual_size: 20 << 30 },
        lvm::thin_lv_create(&vg("vg0"), &lv("pool0"), &lv("vm1"), 20 << 30))]
    #[case::lv_resize(
        Request::LvResize { vg: vg("vg0"), name: lv("data"), new_size: 12 << 30 },
        lvm::lv_resize(&vg("vg0"), &lv("data"), 12 << 30))]
    #[case::lv_shrink(
        Request::LvShrink { vg: vg("vg0"), name: lv("data"), new_size: 8 << 30 },
        lvm::lv_shrink(&vg("vg0"), &lv("data"), 8 << 30))]
    #[case::lv_rename(
        Request::LvRename { vg: vg("vg0"), name: lv("data"), new_name: lv("archive") },
        lvm::lv_rename(&vg("vg0"), &lv("data"), &lv("archive")))]
    #[case::lv_delete(
        Request::LvDelete { vg: vg("vg0"), name: lv("data") },
        lvm::lv_delete(&vg("vg0"), &lv("data")))]
    fn task_requests_route_to_their_builder(#[case] req: Request, #[case] expected: TaskSpec) {
        assert_eq!(task(plan(&ctx(), req)), expected);
    }

    /// The non-task arms: immediate replies, configfs apply, and the empty-set
    /// shortcuts that need no command at all.
    #[test]
    fn oneshot_and_special_arms() {
        let ctx = ctx();
        assert!(matches!(
            plan(&ctx, Request::Ping),
            Dispatch::OneShot(Response::Ok)
        ));
        // Rate limiter is exhausted, so the reply is Busy (not real PAM auth).
        assert!(matches!(
            plan(
                &ctx,
                Request::Authenticate {
                    username: Username::new("alice").unwrap(),
                    password: Secret("secret".into()),
                }
            ),
            Dispatch::OneShot(Response::Err {
                kind: ErrKind::Busy,
                ..
            })
        ));
        // Empty module / package sets resolve to a no-op reply, not a task.
        assert!(matches!(
            plan(&ctx, Request::EnsureModules { modules: vec![] }),
            Dispatch::OneShot(Response::Ok)
        ));
        assert!(matches!(
            plan(&ctx, Request::InstallPackages { packages: vec![] }),
            Dispatch::OneShot(Response::Ok)
        ));
        // NVMe-oF apply is carried through verbatim for the helper to write.
        let desired = NvmetDesired::default();
        assert!(matches!(
            plan(&ctx, Request::NvmetApply { desired: desired.clone() }),
            Dispatch::NvmetApply(d) if d == desired
        ));
    }
}
