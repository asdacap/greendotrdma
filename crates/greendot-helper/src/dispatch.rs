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
