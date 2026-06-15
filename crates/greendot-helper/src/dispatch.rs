//! The privileged-operation allowlist. Each task op resolves to exactly one
//! command (a [`TaskSpec`]); `Ping`/`Authenticate` are one-shot replies and
//! are never recorded as tasks (auth would store the password).

use crate::cmd::TaskSpec;
use crate::{install, lio, modules, nvmet, pam, partition, zfs};
use greendot_proto::{Request, Response};
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

        Request::NvmetApply { desired } => Dispatch::Task(nvmet::apply_spec(&desired)),
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

        Request::InstallPackages { packages } => {
            match install::install(&packages, &greendot_proto::detect()) {
                Ok(Some(spec)) => Dispatch::Task(spec),
                Ok(None) => Dispatch::OneShot(Response::Ok),
                Err(msg) => Dispatch::FailedTask(msg),
            }
        }
    }
}
