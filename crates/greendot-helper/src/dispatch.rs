//! The privileged-operation allowlist: every reachable operation is a
//! `Request` variant handled here.

use crate::cmd::Runner;
use crate::{lio, modules, nvmet, pam, zfs};
use greendot_proto::{ErrKind, Request, Response};
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Ctx {
    pub auth: pam::AuthConfig,
    pub auth_limiter: Mutex<pam::RateLimiter>,
    pub runner: Box<dyn Runner>,
    pub nvmet_root: PathBuf,
    pub lio_root: PathBuf,
    /// Serializes all mutating operations so configfs changes never interleave.
    pub mutate_lock: Mutex<()>,
}

pub fn dispatch(ctx: &Ctx, req: Request) -> Response {
    match req {
        Request::Ping => Response::Ok,
        Request::Authenticate { username, password } => {
            pam::authenticate(&ctx.auth, &ctx.auth_limiter, &username, &password)
        }
        mutation => {
            let _guard = ctx.mutate_lock.lock().unwrap();
            let runner = ctx.runner.as_ref();
            match mutation {
                Request::ZvolCreate {
                    dataset,
                    size,
                    volblocksize,
                    sparse,
                } => zfs::zvol_create(runner, &dataset, size, volblocksize, sparse),
                Request::ZvolDelete { dataset } => zfs::zvol_delete(runner, &dataset),
                Request::ZvolResize { dataset, new_size } => {
                    zfs::zvol_resize(runner, &dataset, new_size)
                }
                Request::SnapshotCreate { dataset, snap } => {
                    zfs::snapshot_create(runner, &dataset, &snap)
                }
                Request::SnapshotDestroy { dataset, snap } => {
                    zfs::snapshot_destroy(runner, &dataset, &snap)
                }
                Request::NvmetSubsysCreate {
                    nqn,
                    allow_any_host,
                } => nvmet::subsys_create(&ctx.nvmet_root, &nqn, allow_any_host),
                Request::NvmetSubsysDelete { nqn } => nvmet::subsys_delete(&ctx.nvmet_root, &nqn),
                Request::NvmetNamespaceSet {
                    nqn,
                    nsid,
                    device_path,
                    enable,
                } => nvmet::namespace_set(&ctx.nvmet_root, &nqn, nsid, &device_path, enable),
                Request::NvmetNamespaceDelete { nqn, nsid } => {
                    nvmet::namespace_delete(&ctx.nvmet_root, &nqn, nsid)
                }
                Request::NvmetPortCreate {
                    id,
                    trtype,
                    traddr,
                    trsvcid,
                } => nvmet::port_create(&ctx.nvmet_root, id, trtype, traddr, trsvcid),
                Request::NvmetPortDelete { id } => nvmet::port_delete(&ctx.nvmet_root, id),
                Request::NvmetPortLink { port, nqn } => {
                    nvmet::port_link(&ctx.nvmet_root, port, &nqn)
                }
                Request::NvmetPortUnlink { port, nqn } => {
                    nvmet::port_unlink(&ctx.nvmet_root, port, &nqn)
                }
                Request::NvmetHostAllow { nqn, host_nqn } => {
                    nvmet::host_allow(&ctx.nvmet_root, &nqn, &host_nqn)
                }
                Request::NvmetHostRemove { nqn, host_nqn } => {
                    nvmet::host_remove(&ctx.nvmet_root, &nqn, &host_nqn)
                }
                Request::LioBackstoreCreate { name, device_path } => {
                    lio::backstore_create(&ctx.lio_root, &name, &device_path)
                }
                Request::LioBackstoreDelete { name } => lio::backstore_delete(&ctx.lio_root, &name),
                Request::LioTargetCreate { iqn } => lio::target_create(&ctx.lio_root, &iqn),
                Request::LioTargetDelete { iqn } => lio::target_delete(&ctx.lio_root, &iqn),
                Request::LioLunMap {
                    iqn,
                    lun,
                    backstore,
                } => lio::lun_map(&ctx.lio_root, &iqn, lun, &backstore),
                Request::LioPortalSet {
                    iqn,
                    addr,
                    port,
                    iser,
                } => lio::portal_set(&ctx.lio_root, &iqn, addr, port, iser),
                Request::LioPortalDelete { iqn, addr, port } => {
                    lio::portal_delete(&ctx.lio_root, &iqn, addr, port)
                }
                Request::LioAclAdd { iqn, initiator } => {
                    lio::acl_add(&ctx.lio_root, &iqn, &initiator)
                }
                Request::LioAclRemove { iqn, initiator } => {
                    lio::acl_remove(&ctx.lio_root, &iqn, &initiator)
                }
                Request::LioTpgSet {
                    iqn,
                    enabled,
                    demo_mode,
                    auth,
                } => lio::tpg_set(&ctx.lio_root, &iqn, enabled, demo_mode, auth.as_ref()),
                Request::EnsureModules { modules: list } => modules::ensure(runner, &list),
                Request::RxeLinkAdd { netdev } => modules::rxe_link_add(runner, &netdev),
                other => Response::err(
                    ErrKind::Unsupported,
                    format!("not yet implemented: {other:?}"),
                ),
            }
        }
    }
}
