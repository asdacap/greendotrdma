use super::snapshots::SnapRow;
use super::{AppState, page};
use crate::actual::block;
use crate::actual::zfs::{self, DsKind};
use crate::auth::{CurrentUser, nav_redirect};
use crate::fmt::human_bytes;
use crate::metrics::{ChartUnit, chart_svg};
use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Router, routing::post};
use greendot_proto::{DatasetName, DevicePath, MountPoint, PoolName, VdevLayout, VdevTarget, ops};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/zfs", axum::routing::get(zfs_page))
        .route("/zfs/pool/create", axum::routing::get(pool_create_page))
        .route("/zfs/pool", post(pool_create))
        .route("/zfs/pool/{name}", axum::routing::get(pool_detail_page))
        .route("/zfs/pool/{name}/add-device", post(pool_add_device))
        .route("/zfs/pool/{name}/remove-device", post(pool_remove_device))
        .route("/zfs/pool/{name}/detach-device", post(pool_detach_device))
        .route(
            "/zfs/pool/{pool}/zvol/{*rest}",
            axum::routing::get(zvol_detail_page),
        )
        .route(
            "/zfs/dataset/{*name}",
            axum::routing::get(dataset_detail_page),
        )
        .route("/zfs/zvol", post(zvol_create))
        .route("/zfs/zvol/resize", post(zvol_resize))
        .route("/zfs/zvol/delete", post(zvol_delete))
        .route("/zfs/fs", post(fs_create))
        .route("/zfs/fs/mount", post(fs_mount))
        .route("/zfs/fs/unmount", post(fs_unmount))
        .route("/zfs/fs/set-mountpoint", post(fs_set_mountpoint))
        .route("/zfs/fs/destroy", post(fs_destroy))
}

pub struct PoolRow {
    pub name: String,
    pub size: String,
    pub free: String,
    pub used_percent: u8,
    pub frag: String,
    pub health: String,
    pub healthy: bool,
}

impl PoolRow {
    fn new(p: zfs::Pool) -> Self {
        PoolRow {
            used_percent: (p.alloc.saturating_mul(100) / p.size.max(1)) as u8,
            size: human_bytes(p.size),
            free: human_bytes(p.free),
            frag: p.frag_percent.map_or("–".into(), |f| format!("{f}%")),
            healthy: p.health == "ONLINE",
            health: p.health,
            name: p.name,
        }
    }
}

pub struct ZvolRow {
    pub name: String,
    /// The pool (first path component) the zvol belongs to, for the per-zvol page link.
    pub pool: String,
    /// `name` with the `"{pool}/"` prefix stripped, for the per-zvol page link.
    pub rel: String,
    pub used: String,
    pub volsize: String,
}

pub struct FsRow {
    pub name: String,
    pub used: String,
    /// Mountpoint path, or `none`/`legacy`/`-`.
    pub mountpoint: String,
    pub mounted: bool,
    /// Whether `zfs mount` applies (an absolute-path mountpoint, not yet mounted).
    pub mountable: bool,
}

#[derive(Default)]
pub struct ZfsView {
    pub pools: Vec<PoolRow>,
    /// True when the `zpool`/`zfs` binaries are absent on this host.
    pub not_installed: bool,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "zfs.html")]
struct ZfsTemplate {
    user: CurrentUser,
    view: ZfsView,
}

/// The ZFS landing page: a pool index that links into each pool's own page.
async fn gather() -> ZfsView {
    let mut view = ZfsView::default();
    match zfs::pools().await {
        Ok(Some(pools)) => view.pools = pools.into_iter().map(PoolRow::new).collect(),
        // Absent `zpool` ⇒ ZFS isn't installed on this host.
        Ok(None) => view.not_installed = true,
        Err(e) => view.error = Some(format!("could not read ZFS state: {e:#}")),
    }
    view
}

async fn zfs_page(
    State(_): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(ZfsTemplate {
        user,
        view: gather().await,
    })
}

// ---- Per-pool page (zvol listing + creation) ----

/// One row of the pool's device table: a top-level vdev or an indented leaf,
/// with the actions the view builder decided apply to it (the template stays
/// dumb; the helper re-validates regardless).
pub struct MemberRow {
    pub name: String,
    /// Disk/partition detail-page URL for a leaf device, so the name links to
    /// its device page. `None` for vdev containers (`mirror-0`, …) and for
    /// devices lsblk didn't report (a missing member) — those render unlinked.
    pub detail_url: Option<String>,
    /// Allocation-class tag next to the name (`log`, `cache`, …; empty for data).
    pub class: String,
    /// A leaf inside a mirror/raidz container — indented in the table.
    pub is_child: bool,
    pub size: String,
    pub health: String,
    pub can_remove: bool,
    pub can_detach: bool,
}

/// Maps each block device's `/dev/<name>` path to its detail-page URL, so a pool
/// member — which zpool reports as a `/dev/...` leaf path (by-id links resolved
/// to kernel names by `-L`) — can link to the disk or partition page.
fn device_detail_urls(disks: Vec<block::Disk>) -> HashMap<String, String> {
    let mut urls = HashMap::new();
    for d in disks {
        urls.insert(format!("/dev/{}", d.name), format!("/disks/{}", d.name));
        for p in d.partitions {
            if let Some(n) = p.number {
                urls.insert(
                    format!("/dev/{}", p.name),
                    format!("/disks/{}/part/{n}", d.name),
                );
            }
        }
    }
    urls
}

/// Decides per-member actions. Detach applies to leaves inside a mirror.
/// Remove is offered where `zpool remove` can succeed: any log/cache/spare
/// member, and top-level data/special/dedup vdevs when the pool has no
/// raidz (which blocks device evacuation) and more than one data vdev
/// remains. These gates only hide doomed buttons — zpool re-checks anyway
/// and the recorded task shows its stderr verbatim.
fn member_rows(
    members: Vec<zfs::PoolMember>,
    dev_urls: &HashMap<String, String>,
) -> Vec<MemberRow> {
    use zfs::MemberClass as C;
    let toplevel_data = |m: &&zfs::PoolMember| m.class == C::Data && m.parent.is_none();
    let pool_has_raidz = members
        .iter()
        .filter(toplevel_data)
        .any(|m| !m.is_leaf && (m.name.starts_with("raidz") || m.name.starts_with("draid")));
    let data_toplevels = members.iter().filter(toplevel_data).count();
    members
        .into_iter()
        .map(|m| {
            let in_mirror = m
                .parent
                .as_deref()
                .is_some_and(|p| p.starts_with("mirror-"));
            let can_remove = m.parent.is_none()
                && VdevTarget::new(&m.name).is_ok()
                && match m.class {
                    C::Data => {
                        !pool_has_raidz
                            && data_toplevels > 1
                            && (m.is_leaf || m.name.starts_with("mirror-"))
                    }
                    C::Log | C::Cache | C::Spare => true,
                    C::Special | C::Dedup => !pool_has_raidz,
                };
            MemberRow {
                detail_url: dev_urls.get(&m.name).cloned(),
                can_detach: m.is_leaf && in_mirror && DevicePath::new(&m.name).is_ok(),
                can_remove,
                is_child: m.parent.is_some(),
                class: match m.class {
                    C::Data => "",
                    C::Log => "log",
                    C::Cache => "cache",
                    C::Spare => "spare",
                    C::Special => "special",
                    C::Dedup => "dedup",
                }
                .into(),
                size: m.size.map_or("–".into(), human_bytes),
                health: m.health.unwrap_or_else(|| "–".into()),
                name: m.name,
            }
        })
        .collect()
}

#[derive(Default)]
pub struct PoolDetailView {
    pub name: String,
    /// `None` when the named pool doesn't exist on this host.
    pub pool: Option<PoolRow>,
    /// The pool's vdev tree with per-row remove/detach actions.
    pub members: Vec<MemberRow>,
    /// Live pool traffic/capacity charts (inline SVG; rendered unescaped).
    pub read_svg: String,
    pub write_svg: String,
    pub used_svg: String,
    /// Child filesystem datasets in this pool (mount/unmount/destroy targets).
    pub fs_rows: Vec<FsRow>,
    /// Filesystems in this pool, offered as zvol/filesystem parents.
    pub parents: Vec<String>,
    /// Empty raw devices offered to expand this pool (the "Add device" form).
    pub add_devices: Vec<PoolDeviceOption>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "pool_detail.html")]
struct PoolDetailTemplate {
    user: CurrentUser,
    view: PoolDetailView,
}

#[derive(Template)]
#[template(path = "_pool_detail.html")]
struct PoolDetailPartial {
    view: PoolDetailView,
}

async fn gather_pool_detail(
    state: &AppState,
    name: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> PoolDetailView {
    let mut view = PoolDetailView {
        name: name.to_owned(),
        flash,
        form_error,
        task_id,
        ..Default::default()
    };
    match tokio::try_join!(zfs::pools(), zfs::datasets(), zfs::pool_vdevs()) {
        Ok((Some(pools), Some(datasets), Some(vdevs))) => {
            view.pool = pools.into_iter().find(|p| p.name == name).map(PoolRow::new);
            // Best-effort device→page map so members link to their disk page;
            // a disk-listing failure just leaves the names unlinked.
            let dev_urls = block::disks()
                .await
                .map(device_detail_urls)
                .unwrap_or_default();
            view.members = member_rows(
                vdevs.into_iter().filter(|m| m.pool == name).collect(),
                &dev_urls,
            );
            // A vdev added to the pool must be an empty raw device, so offer the
            // same candidates as pool creation (no zvols, LVs, or formatted parts).
            if view.pool.is_some() {
                view.add_devices = gather_pool_create(state, &HashSet::new(), None)
                    .await
                    .devices;
                let series = |suffix| state.metrics.ring_series(&format!("pool:{name}:{suffix}"));
                view.read_svg = chart_svg(&series("read_bps"), 600, 120, ChartUnit::Bytes);
                view.write_svg = chart_svg(&series("write_bps"), 600, 120, ChartUnit::Bytes);
                view.used_svg = chart_svg(&series("used_percent"), 600, 120, ChartUnit::Percent);
            }
            let prefix = format!("{name}/");
            view.parents = datasets
                .iter()
                .filter(|d| {
                    d.kind == DsKind::Filesystem && (d.name == name || d.name.starts_with(&prefix))
                })
                .map(|d| d.name.clone())
                .collect();
            // Child filesystem datasets (the pool root itself is managed via
            // pools, not listed here as a mount/destroy target).
            view.fs_rows = datasets
                .iter()
                .filter(|d| d.kind == DsKind::Filesystem && d.name.starts_with(&prefix))
                .map(|d| FsRow {
                    mountable: !d.mounted && d.mountpoint.starts_with('/'),
                    mounted: d.mounted,
                    mountpoint: d.mountpoint.clone(),
                    used: human_bytes(d.used),
                    name: d.name.clone(),
                })
                .collect();
        }
        // Either binary missing → ZFS isn't installed on this host.
        Ok(_) => view.not_installed = true,
        Err(e) => view.error = Some(format!("could not read ZFS state: {e:#}")),
    }
    view
}

async fn pool_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(name): Path<String>,
) -> Response {
    page(PoolDetailTemplate {
        user,
        view: gather_pool_detail(&state, &name, None, None, None).await,
    })
}

/// Parses a "value + unit" size form input into bytes.
pub fn parse_size(value: &str, unit: &str) -> Option<u64> {
    let value: u64 = value.trim().parse().ok()?;
    let mult: u64 = match unit {
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        _ => return None,
    };
    value.checked_mul(mult).filter(|&b| b > 0)
}

/// The pool (first path component) a dataset belongs to.
fn pool_of(dataset: &str) -> &str {
    dataset.split('/').next().unwrap_or(dataset)
}

/// Runs a pool/zvol request as a recorded task and re-renders the owning pool's
/// detail partial with the outcome.
async fn run_pool_op(
    state: &Arc<AppState>,
    rx: tokio::sync::mpsc::Receiver<greendot_proto::TaskEvent>,
    kind: &str,
    title: &str,
    pool: &str,
) -> Response {
    let view = match crate::task_runner::start(state, rx, kind, title) {
        Ok(id) => {
            gather_pool_detail(
                state,
                pool,
                Some(format!("started {title}")),
                None,
                Some(id),
            )
            .await
        }
        Err(e) => gather_pool_detail(state, pool, None, Some(format!("{e:#}")), None).await,
    };
    page(PoolDetailPartial { view })
}

async fn pool_op_failed(state: &AppState, pool: &str, message: impl Into<String>) -> Response {
    page(PoolDetailPartial {
        view: gather_pool_detail(state, pool, None, Some(message.into()), None).await,
    })
}

// ---- Per-zvol page (resize + delete) ----

#[derive(Default)]
pub struct ZvolDetailView {
    pub pool: String,
    /// The zvol's full dataset name (`pool/…`).
    pub name: String,
    /// `None` when the named zvol doesn't exist on this host.
    pub zvol: Option<ZvolRow>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "zvol_detail.html")]
struct ZvolDetailTemplate {
    user: CurrentUser,
    view: ZvolDetailView,
}

#[derive(Template)]
#[template(path = "_zvol_detail.html")]
struct ZvolDetailPartial {
    view: ZvolDetailView,
}

async fn gather_zvol_detail(
    pool: &str,
    rest: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> ZvolDetailView {
    let dataset = format!("{pool}/{rest}");
    let mut view = ZvolDetailView {
        pool: pool.to_owned(),
        name: dataset.clone(),
        flash,
        form_error,
        task_id,
        ..Default::default()
    };
    match zfs::datasets().await {
        Ok(Some(datasets)) => {
            view.zvol = datasets
                .into_iter()
                .find(|d| d.kind == DsKind::Volume && d.name == dataset)
                .map(|d| ZvolRow {
                    pool: pool.to_owned(),
                    rel: rest.to_owned(),
                    used: human_bytes(d.used),
                    volsize: d.volsize.map_or(String::new(), human_bytes),
                    name: d.name,
                });
        }
        // Absent `zfs` ⇒ ZFS isn't installed on this host.
        Ok(None) => view.not_installed = true,
        Err(e) => view.error = Some(format!("could not read ZFS state: {e:#}")),
    }
    view
}

async fn zvol_detail_page(
    State(_): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path((pool, rest)): Path<(String, String)>,
) -> Response {
    page(ZvolDetailTemplate {
        user,
        view: gather_zvol_detail(&pool, &rest, None, None, None).await,
    })
}

/// Runs a zvol request as a recorded task and re-renders the owning zvol's
/// detail partial with the outcome.
async fn run_zvol_op(
    state: &Arc<AppState>,
    rx: tokio::sync::mpsc::Receiver<greendot_proto::TaskEvent>,
    kind: &str,
    title: &str,
    pool: &str,
    rest: &str,
) -> Response {
    let view = match crate::task_runner::start(state, rx, kind, title) {
        Ok(id) => {
            gather_zvol_detail(pool, rest, Some(format!("started {title}")), None, Some(id)).await
        }
        Err(e) => gather_zvol_detail(pool, rest, None, Some(format!("{e:#}")), None).await,
    };
    page(ZvolDetailPartial { view })
}

async fn zvol_detail_failed(pool: &str, rest: &str, message: impl Into<String>) -> Response {
    page(ZvolDetailPartial {
        view: gather_zvol_detail(pool, rest, None, Some(message.into()), None).await,
    })
}

/// The zvol's name within its pool (full dataset minus the `"{pool}/"` prefix).
fn zvol_rel<'a>(pool: &str, dataset: &'a str) -> &'a str {
    dataset
        .strip_prefix(pool)
        .map_or(dataset, |s| s.trim_start_matches('/'))
}

// ---- Per-dataset page (zvols + snapshots under a dataset) ----

pub struct DatasetRow {
    pub name: String,
    /// `"filesystem"` or `"volume"`.
    pub kind: String,
    pub used: String,
    pub avail: String,
    pub mountpoint: String,
    pub mounted: bool,
}

#[derive(Default)]
pub struct DatasetDetailView {
    pub name: String,
    /// The pool (first path component) this dataset belongs to, for the back link.
    pub pool: String,
    /// `None` when the named dataset doesn't exist on this host.
    pub dataset: Option<DatasetRow>,
    /// Zvols nested under this dataset.
    pub zvols: Vec<ZvolRow>,
    /// Snapshots of this dataset and its descendants.
    pub snapshots: Vec<SnapRow>,
    pub not_installed: bool,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "dataset_detail.html")]
struct DatasetDetailTemplate {
    user: CurrentUser,
    view: DatasetDetailView,
}

async fn gather_dataset_detail(name: &str) -> DatasetDetailView {
    let mut view = DatasetDetailView {
        name: name.to_owned(),
        pool: pool_of(name).to_owned(),
        ..Default::default()
    };
    match tokio::try_join!(zfs::datasets(), zfs::snapshots()) {
        Ok((Some(datasets), Some(snapshots))) => {
            let child = format!("{name}/");
            view.dataset = datasets
                .iter()
                .find(|d| d.name == name)
                .map(|d| DatasetRow {
                    kind: match d.kind {
                        DsKind::Filesystem => "filesystem",
                        DsKind::Volume => "volume",
                    }
                    .to_owned(),
                    used: human_bytes(d.used),
                    avail: human_bytes(d.avail),
                    mountpoint: d.mountpoint.clone(),
                    mounted: d.mounted,
                    name: d.name.clone(),
                });
            view.zvols = datasets
                .into_iter()
                .filter(|d| d.kind == DsKind::Volume && d.name.starts_with(&child))
                .map(|d| {
                    let pool = pool_of(&d.name).to_owned();
                    let rel = zvol_rel(&pool, &d.name).to_owned();
                    ZvolRow {
                        pool,
                        rel,
                        used: human_bytes(d.used),
                        volsize: d.volsize.map_or(String::new(), human_bytes),
                        name: d.name,
                    }
                })
                .collect();
            view.snapshots = snapshots
                .into_iter()
                .filter(|s| {
                    let ds = s.name.split('@').next().unwrap_or(&s.name);
                    ds == name || ds.starts_with(&child)
                })
                .map(SnapRow::new)
                .collect();
        }
        // Either binary missing → ZFS isn't installed on this host.
        Ok(_) => view.not_installed = true,
        Err(e) => view.error = Some(format!("could not read ZFS state: {e:#}")),
    }
    view
}

async fn dataset_detail_page(
    State(_): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(name): Path<String>,
) -> Response {
    page(DatasetDetailTemplate {
        user,
        view: gather_dataset_detail(&name).await,
    })
}

#[derive(Deserialize)]
struct CreateForm {
    parent: String,
    name: String,
    size: String,
    unit: String,
    #[serde(default)]
    sparse: Option<String>,
    #[serde(default)]
    volblocksize: String,
}

async fn zvol_create(State(state): State<Arc<AppState>>, Form(form): Form<CreateForm>) -> Response {
    let pool = pool_of(&form.parent).to_owned();
    let Ok(dataset) = DatasetName::new(format!("{}/{}", form.parent, form.name.trim())) else {
        return pool_op_failed(&state, &pool, format!("invalid zvol name {:?}", form.name)).await;
    };
    let Some(size) = parse_size(&form.size, &form.unit) else {
        return pool_op_failed(&state, &pool, "invalid size").await;
    };
    let volblocksize = match form.volblocksize.as_str() {
        "" => None,
        v => match v.parse() {
            Ok(v) => Some(v),
            Err(_) => return pool_op_failed(&state, &pool, "invalid volblocksize").await,
        },
    };
    let req = ops::ZvolCreate {
        dataset: dataset.clone(),
        size,
        volblocksize,
        sparse: form.sparse.is_some(),
    };
    run_pool_op(
        &state,
        state.helper.zvol_create(req),
        "zvol-create",
        &format!("create zvol {dataset}"),
        &pool,
    )
    .await
}

#[derive(Deserialize)]
struct ResizeForm {
    dataset: String,
    size: String,
    unit: String,
}

async fn zvol_resize(State(state): State<Arc<AppState>>, Form(form): Form<ResizeForm>) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let rest = zvol_rel(&pool, &form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return zvol_detail_failed(&pool, &rest, "invalid dataset name").await;
    };
    let Some(new_size) = parse_size(&form.size, &form.unit) else {
        return zvol_detail_failed(&pool, &rest, "invalid size").await;
    };
    let req = ops::ZvolResize {
        dataset: dataset.clone(),
        new_size,
    };
    run_zvol_op(
        &state,
        state.helper.zvol_resize(req),
        "zvol-resize",
        &format!("resize {dataset}"),
        &pool,
        &rest,
    )
    .await
}

#[derive(Deserialize)]
struct DeleteForm {
    dataset: String,
}

async fn zvol_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let rest = zvol_rel(&pool, &form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return zvol_detail_failed(&pool, &rest, "invalid dataset name").await;
    };
    let req = ops::ZvolDelete {
        dataset: dataset.clone(),
    };
    // Removing the zvol means its page no longer applies — go back to the pool;
    // the delete task is viewable on /tasks.
    match crate::task_runner::start(
        &state,
        state.helper.zvol_delete(req),
        "zvol-delete",
        &format!("delete {dataset}"),
    ) {
        Ok(_) => nav_redirect(&headers, &format!("/zfs/pool/{pool}")),
        Err(e) => zvol_detail_failed(&pool, &rest, format!("{e:#}")).await,
    }
}

// ---- Filesystem dataset lifecycle (mount support) ----

#[derive(Deserialize)]
struct FsCreateForm {
    parent: String,
    name: String,
    #[serde(default)]
    mountpoint: String,
}

async fn fs_create(State(state): State<Arc<AppState>>, Form(form): Form<FsCreateForm>) -> Response {
    let pool = pool_of(&form.parent).to_owned();
    let Ok(dataset) = DatasetName::new(format!("{}/{}", form.parent, form.name.trim())) else {
        return pool_op_failed(
            &state,
            &pool,
            format!("invalid dataset name {:?}", form.name),
        )
        .await;
    };
    let mountpoint = match form.mountpoint.trim() {
        "" => None,
        m => match MountPoint::new(m) {
            Ok(mp) => Some(mp),
            Err(_) => {
                return pool_op_failed(&state, &pool, format!("invalid mountpoint {m:?}")).await;
            }
        },
    };
    let req = ops::ZfsFsCreate {
        dataset: dataset.clone(),
        mountpoint,
    };
    run_pool_op(
        &state,
        state.helper.zfs_fs_create(req),
        "fs-create",
        &format!("create filesystem {dataset}"),
        &pool,
    )
    .await
}

#[derive(Deserialize)]
struct FsDatasetForm {
    dataset: String,
}

async fn fs_mount(State(state): State<Arc<AppState>>, Form(form): Form<FsDatasetForm>) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return pool_op_failed(&state, &pool, "invalid dataset name").await;
    };
    run_pool_op(
        &state,
        state.helper.zfs_mount(ops::ZfsMount {
            dataset: dataset.clone(),
        }),
        "fs-mount",
        &format!("mount {dataset}"),
        &pool,
    )
    .await
}

async fn fs_unmount(
    State(state): State<Arc<AppState>>,
    Form(form): Form<FsDatasetForm>,
) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return pool_op_failed(&state, &pool, "invalid dataset name").await;
    };
    run_pool_op(
        &state,
        state.helper.zfs_unmount(ops::ZfsUnmount {
            dataset: dataset.clone(),
        }),
        "fs-unmount",
        &format!("unmount {dataset}"),
        &pool,
    )
    .await
}

#[derive(Deserialize)]
struct FsMountpointForm {
    dataset: String,
    mountpoint: String,
}

async fn fs_set_mountpoint(
    State(state): State<Arc<AppState>>,
    Form(form): Form<FsMountpointForm>,
) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return pool_op_failed(&state, &pool, "invalid dataset name").await;
    };
    let Ok(mountpoint) = MountPoint::new(form.mountpoint.trim()) else {
        return pool_op_failed(
            &state,
            &pool,
            format!("invalid mountpoint {:?}", form.mountpoint),
        )
        .await;
    };
    run_pool_op(
        &state,
        state.helper.zfs_set_mountpoint(ops::ZfsSetMountpoint {
            dataset: dataset.clone(),
            mountpoint: mountpoint.clone(),
        }),
        "fs-set-mountpoint",
        &format!("set {dataset} mountpoint={mountpoint}"),
        &pool,
    )
    .await
}

#[derive(Deserialize)]
struct FsDestroyForm {
    dataset: String,
    #[serde(default)]
    recursive: Option<String>,
}

async fn fs_destroy(
    State(state): State<Arc<AppState>>,
    Form(form): Form<FsDestroyForm>,
) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return pool_op_failed(&state, &pool, "invalid dataset name").await;
    };
    let req = ops::ZfsDestroy {
        dataset: dataset.clone(),
        recursive: form.recursive.is_some(),
    };
    run_pool_op(
        &state,
        state.helper.zfs_destroy(req),
        "fs-destroy",
        &format!("destroy {dataset}"),
        &pool,
    )
    .await
}

#[derive(Deserialize)]
struct AddDeviceForm {
    device: String,
}

/// Adds a device to an existing pool (`zpool add`). The pool comes from the URL;
/// the helper refuses a single-disk vdev that would reduce the pool's redundancy.
async fn pool_add_device(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Form(form): Form<AddDeviceForm>,
) -> Response {
    let Ok(pool) = PoolName::new(name.trim()) else {
        return pool_op_failed(&state, &name, format!("invalid pool name {name:?}")).await;
    };
    let Ok(device) = DevicePath::new(form.device.trim()) else {
        return pool_op_failed(&state, &name, format!("invalid device {:?}", form.device)).await;
    };
    let req = ops::PoolDeviceAdd {
        pool: pool.clone(),
        device: device.clone(),
    };
    run_pool_op(
        &state,
        state.helper.pool_device_add(req),
        "pool-add",
        &format!("add {device} to {pool}"),
        &name,
    )
    .await
}

#[derive(Deserialize)]
struct RemoveDeviceForm {
    target: String,
}

/// Removes a leaf device or a whole top-level vdev from a pool (`zpool remove`
/// plus `zpool wait -t remove`, so the task ends when evacuation completes).
async fn pool_remove_device(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Form(form): Form<RemoveDeviceForm>,
) -> Response {
    let Ok(pool) = PoolName::new(name.trim()) else {
        return pool_op_failed(&state, &name, format!("invalid pool name {name:?}")).await;
    };
    let Ok(target) = VdevTarget::new(form.target.trim()) else {
        return pool_op_failed(
            &state,
            &name,
            format!("invalid remove target {:?}", form.target),
        )
        .await;
    };
    let req = ops::PoolDeviceRemove {
        pool: pool.clone(),
        target: target.clone(),
    };
    run_pool_op(
        &state,
        state.helper.pool_device_remove(req),
        "pool-remove",
        &format!("remove {target} from {pool}"),
        &name,
    )
    .await
}

#[derive(Deserialize)]
struct DetachDeviceForm {
    device: String,
}

/// Detaches a leaf device from its mirror (`zpool detach`).
async fn pool_detach_device(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Form(form): Form<DetachDeviceForm>,
) -> Response {
    let Ok(pool) = PoolName::new(name.trim()) else {
        return pool_op_failed(&state, &name, format!("invalid pool name {name:?}")).await;
    };
    let Ok(device) = DevicePath::new(form.device.trim()) else {
        return pool_op_failed(&state, &name, format!("invalid device {:?}", form.device)).await;
    };
    let req = ops::PoolDeviceDetach {
        pool: pool.clone(),
        device: device.clone(),
    };
    run_pool_op(
        &state,
        state.helper.pool_device_detach(req),
        "pool-detach",
        &format!("detach {device} from {pool}"),
        &name,
    )
    .await
}

// ---- Dedicated ZFS pool creation form ----

pub struct PoolDeviceOption {
    pub path: String,
    pub label: String,
    pub checked: bool,
}

#[derive(Default)]
pub struct PoolCreateView {
    pub devices: Vec<PoolDeviceOption>,
    pub not_installed: bool,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "pool_create.html")]
struct PoolCreateTemplate {
    user: CurrentUser,
    view: PoolCreateView,
}

#[derive(Template)]
#[template(path = "_pool_create.html")]
struct PoolCreatePartial {
    view: PoolCreateView,
}

/// Available devices for a new pool: the shared inventory, minus zvols and
/// filesystem-bearing partitions (a vdev must be an empty raw device).
async fn gather_pool_create(
    state: &AppState,
    selected: &HashSet<String>,
    error: Option<String>,
) -> PoolCreateView {
    // Absent `zpool` ⇒ ZFS not installed; an error still counts as installed.
    if matches!(zfs::pools().await, Ok(None)) {
        return PoolCreateView {
            not_installed: true,
            error,
            ..Default::default()
        };
    }
    let in_use: HashSet<String> = state.db.export_device_paths().into_iter().collect();
    let devices = block::available_block_devices(&state.helper, &in_use)
        .await
        .into_iter()
        .filter(|d| {
            d.kind != block::AvailKind::Zvol && d.kind != block::AvailKind::Lv && d.fstype.is_none()
        })
        .map(|d| PoolDeviceOption {
            checked: selected.contains(&d.path),
            path: d.path,
            label: d.label,
        })
        .collect();
    PoolCreateView {
        devices,
        not_installed: false,
        error,
    }
}

async fn pool_create_failed(
    state: &AppState,
    selected: HashSet<String>,
    message: String,
) -> Response {
    page(PoolCreatePartial {
        view: gather_pool_create(state, &selected, Some(message)).await,
    })
}

#[derive(Deserialize)]
struct PoolCreateQuery {
    #[serde(default)]
    device: String,
}

async fn pool_create_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Query(q): Query<PoolCreateQuery>,
) -> Response {
    let selected: HashSet<String> = if q.device.is_empty() {
        HashSet::new()
    } else {
        HashSet::from([q.device])
    };
    page(PoolCreateTemplate {
        user,
        view: gather_pool_create(&state, &selected, None).await,
    })
}

async fn pool_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    // `devices` arrives as repeated keys, so read the raw pair list.
    let (mut name, mut vdev, mut ashift) = (String::new(), String::new(), String::new());
    let mut selected: HashSet<String> = HashSet::new();
    let mut devices: Vec<String> = Vec::new();
    for (k, v) in fields {
        match k.as_str() {
            "name" => name = v,
            "vdev" => vdev = v,
            "ashift" => ashift = v,
            "devices" => {
                selected.insert(v.clone());
                devices.push(v);
            }
            _ => {}
        }
    }
    let Ok(pool) = PoolName::new(name.trim()) else {
        return pool_create_failed(&state, selected, format!("invalid pool name {name:?}")).await;
    };
    let Some(layout) = VdevLayout::parse(vdev.trim()) else {
        return pool_create_failed(&state, selected, "choose a vdev layout".into()).await;
    };
    let mut device_paths = Vec::new();
    for d in &devices {
        let Ok(dp) = DevicePath::new(d.trim()) else {
            return pool_create_failed(&state, selected, format!("invalid device {d:?}")).await;
        };
        device_paths.push(dp);
    }
    if device_paths.len() < layout.min_devices() {
        let msg = format!("{vdev} needs at least {} devices", layout.min_devices());
        return pool_create_failed(&state, selected, msg).await;
    }
    let ashift = match ashift.trim() {
        "" => None,
        a => match a.parse::<u8>() {
            Ok(n) if (9..=16).contains(&n) => Some(n),
            _ => return pool_create_failed(&state, selected, "ashift must be 9–16".into()).await,
        },
    };
    let title = format!("create pool {pool}");
    let req = ops::PoolCreate {
        name: pool,
        vdev: layout,
        devices: device_paths,
        ashift,
    };
    match crate::task_runner::start(&state, state.helper.pool_create(req), "pool-create", &title) {
        Ok(_) => nav_redirect(&headers, "/zfs"),
        Err(e) => pool_create_failed(&state, selected, format!("{e:#}")).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::gib("10", "GiB", Some(10 << 30))]
    #[case::mib("512", "MiB", Some(512 << 20))]
    #[case::tib("2", "TiB", Some(2u64 << 40))]
    #[case::whitespace(" 8 ", "GiB", Some(8 << 30))]
    #[case::zero("0", "GiB", None)]
    #[case::negative("-1", "GiB", None)]
    #[case::fractional("1.5", "GiB", None)]
    #[case::bad_unit("1", "KB", None)]
    #[case::empty("", "GiB", None)]
    #[case::overflow("99999999999", "TiB", None)]
    fn size_parsing(#[case] value: &str, #[case] unit: &str, #[case] expected: Option<u64>) {
        assert_eq!(parse_size(value, unit), expected);
    }

    #[test]
    fn device_detail_urls_maps_disks_and_numbered_partitions() {
        let disk = |name: &str, parts: Vec<block::Partition>| block::Disk {
            name: name.into(),
            size: 0,
            model: None,
            serial: None,
            transport: None,
            id_link: None,
            mountpoint: None,
            fstype: None,
            partitions: parts,
        };
        let part = |name: &str, number: Option<u32>| block::Partition {
            name: name.into(),
            number,
            size: 0,
            label: None,
            mountpoint: None,
            fstype: None,
        };
        let urls = device_detail_urls(vec![
            disk("sdb", vec![part("sdb1", Some(1))]),
            disk("sdg", vec![]),
            // A partition lsblk reported without a number can't address a page.
            disk("sdh", vec![part("sdh1", None)]),
        ]);
        // Whole disk and numbered partition each map to their page; the members
        // table stores full `/dev/...` paths, so keys are `/dev/...` too.
        assert_eq!(
            urls.get("/dev/sdb1").map(String::as_str),
            Some("/disks/sdb/part/1")
        );
        assert_eq!(urls.get("/dev/sdg").map(String::as_str), Some("/disks/sdg"));
        assert_eq!(urls.get("/dev/sdh1"), None);
    }

    #[rstest]
    #[case::pool_root("tank", "tank")]
    #[case::nested("tank/vols/vm1", "tank")]
    #[case::bare("rpool", "rpool")]
    fn pool_derivation(#[case] dataset: &str, #[case] expected: &str) {
        assert_eq!(pool_of(dataset), expected);
    }

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::http::{Request as HttpRequest, StatusCode, header};

        #[tokio::test]
        async fn page_create_and_validation_flow() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;

            // The ZFS index lists pools and links to pool creation — unless ZFS
            // is unavailable on the test host, in which case it says so. Either
            // is a successful render, not a failure.
            let req = HttpRequest::get("/zfs")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("Create pool") || body.contains("ZFS is not installed"),
                "{body}"
            );

            // The per-pool page hosts the create-zvol form (or the same notice,
            // or a "not found" when the pool is absent).
            let req = HttpRequest::get("/zfs/pool/tank")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("Create zvol")
                    || body.contains("ZFS is not installed")
                    || body.contains("not found"),
                "{body}"
            );

            // Valid create goes to the (fake) helper and reports success.
            let mut req = form_post(
                "/zfs/zvol",
                "parent=tank&name=vm1&size=10&unit=GiB&volblocksize=",
            );
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("started create zvol tank/vm1"), "{body}");

            // Invalid name is rejected before reaching the helper.
            let mut req = form_post(
                "/zfs/zvol",
                "parent=tank&name=..&size=10&unit=GiB&volblocksize=",
            );
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("invalid zvol name"), "{body}");

            // The per-zvol page renders (graceful "not found" in the test env).
            let req = HttpRequest::get("/zfs/pool/tank/zvol/vm1")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("Zvol tank/vm1")
                    && (body.contains("Resize")
                        || body.contains("ZFS is not installed")
                        || body.contains("not found")),
                "{body}"
            );

            // Resize is a stay-op: it re-renders the zvol's detail partial.
            let mut req = form_post("/zfs/zvol/resize", "dataset=tank/vm1&size=20&unit=GiB");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("zvol-detail-content") && body.contains("started resize tank/vm1"),
                "{body}"
            );

            // Delete is a remove-op: a non-htmx POST redirects back to the pool.
            let mut req = form_post("/zfs/zvol/delete", "dataset=tank/vm1");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            let (status, headers, _) = send(&app, req).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
            assert_eq!(headers[header::LOCATION], "/zfs/pool/tank");
        }

        #[tokio::test]
        async fn filesystem_mount_lifecycle_flow() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // Create a filesystem dataset with an explicit mountpoint.
            let (_, _, body) = send(
                &app,
                auth(form_post(
                    "/zfs/fs",
                    "parent=tank&name=share&mountpoint=%2Fsrv%2Fshare",
                )),
            )
            .await;
            assert!(
                body.contains("started create filesystem tank/share"),
                "{body}"
            );

            // Mount / unmount route to the (fake) helper and report success.
            let (_, _, body) = send(
                &app,
                auth(form_post("/zfs/fs/mount", "dataset=tank%2Fshare")),
            )
            .await;
            assert!(body.contains("started mount tank/share"), "{body}");

            // A relative mountpoint is rejected before the helper.
            let (_, _, body) = send(
                &app,
                auth(form_post(
                    "/zfs/fs/set-mountpoint",
                    "dataset=tank%2Fshare&mountpoint=relative",
                )),
            )
            .await;
            assert!(body.contains("invalid mountpoint"), "{body}");

            // Destroy (recursive) succeeds through the fake helper.
            let (_, _, body) = send(
                &app,
                auth(form_post(
                    "/zfs/fs/destroy",
                    "dataset=tank%2Fshare&recursive=1",
                )),
            )
            .await;
            assert!(body.contains("started destroy tank/share"), "{body}");
        }

        #[tokio::test]
        async fn pool_create_form_and_validation() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // The dedicated form renders (whether or not ZFS is installed).
            let req = auth(
                HttpRequest::get("/zfs/pool/create?device=%2Fdev%2Fsdb")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("Create ZFS pool"), "{body}");

            // A reserved vdev keyword as the pool name is rejected.
            let req = auth(form_post(
                "/zfs/pool",
                "name=mirror&vdev=stripe&devices=%2Fdev%2Fsdb",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid pool name"), "{body}");

            // Too few devices for the chosen layout.
            let req = auth(form_post(
                "/zfs/pool",
                "name=tank&vdev=mirror&devices=%2Fdev%2Fsdb",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("at least 2 devices"), "{body}");

            // Valid mirror (two repeated devices= keys) → success redirect.
            let req = auth(form_post(
                "/zfs/pool",
                "name=tank&vdev=mirror&devices=%2Fdev%2Fsdb&devices=%2Fdev%2Fsdc",
            ));
            let (status, headers, _) = send(&app, req).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
            assert_eq!(headers[header::LOCATION], "/zfs");

            // Add-device: the pool name comes from the URL. A valid request
            // streams through the fake helper; a reserved vdev keyword is rejected.
            let req = auth(form_post(
                "/zfs/pool/tank/add-device",
                "device=%2Fdev%2Fsdb",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("started add /dev/sdb to tank"), "{body}");
            let req = auth(form_post(
                "/zfs/pool/mirror/add-device",
                "device=%2Fdev%2Fsdb",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid pool name"), "{body}");
        }

        #[tokio::test]
        async fn pool_device_remove_and_detach_flow() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // Remove takes vdev names and /dev paths; a bare vdev keyword is
            // rejected before the helper.
            let req = auth(form_post("/zfs/pool/tank/remove-device", "target=mirror-0"));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("started remove mirror-0 from tank"), "{body}");
            let req = auth(form_post(
                "/zfs/pool/tank/remove-device",
                "target=%2Fdev%2Fsdd",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("started remove /dev/sdd from tank"), "{body}");
            let req = auth(form_post("/zfs/pool/tank/remove-device", "target=mirror"));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid remove target"), "{body}");

            // Detach only takes leaf device paths — a container is rejected.
            let req = auth(form_post(
                "/zfs/pool/tank/detach-device",
                "device=%2Fdev%2Fsdc",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("started detach /dev/sdc from tank"), "{body}");
            let req = auth(form_post("/zfs/pool/tank/detach-device", "device=mirror-0"));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid device"), "{body}");
        }

        #[tokio::test]
        async fn dataset_page_renders() {
            let app = test_app();
            let (cookie, _) = login(&app).await;
            // Both the pool-root dataset and a nested dataset render the page.
            for path in ["/zfs/dataset/tank", "/zfs/dataset/tank/data"] {
                let req = HttpRequest::get(path)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap();
                let (status, _, body) = send(&app, req).await;
                assert_eq!(status, StatusCode::OK);
                // The dataset page shows the Zvols/Snapshots sections, or a
                // graceful empty state when ZFS is absent from the test host.
                assert!(
                    (body.contains("Zvols") && body.contains("Snapshots"))
                        || body.contains("ZFS is not installed")
                        || body.contains("not found"),
                    "{body}"
                );
            }
        }
    }
}
