use super::{AppState, page};
use crate::actual::block;
use crate::actual::zfs::{self, DsKind};
use crate::auth::{CurrentUser, nav_redirect};
use crate::fmt::human_bytes;
use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Router, routing::post};
use greendot_proto::{DatasetName, DevicePath, MountPoint, PoolName, Request, VdevLayout};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/zfs", axum::routing::get(zfs_page))
        .route("/zfs/pool/create", axum::routing::get(pool_create_page))
        .route("/zfs/pool", post(pool_create))
        .route("/zfs/pool/{name}", axum::routing::get(pool_detail_page))
        .route("/zfs/pool/{name}/add-device", post(pool_add_device))
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

#[derive(Default)]
pub struct PoolDetailView {
    pub name: String,
    /// `None` when the named pool doesn't exist on this host.
    pub pool: Option<PoolRow>,
    pub zvols: Vec<ZvolRow>,
    /// Child filesystem datasets in this pool (mount/unmount/destroy targets).
    pub fs_rows: Vec<FsRow>,
    /// Filesystems in this pool, offered as zvol/filesystem parents.
    pub parents: Vec<String>,
    /// Empty raw devices offered to expand this pool (the "Add device" form).
    pub add_devices: Vec<PoolDeviceOption>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
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
) -> PoolDetailView {
    let mut view = PoolDetailView {
        name: name.to_owned(),
        flash,
        form_error,
        ..Default::default()
    };
    match tokio::try_join!(zfs::pools(), zfs::datasets()) {
        Ok((Some(pools), Some(datasets))) => {
            view.pool = pools.into_iter().find(|p| p.name == name).map(PoolRow::new);
            // A vdev added to the pool must be an empty raw device, so offer the
            // same candidates as pool creation (no zvols, LVs, or formatted parts).
            if view.pool.is_some() {
                view.add_devices = gather_pool_create(state, &HashSet::new(), None)
                    .await
                    .devices;
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
            view.zvols = datasets
                .into_iter()
                .filter(|d| d.kind == DsKind::Volume && d.name.starts_with(&prefix))
                .map(|d| ZvolRow {
                    used: human_bytes(d.used),
                    volsize: d.volsize.map_or(String::new(), human_bytes),
                    name: d.name,
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
        view: gather_pool_detail(&state, &name, None, None).await,
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
    state: &AppState,
    req: Request,
    kind: &str,
    title: &str,
    success: String,
    pool: &str,
) -> Response {
    let view = match crate::task_runner::run(state, req, kind, title).await {
        Ok(outcome) => {
            let (flash, error) = outcome.message(&success);
            gather_pool_detail(state, pool, flash, error).await
        }
        Err(e) => gather_pool_detail(state, pool, None, Some(format!("{e:#}"))).await,
    };
    page(PoolDetailPartial { view })
}

async fn pool_op_failed(state: &AppState, pool: &str, message: impl Into<String>) -> Response {
    page(PoolDetailPartial {
        view: gather_pool_detail(state, pool, None, Some(message.into())).await,
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
    let req = Request::ZvolCreate {
        dataset: dataset.clone(),
        size,
        volblocksize,
        sparse: form.sparse.is_some(),
    };
    run_pool_op(
        &state,
        req,
        "zvol-create",
        &format!("create zvol {dataset}"),
        format!("created zvol {dataset}"),
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
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return pool_op_failed(&state, &pool, "invalid dataset name").await;
    };
    let Some(new_size) = parse_size(&form.size, &form.unit) else {
        return pool_op_failed(&state, &pool, "invalid size").await;
    };
    let req = Request::ZvolResize {
        dataset: dataset.clone(),
        new_size,
    };
    run_pool_op(
        &state,
        req,
        "zvol-resize",
        &format!("resize {dataset}"),
        format!("resized {dataset}"),
        &pool,
    )
    .await
}

#[derive(Deserialize)]
struct DeleteForm {
    dataset: String,
}

async fn zvol_delete(State(state): State<Arc<AppState>>, Form(form): Form<DeleteForm>) -> Response {
    let pool = pool_of(&form.dataset).to_owned();
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return pool_op_failed(&state, &pool, "invalid dataset name").await;
    };
    let req = Request::ZvolDelete {
        dataset: dataset.clone(),
    };
    run_pool_op(
        &state,
        req,
        "zvol-delete",
        &format!("delete {dataset}"),
        format!("deleted {dataset}"),
        &pool,
    )
    .await
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
    let req = Request::ZfsFsCreate {
        dataset: dataset.clone(),
        mountpoint,
    };
    run_pool_op(
        &state,
        req,
        "fs-create",
        &format!("create filesystem {dataset}"),
        format!("created filesystem {dataset}"),
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
        Request::ZfsMount {
            dataset: dataset.clone(),
        },
        "fs-mount",
        &format!("mount {dataset}"),
        format!("mounted {dataset}"),
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
        Request::ZfsUnmount {
            dataset: dataset.clone(),
        },
        "fs-unmount",
        &format!("unmount {dataset}"),
        format!("unmounted {dataset}"),
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
        Request::ZfsSetMountpoint {
            dataset: dataset.clone(),
            mountpoint: mountpoint.clone(),
        },
        "fs-set-mountpoint",
        &format!("set {dataset} mountpoint={mountpoint}"),
        format!("set {dataset} mountpoint to {mountpoint}"),
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
    let req = Request::ZfsDestroy {
        dataset: dataset.clone(),
        recursive: form.recursive.is_some(),
    };
    run_pool_op(
        &state,
        req,
        "fs-destroy",
        &format!("destroy {dataset}"),
        format!("destroyed {dataset}"),
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
    let req = Request::PoolDeviceAdd {
        pool: pool.clone(),
        device: device.clone(),
    };
    run_pool_op(
        &state,
        req,
        "pool-add",
        &format!("add {device} to {pool}"),
        format!("added {device} to pool {pool}"),
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
    let in_use: HashSet<String> = state
        .db
        .list_exports()
        .map(|es| es.into_iter().map(|e| e.device_path).collect())
        .unwrap_or_default();
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
    let req = Request::PoolCreate {
        name: pool,
        vdev: layout,
        devices: device_paths,
        ashift,
    };
    match crate::task_runner::run(&state, req, "pool-create", &title).await {
        Ok(o) if o.ok => nav_redirect(&headers, "/zfs"),
        Ok(o) => {
            let msg = o.error.unwrap_or_else(|| "pool creation failed".into());
            pool_create_failed(&state, selected, msg).await
        }
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
            assert!(body.contains("created zvol tank/vm1"), "{body}");

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
            assert!(body.contains("created filesystem tank/share"), "{body}");

            // Mount / unmount route to the (fake) helper and report success.
            let (_, _, body) = send(
                &app,
                auth(form_post("/zfs/fs/mount", "dataset=tank%2Fshare")),
            )
            .await;
            assert!(body.contains("mounted tank/share"), "{body}");

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
            assert!(body.contains("destroyed tank/share"), "{body}");
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
            assert!(body.contains("added /dev/sdb to pool tank"), "{body}");
            let req = auth(form_post(
                "/zfs/pool/mirror/add-device",
                "device=%2Fdev%2Fsdb",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid pool name"), "{body}");
        }
    }
}
