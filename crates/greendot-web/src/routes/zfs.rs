use super::{AppState, page};
use crate::actual::block;
use crate::actual::zfs::{self, DsKind};
use crate::auth::{CurrentUser, nav_redirect};
use crate::fmt::human_bytes;
use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Router, routing::post};
use greendot_proto::{DatasetName, DevicePath, PoolName, Request, VdevLayout};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/zfs", axum::routing::get(zfs_page))
        .route("/zfs/zvol", post(zvol_create))
        .route("/zfs/zvol/resize", post(zvol_resize))
        .route("/zfs/zvol/delete", post(zvol_delete))
        .route("/zfs/pool/create", axum::routing::get(pool_create_page))
        .route("/zfs/pool", post(pool_create))
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

pub struct DatasetRow {
    pub name: String,
    pub indent_px: usize,
    pub kind_label: &'static str,
    pub used: String,
    pub avail: String,
    pub volsize: String,
    pub is_volume: bool,
}

#[derive(Default)]
pub struct ZfsView {
    pub pools: Vec<PoolRow>,
    pub datasets: Vec<DatasetRow>,
    pub parents: Vec<String>,
    /// True when the `zpool`/`zfs` binaries are absent on this host.
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "zfs.html")]
struct ZfsTemplate {
    user: CurrentUser,
    view: ZfsView,
}

#[derive(Template)]
#[template(path = "_zfs.html")]
struct ZfsPartial {
    view: ZfsView,
}

async fn gather(flash: Option<String>, form_error: Option<String>) -> ZfsView {
    let mut view = ZfsView {
        flash,
        form_error,
        ..Default::default()
    };
    match tokio::try_join!(zfs::pools(), zfs::datasets()) {
        Ok((Some(pools), Some(datasets))) => {
            view.pools = pools
                .into_iter()
                .map(|p| PoolRow {
                    used_percent: (p.alloc.saturating_mul(100) / p.size.max(1)) as u8,
                    size: human_bytes(p.size),
                    free: human_bytes(p.free),
                    frag: p.frag_percent.map_or("–".into(), |f| format!("{f}%")),
                    healthy: p.health == "ONLINE",
                    health: p.health,
                    name: p.name,
                })
                .collect();
            view.parents = datasets
                .iter()
                .filter(|d| d.kind == DsKind::Filesystem)
                .map(|d| d.name.clone())
                .collect();
            view.datasets = datasets
                .into_iter()
                .map(|d| DatasetRow {
                    indent_px: d.name.matches('/').count() * 18,
                    kind_label: match d.kind {
                        DsKind::Filesystem => "filesystem",
                        DsKind::Volume => "zvol",
                    },
                    used: human_bytes(d.used),
                    avail: human_bytes(d.avail),
                    volsize: d.volsize.map_or(String::new(), human_bytes),
                    is_volume: d.kind == DsKind::Volume,
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

async fn zfs_page(
    State(_): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(ZfsTemplate {
        user,
        view: gather(None, None).await,
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

/// Runs the request as a recorded task and renders the partial with its
/// outcome.
async fn run(state: &AppState, req: Request, kind: &str, title: &str, success: String) -> Response {
    let view = match crate::task_runner::run(state, req, kind, title).await {
        Ok(outcome) => {
            let (flash, error) = outcome.message(&success);
            gather(flash, error).await
        }
        Err(e) => gather(None, Some(format!("{e:#}"))).await,
    };
    page(ZfsPartial { view })
}

async fn form_failed(message: impl Into<String>) -> Response {
    page(ZfsPartial {
        view: gather(None, Some(message.into())).await,
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
    let Ok(dataset) = DatasetName::new(format!("{}/{}", form.parent, form.name.trim())) else {
        return form_failed(format!("invalid zvol name {:?}", form.name)).await;
    };
    let Some(size) = parse_size(&form.size, &form.unit) else {
        return form_failed("invalid size").await;
    };
    let volblocksize = match form.volblocksize.as_str() {
        "" => None,
        v => match v.parse() {
            Ok(v) => Some(v),
            Err(_) => return form_failed("invalid volblocksize").await,
        },
    };
    let req = Request::ZvolCreate {
        dataset: dataset.clone(),
        size,
        volblocksize,
        sparse: form.sparse.is_some(),
    };
    run(
        &state,
        req,
        "zvol-create",
        &format!("create zvol {dataset}"),
        format!("created zvol {dataset}"),
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
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return form_failed("invalid dataset name").await;
    };
    let Some(new_size) = parse_size(&form.size, &form.unit) else {
        return form_failed("invalid size").await;
    };
    let req = Request::ZvolResize {
        dataset: dataset.clone(),
        new_size,
    };
    run(
        &state,
        req,
        "zvol-resize",
        &format!("resize {dataset}"),
        format!("resized {dataset}"),
    )
    .await
}

#[derive(Deserialize)]
struct DeleteForm {
    dataset: String,
}

async fn zvol_delete(State(state): State<Arc<AppState>>, Form(form): Form<DeleteForm>) -> Response {
    let Ok(dataset) = DatasetName::new(form.dataset) else {
        return form_failed("invalid dataset name").await;
    };
    let req = Request::ZvolDelete {
        dataset: dataset.clone(),
    };
    run(
        &state,
        req,
        "zvol-delete",
        &format!("delete {dataset}"),
        format!("deleted {dataset}"),
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
    let devices = block::available_block_devices(&in_use)
        .await
        .into_iter()
        .filter(|d| d.kind != block::AvailKind::Zvol && d.fstype.is_none())
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

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::http::{Request as HttpRequest, StatusCode, header};

        #[tokio::test]
        async fn page_create_and_validation_flow() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;

            // Page renders. ZFS may be unavailable on the test host, in which
            // case the create form is replaced by a "not installed" notice —
            // either is a successful render, not a failure.
            let req = HttpRequest::get("/zfs")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("Create zvol") || body.contains("ZFS is not installed"),
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
        }
    }
}
