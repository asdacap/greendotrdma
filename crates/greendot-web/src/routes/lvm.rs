//! LVM manager: volume groups, physical volumes, and logical volumes (linear +
//! thin). Mirrors the ZFS page; the one difference is that reads go through the
//! helper (LVM reporting needs root) via `actual::lvm`.

use super::{AppState, page};
use crate::actual::block;
use crate::actual::lvm::{self, LvKind};
use crate::auth::{CurrentUser, nav_redirect};
use crate::fmt::human_bytes;
use crate::routes::zfs::parse_size;
use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Router, routing::post};
use greendot_proto::{DevicePath, LvName, Request, VgName};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/lvm", axum::routing::get(lvm_page))
        .route("/lvm/lv", post(lv_create))
        .route("/lvm/lv/resize", post(lv_resize))
        .route("/lvm/lv/shrink", post(lv_shrink))
        .route("/lvm/lv/rename", post(lv_rename))
        .route("/lvm/lv/delete", post(lv_delete))
        .route("/lvm/thinpool", post(thin_pool_create))
        .route("/lvm/vg/extend", post(vg_extend))
        .route("/lvm/vg/reduce", post(vg_reduce))
        .route("/lvm/vg/delete", post(vg_remove))
        .route("/lvm/vg/create", axum::routing::get(vg_create_page))
        .route("/lvm/vg", post(vg_create))
}

pub struct VgRow {
    pub name: String,
    pub size: String,
    pub free: String,
    pub used_percent: u8,
    pub pv_count: u64,
    pub lv_count: u64,
}

pub struct PvRow {
    pub name: String,
    pub vg: String,
    pub size: String,
    pub free: String,
    /// True when the PV belongs to a VG (so it can be reduced out).
    pub in_vg: bool,
}

pub struct LvRow {
    pub vg: String,
    pub name: String,
    pub full_name: String,
    pub size: String,
    pub type_label: &'static str,
    pub pool: String,
    pub data_percent: String,
}

pub struct DeviceOption {
    pub path: String,
    pub label: String,
    pub checked: bool,
}

#[derive(Default)]
pub struct LvmView {
    pub vgs: Vec<VgRow>,
    pub pvs: Vec<PvRow>,
    pub lvs: Vec<LvRow>,
    pub vg_names: Vec<String>,
    /// `vg/pool` identifiers for the thin-volume form.
    pub thin_pools: Vec<String>,
    /// Empty raw devices offered for extending a VG.
    pub extend_devices: Vec<DeviceOption>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "lvm.html")]
struct LvmTemplate {
    user: CurrentUser,
    view: LvmView,
}

#[derive(Template)]
#[template(path = "_lvm.html")]
struct LvmPartial {
    view: LvmView,
}

fn used_percent(size: u64, free: u64) -> u8 {
    (size.saturating_sub(free).saturating_mul(100) / size.max(1)) as u8
}

async fn gather(state: &AppState, flash: Option<String>, form_error: Option<String>) -> LvmView {
    let mut view = LvmView {
        flash,
        form_error,
        ..Default::default()
    };
    let joined = tokio::try_join!(
        lvm::volume_groups(&state.helper),
        lvm::physical_volumes(&state.helper),
        lvm::logical_volumes(&state.helper),
    );
    let (Some(vgs), Some(pvs), Some(lvs)) = (match joined {
        Ok(t) => t,
        Err(e) => {
            view.error = Some(format!("could not read LVM state: {e:#}"));
            return view;
        }
    }) else {
        // Any of the three missing ⇒ LVM isn't installed on this host.
        view.not_installed = true;
        return view;
    };

    view.vg_names = vgs.iter().map(|v| v.name.clone()).collect();
    view.thin_pools = lvs
        .iter()
        .filter(|l| l.kind == LvKind::ThinPool)
        .map(|l| format!("{}/{}", l.vg, l.name))
        .collect();
    view.vgs = vgs
        .into_iter()
        .map(|v| VgRow {
            used_percent: used_percent(v.size, v.free),
            size: human_bytes(v.size),
            free: human_bytes(v.free),
            pv_count: v.pv_count,
            lv_count: v.lv_count,
            name: v.name,
        })
        .collect();
    view.pvs = pvs
        .into_iter()
        .map(|p| PvRow {
            in_vg: p.vg.is_some(),
            vg: p.vg.unwrap_or_else(|| "–".into()),
            size: human_bytes(p.size),
            free: human_bytes(p.free),
            name: p.name,
        })
        .collect();
    view.lvs = lvs
        .into_iter()
        .map(|l| LvRow {
            full_name: format!("{}/{}", l.vg, l.name),
            type_label: match l.kind {
                LvKind::Linear => "linear",
                LvKind::ThinPool => "thin pool",
                LvKind::Thin => "thin",
            },
            pool: l.pool.unwrap_or_default(),
            data_percent: l.data_percent.map_or(String::new(), |p| format!("{p:.1}%")),
            size: human_bytes(l.size),
            vg: l.vg,
            name: l.name,
        })
        .collect();

    let in_use: HashSet<String> = state
        .db
        .list_exports()
        .map(|es| es.into_iter().map(|e| e.device_path).collect())
        .unwrap_or_default();
    view.extend_devices = block::available_block_devices(&state.helper, &in_use)
        .await
        .into_iter()
        .filter(|d| {
            matches!(
                d.kind,
                block::AvailKind::WholeDisk | block::AvailKind::Partition
            ) && d.fstype.is_none()
        })
        .map(|d| DeviceOption {
            path: d.path,
            label: d.label,
            checked: false,
        })
        .collect();
    view
}

async fn lvm_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(LvmTemplate {
        user,
        view: gather(&state, None, None).await,
    })
}

/// Runs the request as a recorded task and re-renders the partial.
async fn run(state: &AppState, req: Request, kind: &str, title: &str, success: String) -> Response {
    let view = match crate::task_runner::run(state, req, kind, title).await {
        Ok(outcome) => {
            let (flash, error) = outcome.message(&success);
            gather(state, flash, error).await
        }
        Err(e) => gather(state, None, Some(format!("{e:#}"))).await,
    };
    page(LvmPartial { view })
}

async fn form_failed(state: &AppState, message: impl Into<String>) -> Response {
    page(LvmPartial {
        view: gather(state, None, Some(message.into())).await,
    })
}

// ---- Logical volumes ----

#[derive(Deserialize)]
struct LvCreateForm {
    vg: String,
    name: String,
    size: String,
    unit: String,
    #[serde(default)]
    thin: Option<String>,
    /// `vg/pool`, used only when `thin` is set.
    #[serde(default)]
    pool: String,
}

async fn lv_create(State(state): State<Arc<AppState>>, Form(form): Form<LvCreateForm>) -> Response {
    let Ok(name) = LvName::new(form.name.trim()) else {
        return form_failed(&state, format!("invalid LV name {:?}", form.name)).await;
    };
    let Some(size) = parse_size(&form.size, &form.unit) else {
        return form_failed(&state, "invalid size").await;
    };
    let (req, title, success) = if form.thin.is_some() {
        // Thin volume: the chosen pool (`vg/pool`) determines the VG.
        let Some((vg, pool)) = form.pool.split_once('/') else {
            return form_failed(&state, "choose a thin pool").await;
        };
        let (Ok(vg), Ok(pool)) = (VgName::new(vg), LvName::new(pool)) else {
            return form_failed(&state, "invalid thin pool").await;
        };
        (
            Request::ThinLvCreate {
                vg: vg.clone(),
                pool,
                name: name.clone(),
                virtual_size: size,
            },
            format!("create thin volume {vg}/{name}"),
            format!("created thin volume {vg}/{name}"),
        )
    } else {
        let Ok(vg) = VgName::new(form.vg.trim()) else {
            return form_failed(&state, "choose a volume group").await;
        };
        (
            Request::LvCreate {
                vg: vg.clone(),
                name: name.clone(),
                size,
            },
            format!("create LV {vg}/{name}"),
            format!("created LV {vg}/{name}"),
        )
    };
    run(&state, req, "lv-create", &title, success).await
}

#[derive(Deserialize)]
struct ThinPoolForm {
    vg: String,
    name: String,
    size: String,
    unit: String,
}

async fn thin_pool_create(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ThinPoolForm>,
) -> Response {
    let (Ok(vg), Ok(name)) = (VgName::new(form.vg.trim()), LvName::new(form.name.trim())) else {
        return form_failed(&state, "invalid thin pool name").await;
    };
    let Some(size) = parse_size(&form.size, &form.unit) else {
        return form_failed(&state, "invalid size").await;
    };
    let req = Request::ThinPoolCreate {
        vg: vg.clone(),
        name: name.clone(),
        size,
    };
    run(
        &state,
        req,
        "thin-pool-create",
        &format!("create thin pool {vg}/{name}"),
        format!("created thin pool {vg}/{name}"),
    )
    .await
}

#[derive(Deserialize)]
struct LvResizeForm {
    vg: String,
    name: String,
    size: String,
    unit: String,
}

/// Shared parse for resize/shrink, which take the same fields.
fn parse_lv_resize(form: &LvResizeForm) -> Result<(VgName, LvName, u64), &'static str> {
    let vg = VgName::new(form.vg.trim()).map_err(|_| "invalid volume group")?;
    let name = LvName::new(form.name.trim()).map_err(|_| "invalid logical volume")?;
    let size = parse_size(&form.size, &form.unit).ok_or("invalid size")?;
    Ok((vg, name, size))
}

async fn lv_resize(State(state): State<Arc<AppState>>, Form(form): Form<LvResizeForm>) -> Response {
    let (vg, name, new_size) = match parse_lv_resize(&form) {
        Ok(v) => v,
        Err(e) => return form_failed(&state, e).await,
    };
    let req = Request::LvResize {
        vg: vg.clone(),
        name: name.clone(),
        new_size,
    };
    run(
        &state,
        req,
        "lv-resize",
        &format!("grow {vg}/{name}"),
        format!("resized {vg}/{name}"),
    )
    .await
}

async fn lv_shrink(State(state): State<Arc<AppState>>, Form(form): Form<LvResizeForm>) -> Response {
    let (vg, name, new_size) = match parse_lv_resize(&form) {
        Ok(v) => v,
        Err(e) => return form_failed(&state, e).await,
    };
    let req = Request::LvShrink {
        vg: vg.clone(),
        name: name.clone(),
        new_size,
    };
    run(
        &state,
        req,
        "lv-shrink",
        &format!("shrink {vg}/{name}"),
        format!("shrank {vg}/{name}"),
    )
    .await
}

#[derive(Deserialize)]
struct LvRenameForm {
    vg: String,
    name: String,
    new_name: String,
}

async fn lv_rename(State(state): State<Arc<AppState>>, Form(form): Form<LvRenameForm>) -> Response {
    let (Ok(vg), Ok(name), Ok(new_name)) = (
        VgName::new(form.vg.trim()),
        LvName::new(form.name.trim()),
        LvName::new(form.new_name.trim()),
    ) else {
        return form_failed(&state, format!("invalid name {:?}", form.new_name)).await;
    };
    let req = Request::LvRename {
        vg: vg.clone(),
        name: name.clone(),
        new_name: new_name.clone(),
    };
    run(
        &state,
        req,
        "lv-rename",
        &format!("rename {vg}/{name} to {new_name}"),
        format!("renamed {vg}/{name} to {new_name}"),
    )
    .await
}

#[derive(Deserialize)]
struct LvDeleteForm {
    vg: String,
    name: String,
}

async fn lv_delete(State(state): State<Arc<AppState>>, Form(form): Form<LvDeleteForm>) -> Response {
    let (Ok(vg), Ok(name)) = (VgName::new(form.vg.trim()), LvName::new(form.name.trim())) else {
        return form_failed(&state, "invalid logical volume").await;
    };
    let req = Request::LvDelete {
        vg: vg.clone(),
        name: name.clone(),
    };
    run(
        &state,
        req,
        "lv-delete",
        &format!("delete {vg}/{name}"),
        format!("deleted {vg}/{name}"),
    )
    .await
}

// ---- Volume group: extend / reduce / remove ----

#[derive(Deserialize)]
struct VgDeviceForm {
    vg: String,
    device: String,
}

async fn vg_extend(State(state): State<Arc<AppState>>, Form(form): Form<VgDeviceForm>) -> Response {
    let (Ok(vg), Ok(device)) = (
        VgName::new(form.vg.trim()),
        DevicePath::new(form.device.trim()),
    ) else {
        return form_failed(&state, "invalid volume group or device").await;
    };
    let req = Request::VgExtend {
        vg: vg.clone(),
        device: device.clone(),
    };
    run(
        &state,
        req,
        "vg-extend",
        &format!("extend {vg} with {device}"),
        format!("added {device} to {vg}"),
    )
    .await
}

async fn vg_reduce(State(state): State<Arc<AppState>>, Form(form): Form<VgDeviceForm>) -> Response {
    let (Ok(vg), Ok(device)) = (
        VgName::new(form.vg.trim()),
        DevicePath::new(form.device.trim()),
    ) else {
        return form_failed(&state, "invalid volume group or device").await;
    };
    let req = Request::VgReduce {
        vg: vg.clone(),
        device: device.clone(),
    };
    run(
        &state,
        req,
        "vg-reduce",
        &format!("remove {device} from {vg}"),
        format!("removed {device} from {vg}"),
    )
    .await
}

#[derive(Deserialize)]
struct VgRemoveForm {
    vg: String,
}

async fn vg_remove(State(state): State<Arc<AppState>>, Form(form): Form<VgRemoveForm>) -> Response {
    let Ok(vg) = VgName::new(form.vg.trim()) else {
        return form_failed(&state, "invalid volume group").await;
    };
    let req = Request::VgRemove { vg: vg.clone() };
    run(
        &state,
        req,
        "vg-remove",
        &format!("remove volume group {vg}"),
        format!("removed volume group {vg}"),
    )
    .await
}

// ---- Dedicated VG creation form ----

#[derive(Default)]
pub struct VgCreateView {
    pub devices: Vec<DeviceOption>,
    pub not_installed: bool,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "vg_create.html")]
struct VgCreateTemplate {
    user: CurrentUser,
    view: VgCreateView,
}

#[derive(Template)]
#[template(path = "_vg_create.html")]
struct VgCreatePartial {
    view: VgCreateView,
}

/// Available devices for a new VG: empty raw disks/partitions (a PV must be an
/// unused block device — a device already a PV shows fstype `LVM2_member`).
async fn gather_vg_create(
    state: &AppState,
    selected: &HashSet<String>,
    error: Option<String>,
) -> VgCreateView {
    // Absent `vgs` ⇒ LVM not installed; an error still counts as installed.
    if matches!(lvm::volume_groups(&state.helper).await, Ok(None)) {
        return VgCreateView {
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
            matches!(
                d.kind,
                block::AvailKind::WholeDisk | block::AvailKind::Partition
            ) && d.fstype.is_none()
        })
        .map(|d| DeviceOption {
            checked: selected.contains(&d.path),
            path: d.path,
            label: d.label,
        })
        .collect();
    VgCreateView {
        devices,
        not_installed: false,
        error,
    }
}

async fn vg_create_failed(
    state: &AppState,
    selected: HashSet<String>,
    message: String,
) -> Response {
    page(VgCreatePartial {
        view: gather_vg_create(state, &selected, Some(message)).await,
    })
}

#[derive(Deserialize)]
struct VgCreateQuery {
    #[serde(default)]
    device: String,
}

async fn vg_create_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Query(q): Query<VgCreateQuery>,
) -> Response {
    let selected: HashSet<String> = if q.device.is_empty() {
        HashSet::new()
    } else {
        HashSet::from([q.device])
    };
    page(VgCreateTemplate {
        user,
        view: gather_vg_create(&state, &selected, None).await,
    })
}

async fn vg_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    // `devices` arrives as repeated keys, so read the raw pair list.
    let mut name = String::new();
    let mut selected: HashSet<String> = HashSet::new();
    let mut devices: Vec<String> = Vec::new();
    for (k, v) in fields {
        match k.as_str() {
            "name" => name = v,
            "devices" => {
                selected.insert(v.clone());
                devices.push(v);
            }
            _ => {}
        }
    }
    let Ok(vg) = VgName::new(name.trim()) else {
        return vg_create_failed(&state, selected, format!("invalid VG name {name:?}")).await;
    };
    let mut device_paths = Vec::new();
    for d in &devices {
        let Ok(dp) = DevicePath::new(d.trim()) else {
            return vg_create_failed(&state, selected, format!("invalid device {d:?}")).await;
        };
        device_paths.push(dp);
    }
    if device_paths.is_empty() {
        return vg_create_failed(&state, selected, "select at least one device".into()).await;
    }
    let title = format!("create volume group {vg}");
    let req = Request::VgCreate {
        name: vg,
        devices: device_paths,
    };
    match crate::task_runner::run(&state, req, "vg-create", &title).await {
        Ok(o) if o.ok => nav_redirect(&headers, "/lvm"),
        Ok(o) => {
            let msg = o.error.unwrap_or_else(|| "VG creation failed".into());
            vg_create_failed(&state, selected, msg).await
        }
        Err(e) => vg_create_failed(&state, selected, format!("{e:#}")).await,
    }
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    fn auth(cookie: &str, csrf: &str, mut req: HttpRequest<Body>) -> HttpRequest<Body> {
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        req.headers_mut()
            .insert("x-greendot-csrf", csrf.parse().unwrap());
        req
    }

    #[tokio::test]
    async fn page_and_lv_validation_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;

        // Page renders whether or not LVM is installed on the test host.
        let req = HttpRequest::get("/lvm")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Logical volumes") || body.contains("LVM is not installed"),
            "{body}"
        );

        // Valid linear LV create reaches the (fake) helper and reports success.
        let req = auth(
            &cookie,
            &csrf,
            form_post("/lvm/lv", "vg=vg0&name=data&size=10&unit=GiB"),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("created LV vg0/data"), "{body}");

        // Invalid LV name is rejected before the helper.
        let req = auth(
            &cookie,
            &csrf,
            form_post("/lvm/lv", "vg=vg0&name=..&size=10&unit=GiB"),
        );
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid LV name"), "{body}");

        // Thin volume needs a pool selection.
        let req = auth(
            &cookie,
            &csrf,
            form_post(
                "/lvm/lv",
                "vg=vg0&name=vm1&size=10&unit=GiB&thin=1&pool=vg0%2Fpool0",
            ),
        );
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("created thin volume vg0/vm1"), "{body}");
    }

    #[tokio::test]
    async fn vg_create_and_remove_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;

        // Dedicated VG form renders.
        let req = auth(
            &cookie,
            &csrf,
            HttpRequest::get("/lvm/vg/create?device=%2Fdev%2Fsdb")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Create volume group"), "{body}");

        // No devices selected is rejected.
        let req = auth(&cookie, &csrf, form_post("/lvm/vg", "name=vg0"));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("at least one device"), "{body}");

        // Valid VG create → redirect to /lvm.
        let req = auth(
            &cookie,
            &csrf,
            form_post(
                "/lvm/vg",
                "name=vg0&devices=%2Fdev%2Fsdb&devices=%2Fdev%2Fsdc",
            ),
        );
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/lvm");

        // Remove VG reaches the helper.
        let req = auth(&cookie, &csrf, form_post("/lvm/vg/delete", "vg=vg0"));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("removed volume group vg0"), "{body}");
    }
}
