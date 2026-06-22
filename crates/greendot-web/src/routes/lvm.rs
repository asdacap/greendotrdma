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
use axum::extract::{Form, Path, Query, State};
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
        .route("/lvm/vg/{name}", axum::routing::get(vg_detail_page))
        .route("/lvm/vg/{vg}/lv/{name}", axum::routing::get(lv_detail_page))
        .route("/lvm/pv/{*id}", axum::routing::get(pv_detail_page))
}

pub struct VgRow {
    pub name: String,
    pub size: String,
    pub free: String,
    pub used_percent: u8,
    pub pv_count: u64,
    pub lv_count: u64,
}

impl VgRow {
    fn new(v: lvm::Vg) -> Self {
        VgRow {
            used_percent: used_percent(v.size, v.free),
            size: human_bytes(v.size),
            free: human_bytes(v.free),
            pv_count: v.pv_count,
            lv_count: v.lv_count,
            name: v.name,
        }
    }
}

pub struct PvRow {
    pub name: String,
    /// `name` minus its leading `/`, so the device works as a URL path segment;
    /// the detail handler rebuilds it as `format!("/{id}")`.
    pub path_id: String,
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

impl LvRow {
    fn new(l: lvm::Lv) -> Self {
        LvRow {
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
        }
    }
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
    );
    let (Some(vgs), Some(pvs)) = (match joined {
        Ok(t) => t,
        Err(e) => {
            view.error = Some(format!("could not read LVM state: {e:#}"));
            return view;
        }
    }) else {
        // Either missing ⇒ LVM isn't installed on this host.
        view.not_installed = true;
        return view;
    };

    view.vgs = vgs.into_iter().map(VgRow::new).collect();
    view.pvs = pvs
        .into_iter()
        .map(|p| PvRow {
            in_vg: p.vg.is_some(),
            vg: p.vg.unwrap_or_else(|| "–".into()),
            size: human_bytes(p.size),
            free: human_bytes(p.free),
            path_id: p.name.trim_start_matches('/').to_owned(),
            name: p.name,
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

// ---- Per-VG page (logical-volume listing + creation) ----

#[derive(Default)]
pub struct VgDetailView {
    pub name: String,
    /// `None` when the named VG doesn't exist on this host.
    pub vg: Option<VgRow>,
    pub lvs: Vec<LvRow>,
    /// `vg/pool` identifiers for this VG's thin pools, for the thin-volume form.
    pub thin_pools: Vec<String>,
    /// Empty raw devices offered for extending this VG (the "Extend" form).
    pub extend_devices: Vec<DeviceOption>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "vg_detail.html")]
struct VgDetailTemplate {
    user: CurrentUser,
    view: VgDetailView,
}

#[derive(Template)]
#[template(path = "_vg_detail.html")]
struct VgDetailPartial {
    view: VgDetailView,
}

async fn gather_vg_detail(
    state: &AppState,
    name: &str,
    flash: Option<String>,
    form_error: Option<String>,
) -> VgDetailView {
    let mut view = VgDetailView {
        name: name.to_owned(),
        flash,
        form_error,
        ..Default::default()
    };
    let joined = tokio::try_join!(
        lvm::volume_groups(&state.helper),
        lvm::logical_volumes(&state.helper),
    );
    let (Some(vgs), Some(lvs)) = (match joined {
        Ok(t) => t,
        Err(e) => {
            view.error = Some(format!("could not read LVM state: {e:#}"));
            return view;
        }
    }) else {
        // Either missing ⇒ LVM isn't installed on this host.
        view.not_installed = true;
        return view;
    };
    view.vg = vgs.into_iter().find(|v| v.name == name).map(VgRow::new);
    // A device added to the VG must be an empty raw device, so offer the same
    // candidates as VG creation (no formatted partitions or existing PVs).
    if view.vg.is_some() {
        let in_use: HashSet<String> = state.db.export_device_paths().into_iter().collect();
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
    }
    view.thin_pools = lvs
        .iter()
        .filter(|l| l.vg == name && l.kind == LvKind::ThinPool)
        .map(|l| format!("{}/{}", l.vg, l.name))
        .collect();
    view.lvs = lvs
        .into_iter()
        .filter(|l| l.vg == name)
        .map(LvRow::new)
        .collect();
    view
}

async fn vg_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(name): Path<String>,
) -> Response {
    page(VgDetailTemplate {
        user,
        view: gather_vg_detail(&state, &name, None, None).await,
    })
}

/// Runs an LV request as a recorded task and re-renders the owning VG's detail
/// partial with the outcome.
async fn run_lv(
    state: &AppState,
    req: Request,
    kind: &str,
    title: &str,
    success: String,
    vg: &str,
) -> Response {
    let view = match crate::task_runner::run(state, req, kind, title).await {
        Ok(outcome) => {
            let (flash, error) = outcome.message(&success);
            gather_vg_detail(state, vg, flash, error).await
        }
        Err(e) => gather_vg_detail(state, vg, None, Some(format!("{e:#}"))).await,
    };
    page(VgDetailPartial { view })
}

async fn lv_failed(state: &AppState, vg: &str, message: impl Into<String>) -> Response {
    page(VgDetailPartial {
        view: gather_vg_detail(state, vg, None, Some(message.into())).await,
    })
}

// ---- Per-LV page (grow / shrink / rename / delete) ----

#[derive(Default)]
pub struct LvDetailView {
    pub vg: String,
    pub name: String,
    /// `None` when the named LV doesn't exist in this VG on this host.
    pub lv: Option<LvRow>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "lv_detail.html")]
struct LvDetailTemplate {
    user: CurrentUser,
    view: LvDetailView,
}

#[derive(Template)]
#[template(path = "_lv_detail.html")]
struct LvDetailPartial {
    view: LvDetailView,
}

async fn gather_lv_detail(
    state: &AppState,
    vg: &str,
    name: &str,
    flash: Option<String>,
    form_error: Option<String>,
) -> LvDetailView {
    let mut view = LvDetailView {
        vg: vg.to_owned(),
        name: name.to_owned(),
        flash,
        form_error,
        ..Default::default()
    };
    match lvm::logical_volumes(&state.helper).await {
        Ok(Some(lvs)) => {
            view.lv = lvs
                .into_iter()
                .find(|l| l.vg == vg && l.name == name)
                .map(LvRow::new);
        }
        // Absent ⇒ LVM isn't installed on this host.
        Ok(None) => view.not_installed = true,
        Err(e) => view.error = Some(format!("could not read LVM state: {e:#}")),
    }
    view
}

async fn lv_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path((vg, name)): Path<(String, String)>,
) -> Response {
    page(LvDetailTemplate {
        user,
        view: gather_lv_detail(&state, &vg, &name, None, None).await,
    })
}

/// Runs an LV request as a recorded task and re-renders the owning LV's detail
/// partial with the outcome (stay-on-page ops: grow / shrink / rename).
async fn run_lv_detail(
    state: &AppState,
    req: Request,
    kind: &str,
    title: &str,
    success: String,
    vg: &str,
    name: &str,
) -> Response {
    let view = match crate::task_runner::run(state, req, kind, title).await {
        Ok(outcome) => {
            let (flash, error) = outcome.message(&success);
            gather_lv_detail(state, vg, name, flash, error).await
        }
        Err(e) => gather_lv_detail(state, vg, name, None, Some(format!("{e:#}"))).await,
    };
    page(LvDetailPartial { view })
}

async fn lv_detail_failed(
    state: &AppState,
    vg: &str,
    name: &str,
    message: impl Into<String>,
) -> Response {
    page(LvDetailPartial {
        view: gather_lv_detail(state, vg, name, None, Some(message.into())).await,
    })
}

// ---- Per-PV page (remove from VG) ----

#[derive(Default)]
pub struct PvDetailView {
    /// `None` when the named PV doesn't exist on this host.
    pub pv: Option<PvRow>,
    pub not_installed: bool,
    pub error: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "pv_detail.html")]
struct PvDetailTemplate {
    user: CurrentUser,
    view: PvDetailView,
}

#[derive(Template)]
#[template(path = "_pv_detail.html")]
struct PvDetailPartial {
    view: PvDetailView,
}

async fn gather_pv_detail(
    state: &AppState,
    device: &str,
    flash: Option<String>,
    form_error: Option<String>,
) -> PvDetailView {
    let mut view = PvDetailView {
        flash,
        form_error,
        ..Default::default()
    };
    match lvm::physical_volumes(&state.helper).await {
        Ok(Some(pvs)) => {
            view.pv = pvs.into_iter().find(|p| p.name == device).map(|p| PvRow {
                in_vg: p.vg.is_some(),
                vg: p.vg.unwrap_or_else(|| "–".into()),
                size: human_bytes(p.size),
                free: human_bytes(p.free),
                path_id: p.name.trim_start_matches('/').to_owned(),
                name: p.name,
            });
        }
        // Absent ⇒ LVM isn't installed on this host.
        Ok(None) => view.not_installed = true,
        Err(e) => view.error = Some(format!("could not read LVM state: {e:#}")),
    }
    view
}

async fn pv_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Response {
    // The wildcard segment drops the device's leading `/`; rebuild it.
    let device = format!("/{id}");
    page(PvDetailTemplate {
        user,
        view: gather_pv_detail(&state, &device, None, None).await,
    })
}

async fn pv_detail_failed(state: &AppState, device: &str, message: impl Into<String>) -> Response {
    page(PvDetailPartial {
        view: gather_pv_detail(state, device, None, Some(message.into())).await,
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
    // The detail page the form lives on; failures re-render this VG.
    let scope = form.vg.trim().to_owned();
    let Ok(name) = LvName::new(form.name.trim()) else {
        return lv_failed(&state, &scope, format!("invalid LV name {:?}", form.name)).await;
    };
    let Some(size) = parse_size(&form.size, &form.unit) else {
        return lv_failed(&state, &scope, "invalid size").await;
    };
    let (req, title, success) = if form.thin.is_some() {
        // Thin volume: the chosen pool (`vg/pool`) determines the VG.
        let Some((vg, pool)) = form.pool.split_once('/') else {
            return lv_failed(&state, &scope, "choose a thin pool").await;
        };
        let (Ok(vg), Ok(pool)) = (VgName::new(vg), LvName::new(pool)) else {
            return lv_failed(&state, &scope, "invalid thin pool").await;
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
            return lv_failed(&state, &scope, "choose a volume group").await;
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
    run_lv(&state, req, "lv-create", &title, success, &scope).await
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
    let scope = form.vg.trim().to_owned();
    let (Ok(vg), Ok(name)) = (VgName::new(form.vg.trim()), LvName::new(form.name.trim())) else {
        return lv_failed(&state, &scope, "invalid thin pool name").await;
    };
    let Some(size) = parse_size(&form.size, &form.unit) else {
        return lv_failed(&state, &scope, "invalid size").await;
    };
    let req = Request::ThinPoolCreate {
        vg: vg.clone(),
        name: name.clone(),
        size,
    };
    run_lv(
        &state,
        req,
        "thin-pool-create",
        &format!("create thin pool {vg}/{name}"),
        format!("created thin pool {vg}/{name}"),
        &scope,
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
    // The LV's detail page hosts this form; stay on it after running.
    let (scope_vg, scope_name) = (form.vg.trim().to_owned(), form.name.trim().to_owned());
    let (vg, name, new_size) = match parse_lv_resize(&form) {
        Ok(v) => v,
        Err(e) => return lv_detail_failed(&state, &scope_vg, &scope_name, e).await,
    };
    let req = Request::LvResize {
        vg: vg.clone(),
        name: name.clone(),
        new_size,
    };
    run_lv_detail(
        &state,
        req,
        "lv-resize",
        &format!("grow {vg}/{name}"),
        format!("resized {vg}/{name}"),
        &scope_vg,
        &scope_name,
    )
    .await
}

async fn lv_shrink(State(state): State<Arc<AppState>>, Form(form): Form<LvResizeForm>) -> Response {
    let (scope_vg, scope_name) = (form.vg.trim().to_owned(), form.name.trim().to_owned());
    let (vg, name, new_size) = match parse_lv_resize(&form) {
        Ok(v) => v,
        Err(e) => return lv_detail_failed(&state, &scope_vg, &scope_name, e).await,
    };
    let req = Request::LvShrink {
        vg: vg.clone(),
        name: name.clone(),
        new_size,
    };
    run_lv_detail(
        &state,
        req,
        "lv-shrink",
        &format!("shrink {vg}/{name}"),
        format!("shrank {vg}/{name}"),
        &scope_vg,
        &scope_name,
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
    let (scope_vg, scope_name) = (form.vg.trim().to_owned(), form.name.trim().to_owned());
    let (Ok(vg), Ok(name), Ok(new_name)) = (
        VgName::new(form.vg.trim()),
        LvName::new(form.name.trim()),
        LvName::new(form.new_name.trim()),
    ) else {
        return lv_detail_failed(
            &state,
            &scope_vg,
            &scope_name,
            format!("invalid name {:?}", form.new_name),
        )
        .await;
    };
    let req = Request::LvRename {
        vg: vg.clone(),
        name: name.clone(),
        new_name: new_name.clone(),
    };
    // The LV now lives under `new_name`, so re-gather (and stay) on that name.
    run_lv_detail(
        &state,
        req,
        "lv-rename",
        &format!("rename {vg}/{name} to {new_name}"),
        format!("renamed {vg}/{name} to {new_name}"),
        &scope_vg,
        new_name.as_str(),
    )
    .await
}

#[derive(Deserialize)]
struct LvDeleteForm {
    vg: String,
    name: String,
}

async fn lv_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LvDeleteForm>,
) -> Response {
    // Removing the LV leaves its page nonexistent, so on success go back to the
    // owning VG; on failure the LV still exists, so re-render its detail.
    let (scope_vg, scope_name) = (form.vg.trim().to_owned(), form.name.trim().to_owned());
    let (Ok(vg), Ok(name)) = (VgName::new(form.vg.trim()), LvName::new(form.name.trim())) else {
        return lv_detail_failed(&state, &scope_vg, &scope_name, "invalid logical volume").await;
    };
    let title = format!("delete {vg}/{name}");
    let req = Request::LvDelete {
        vg: vg.clone(),
        name: name.clone(),
    };
    match crate::task_runner::run(&state, req, "lv-delete", &title).await {
        Ok(o) if o.ok => nav_redirect(&headers, &format!("/lvm/vg/{scope_vg}")),
        Ok(o) => {
            let msg = o.error.unwrap_or_else(|| "delete failed".into());
            lv_detail_failed(&state, &scope_vg, &scope_name, msg).await
        }
        Err(e) => lv_detail_failed(&state, &scope_vg, &scope_name, format!("{e:#}")).await,
    }
}

// ---- Volume group: extend / reduce / remove ----

#[derive(Deserialize)]
struct VgDeviceForm {
    vg: String,
    device: String,
}

/// Extend lives on the VG's detail page (a section-level action there), so it
/// stays on that page after running.
async fn vg_extend(State(state): State<Arc<AppState>>, Form(form): Form<VgDeviceForm>) -> Response {
    let scope = form.vg.trim().to_owned();
    let (Ok(vg), Ok(device)) = (
        VgName::new(form.vg.trim()),
        DevicePath::new(form.device.trim()),
    ) else {
        return lv_failed(&state, &scope, "invalid volume group or device").await;
    };
    let req = Request::VgExtend {
        vg: vg.clone(),
        device: device.clone(),
    };
    run_lv(
        &state,
        req,
        "vg-extend",
        &format!("extend {vg} with {device}"),
        format!("added {device} to {vg}"),
        &scope,
    )
    .await
}

/// Remove-from-VG lives on the PV's detail page; on success the PV is no longer
/// in a VG so go back to the LVM index, otherwise re-render the PV's detail.
async fn vg_reduce(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<VgDeviceForm>,
) -> Response {
    let device_scope = form.device.trim().to_owned();
    let (Ok(vg), Ok(device)) = (
        VgName::new(form.vg.trim()),
        DevicePath::new(form.device.trim()),
    ) else {
        return pv_detail_failed(&state, &device_scope, "invalid volume group or device").await;
    };
    let title = format!("remove {device} from {vg}");
    let req = Request::VgReduce {
        vg: vg.clone(),
        device: device.clone(),
    };
    match crate::task_runner::run(&state, req, "vg-reduce", &title).await {
        Ok(o) if o.ok => nav_redirect(&headers, "/lvm"),
        Ok(o) => {
            let msg = o.error.unwrap_or_else(|| "remove from VG failed".into());
            pv_detail_failed(&state, &device_scope, msg).await
        }
        Err(e) => pv_detail_failed(&state, &device_scope, format!("{e:#}")).await,
    }
}

#[derive(Deserialize)]
struct VgRemoveForm {
    vg: String,
}

/// Remove-VG lives on the VG's detail page; on success that page no longer
/// applies so go back to the LVM index, otherwise re-render the VG's detail.
async fn vg_remove(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<VgRemoveForm>,
) -> Response {
    let scope = form.vg.trim().to_owned();
    let Ok(vg) = VgName::new(form.vg.trim()) else {
        return lv_failed(&state, &scope, "invalid volume group").await;
    };
    let title = format!("remove volume group {vg}");
    let req = Request::VgRemove { vg: vg.clone() };
    match crate::task_runner::run(&state, req, "vg-remove", &title).await {
        Ok(o) if o.ok => nav_redirect(&headers, "/lvm"),
        Ok(o) => {
            let msg = o.error.unwrap_or_else(|| "VG removal failed".into());
            lv_failed(&state, &scope, msg).await
        }
        Err(e) => lv_failed(&state, &scope, format!("{e:#}")).await,
    }
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
    let in_use: HashSet<String> = state.db.export_device_paths().into_iter().collect();
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

        // The index lists volume groups, each linking to its own page; the LV
        // listing and create forms now live on that per-VG page instead.
        let req = HttpRequest::get("/lvm")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Volume groups"), "{body}");
        assert!(body.contains("/lvm/vg/vg0"), "{body}");

        // The per-VG page hosts the LV listing, both create forms, and the VG's
        // own Extend/Remove actions. The fake helper reports vg0 with a linear
        // LV `data` and a thin pool `pool0`; each LV row links to its own page.
        let req = HttpRequest::get("/lvm/vg/vg0")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Logical volumes") && body.contains("/lvm/vg/vg0/lv/data"),
            "{body}"
        );
        assert!(
            body.contains("Create logical volume") && body.contains("Create thin pool"),
            "{body}"
        );
        // The VG's own Extend/Remove actions moved onto this page. The Extend
        // form only renders when free devices exist (the fake helper reports
        // none), so assert on the always-present Extend heading and Remove VG.
        assert!(
            body.contains("<h2>Extend</h2>") && body.contains("Remove VG"),
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

        // Remove VG is a remove-op: success redirects back to the LVM index.
        let req = auth(&cookie, &csrf, form_post("/lvm/vg/delete", "vg=vg0"));
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/lvm");
    }

    #[tokio::test]
    async fn lv_detail_stay_and_delete_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;

        // The LV's own page renders with its grow/shrink/rename/delete forms; an
        // unknown LV renders gracefully (200 + not-found), never a 500.
        let req = HttpRequest::get("/lvm/vg/vg0/lv/data")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Grow") && body.contains("Delete"), "{body}");

        let req = HttpRequest::get("/lvm/vg/vg0/lv/missing")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("not found"), "{body}");

        // Resize is a stay-op: it re-renders the LV's detail partial.
        let req = auth(
            &cookie,
            &csrf,
            form_post("/lvm/lv/resize", "vg=vg0&name=data&size=20&unit=GiB"),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("resized vg0/data") && body.contains(r#"id="lv-detail-content""#),
            "{body}"
        );

        // Delete is a remove-op: success redirects to the owning VG's page.
        let req = auth(
            &cookie,
            &csrf,
            form_post("/lvm/lv/delete", "vg=vg0&name=data"),
        );
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/lvm/vg/vg0");
    }

    #[tokio::test]
    async fn pv_detail_and_vg_extend_reduce_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;

        // The PV page renders its Remove-from-VG action; an unknown PV is a
        // graceful not-found, not a 500. The fake helper reports /dev/sdb in vg0.
        let req = HttpRequest::get("/lvm/pv/dev/sdb")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("Remove from VG") && body.contains("/dev/sdb"),
            "{body}"
        );

        let req = HttpRequest::get("/lvm/pv/dev/nope")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("not found"), "{body}");

        // VG extend is a stay-op on the VG page: it re-renders that detail.
        let req = auth(
            &cookie,
            &csrf,
            form_post("/lvm/vg/extend", "vg=vg0&device=%2Fdev%2Fsdc"),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("added /dev/sdc to vg0"), "{body}");

        // Remove-from-VG is a remove-op: success redirects to the LVM index.
        let req = auth(
            &cookie,
            &csrf,
            form_post("/lvm/vg/reduce", "vg=vg0&device=%2Fdev%2Fsdb"),
        );
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/lvm");
    }
}
