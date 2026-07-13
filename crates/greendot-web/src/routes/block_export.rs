//! Shared machinery for the two block-device export concepts (NVMe-oF and
//! iSCSI). The protocols are first-class concepts with their own pages, structs
//! and tables (see [`super::nvme`] / [`super::iscsi`]); only the genuinely
//! protocol-agnostic pieces live here: the cross-protocol reconcile pass, the
//! row/command view types both pages render, and the shared Diagnose page.

use super::{AppState, page};
use crate::actual;
use crate::auth::{CurrentUser, nav_redirect};
use crate::dot::Criterion;
use crate::dot::DotState;
use crate::state::{Db, IscsiExport, NfsExport, NvmeExport};
use crate::task_runner::TaskOutcome;
use askama::Template;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use greendot_proto::{DevicePath, ExportName};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Web SQLite setting holding the last reconcile pass's error text (empty when
/// it succeeded), surfaced as the export banner and folded into the dots.
pub const RECONCILE_ERROR_KEY: &str = "reconcile_error";

/// Web SQLite setting holding the id of the most recent reconcile task, so the
/// export banner and dots can link to it (`/tasks/{id}`). Empty when none has
/// run.
pub const RECONCILE_TASK_KEY: &str = "reconcile_task_id";

/// Serialized full reconcile against current desired state. A daemon-side drift
/// pre-check keeps the steady state (and the 60 s timer) silent; on drift
/// it asks the daemon to reconcile inline (the `Reconcile` rpc, streamed back
/// as a recorded task) and returns the task id *without waiting* — the outcome
/// is surfaced on the export dots and the settings banner once it finishes (in
/// the background). The web stays the sole writer of the desired state — the
/// daemon's reconcile only reads it.
///
/// Returns `Some(task_id)` when a reconcile was dispatched (so the caller can
/// link its notice/banner to `/tasks/{id}`), or `None` when already realized.
pub async fn reconcile_state(state: &Arc<AppState>) -> anyhow::Result<Option<i64>> {
    // Owned so it can move into the spawn: held continuously through the drift
    // pre-check and the background reconcile run, so passes never overlap.
    let guard = state.reconcile_lock.clone().lock_owned().await;
    let nvme_exports = state.db.list_nvme_exports()?;
    let iscsi_exports = state.db.list_iscsi_exports()?;
    let nfs_exports = state.db.list_nfs_exports()?;

    // The daemon renders its own desired state, reads actual configfs/sysfs, and
    // diffs it in one privileged pass — the web does no hardware read. A
    // transport failure deserializes to "all drifted", so we still reconcile.
    let drift = state.helper.reconcile_dry_run().await;
    if drift.nvmet_ok && drift.lio_ok && drift.nfs_ok && drift.nic_ok {
        return Ok(None); // already realized — emit no task
    }

    // Record the task up front and publish its id, so the banner and the drifted
    // exports' dots can link to it while it runs; drive it to completion — and
    // apply the outcome — on a background task that holds the reconcile lock.
    let id = crate::task_runner::begin(state, "reconcile", "Reconcile exports")?;
    state.db.set_setting(RECONCILE_TASK_KEY, &id.to_string())?;
    let st = state.clone();
    tokio::spawn(async move {
        let _guard = guard; // serialize: released only when the run is done
        let outcome = crate::task_runner::drive(&st, id, st.helper.reconcile())
            .await
            .unwrap_or_else(|e| TaskOutcome {
                ok: false,
                error: Some(format!("{e:#}")),
            });
        st.tasks.unregister(id);
        if let Err(e) = apply_reconcile_outcome(
            &st,
            &nvme_exports,
            &iscsi_exports,
            &nfs_exports,
            (drift.nvmet_ok, drift.lio_ok, drift.nfs_ok),
            outcome,
        ) {
            tracing::error!(error = %e, "recording reconcile outcome failed");
        }
    });
    Ok(Some(id))
}

/// Surfaces a finished reconcile on the dots of the protocols that drifted (the
/// task's output carries the detail) and on the settings banner. `*_ok` are the
/// pre-check verdicts: a protocol that was already satisfied keeps a clear dot.
fn apply_reconcile_outcome(
    state: &AppState,
    nvme_exports: &[NvmeExport],
    iscsi_exports: &[IscsiExport],
    nfs_exports: &[NfsExport],
    (nvmet_ok, lio_ok, nfs_ok): (bool, bool, bool),
    outcome: TaskOutcome,
) -> anyhow::Result<()> {
    let err = (!outcome.ok).then(|| outcome.error.unwrap_or_else(|| "reconcile failed".into()));
    for e in nvme_exports.iter().filter(|e| e.enabled) {
        state
            .db
            .set_nvme_export_error(e.id, (!nvmet_ok).then_some(err.as_deref()).flatten())?;
    }
    for e in iscsi_exports.iter().filter(|e| e.enabled) {
        state
            .db
            .set_iscsi_export_error(e.id, (!lio_ok).then_some(err.as_deref()).flatten())?;
    }
    for e in nfs_exports.iter().filter(|e| e.enabled) {
        state
            .db
            .set_nfs_export_error(e.id, (!nfs_ok).then_some(err.as_deref()).flatten())?;
    }
    state
        .db
        .set_setting(RECONCILE_ERROR_KEY, err.as_deref().unwrap_or_default())?;
    Ok(())
}

/// The list view both protocol pages render — the templates share field names,
/// so one struct serves `nvme.html` and `iscsi.html` alike.
pub struct ExportsView {
    pub rows: Vec<ExportRow>,
    pub devices: Vec<actual::block::AvailDevice>,
    /// Physical ports offered in the create form's "listen interfaces" picker.
    pub interfaces: Vec<IfaceChoice>,
    pub banner: Option<String>,
    /// The reconcile task to link from the banner (`/tasks/{id}`).
    pub banner_task_id: Option<i64>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

/// The per-export page view, shared the same way as [`ExportsView`].
pub struct ExportDetailView {
    pub name: String,
    /// `None` when the export id is unknown (or belongs to a foreign export).
    pub row: Option<ExportRow>,
    /// Physical ports for the "listen interfaces" edit form, this export's
    /// current pins pre-checked.
    pub interfaces: Vec<IfaceChoice>,
    pub banner: Option<String>,
    /// The reconcile task to link from the banner (`/tasks/{id}`).
    pub banner_task_id: Option<i64>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

/// One protocol's bindings for the shared export handlers below. The
/// create/toggle/interfaces/delete flows and the detail plumbing used to live
/// line-for-line in both `routes::nvme` and `routes::iscsi`; each now
/// implements this and the generic handlers do the rest. `gather` stays
/// protocol-owned — rows, transports and client commands genuinely differ —
/// with its shared chrome factored into [`gather_view`].
#[allow(async_fn_in_trait)]
pub trait ExportProtocol: Send + Sync + 'static {
    /// The list page path (`"/nvme"`), used for redirects after delete.
    const LIST_PATH: &'static str;

    async fn gather(
        state: &AppState,
        flash: Option<String>,
        form_error: Option<String>,
        task_id: Option<i64>,
    ) -> ExportsView;
    fn render_list_partial(view: ExportsView) -> Response;
    fn render_detail_partial(view: ExportDetailView) -> Response;
    fn stored_interfaces(db: &Db, id: i64) -> Vec<String>;
    fn set_enabled(db: &Db, id: i64, enable: bool) -> anyhow::Result<()>;
    fn set_interfaces(db: &Db, id: i64, interfaces: &[String]) -> anyhow::Result<()>;
    fn delete(db: &Db, id: i64) -> anyhow::Result<()>;
    /// Whether `i` is a valid initiator identifier for this protocol (NQN vs IQN).
    fn initiator_ok(i: &str) -> bool;
    /// Whether the create form picked a transport — protocol-computed because
    /// loop counts only for NVMe-oF.
    fn has_transport(f: &CreateFields) -> bool;
    /// Inserts the validated export into the desired state.
    fn insert(
        db: &Db,
        name: &ExportName,
        device: &DevicePath,
        allow_any_host: bool,
        initiators: Vec<String>,
        f: CreateFields,
    ) -> anyhow::Result<()>;
}

#[derive(Deserialize)]
pub struct IdForm {
    pub id: i64,
    #[serde(default)]
    pub enable: Option<bool>,
}

/// The most recent reconcile task id, plus the banner text when the last pass
/// failed — the chrome both list gathers thread through their views.
pub fn reconcile_banner(state: &AppState) -> (Option<i64>, Option<String>) {
    let task = state
        .db
        .get_setting(RECONCILE_TASK_KEY)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok());
    let banner = match state.db.get_setting(RECONCILE_ERROR_KEY) {
        Ok(Some(err)) if !err.is_empty() => Some(format!("reconcile problem: {err}")),
        _ => None,
    };
    (task, banner)
}

/// The shared chrome of a protocol's list `gather`: the interface picker, the
/// reconcile banner threading, and the available-devices tail. `rows` builds
/// the protocol's table (managed + foreign) given the reconcile task id to
/// link from unrealized dots, returning the rows plus the store-read error
/// banner, if any (the reconcile banner wins when both are present).
pub async fn gather_view(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
    rows: impl FnOnce(Option<i64>) -> (Vec<ExportRow>, Option<String>),
) -> ExportsView {
    let (reconcile_task, reconcile_banner) = reconcile_banner(state);
    let (rows, store_error) = rows(reconcile_task);
    let mut view = ExportsView {
        rows,
        devices: vec![],
        interfaces: iface_choices(state, &[]).await,
        banner: store_error,
        banner_task_id: None,
        flash,
        task_id,
        form_error,
    };
    if let Some(banner) = reconcile_banner {
        view.banner = Some(banner);
        view.banner_task_id = reconcile_task;
    }
    let in_use: std::collections::HashSet<String> =
        state.db.export_device_paths().into_iter().collect();
    view.devices = actual::block::available_block_devices(&state.helper, &in_use).await;
    view
}

/// The dot cell of a managed export row: CSS class, reason, whether to offer
/// Diagnose, and the reconcile task to link while the export is unrealized.
pub fn managed_dot(
    enabled: bool,
    want_rdma: bool,
    reconcile_task: Option<i64>,
    dot: impl FnOnce() -> crate::dot::Dot,
) -> (&'static str, String, bool, Option<i64>) {
    if !enabled {
        return ("dot-gray", "disabled".to_owned(), false, None);
    }
    let dot = dot();
    let not_green = dot.state != DotState::Green;
    (
        dot_class(dot.state),
        dot.reason,
        want_rdma && not_green,
        not_green.then_some(reconcile_task).flatten(),
    )
}

/// The "hosts" cell: `"any host"` or the allowed-entry count.
pub fn hosts_cell(allow_any_host: bool, allowed: usize) -> String {
    if allow_any_host {
        "any host".into()
    } else {
        format!("{allowed} allowed")
    }
}

/// Re-reads live state via the protocol's `gather` and picks out the one
/// managed export, so the detail page shows the same dot/transports/client
/// commands as the list.
pub async fn gather_detail<P: ExportProtocol>(
    state: &AppState,
    id: i64,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> ExportDetailView {
    let selected = P::stored_interfaces(&state.db, id);
    let sel: std::collections::HashSet<&str> = selected.iter().map(String::as_str).collect();
    let mut view = P::gather(state, flash, form_error, task_id).await;
    // Reuse the list gather's picker (one NIC enumeration round-trip), re-checked
    // against this export's pins instead of querying the helper again.
    for c in &mut view.interfaces {
        c.checked = sel.contains(c.value.as_str());
    }
    let row = view.rows.into_iter().find(|r| r.id == id && !r.external);
    ExportDetailView {
        name: row
            .as_ref()
            .map_or_else(|| id.to_string(), |r| r.name.clone()),
        interfaces: view.interfaces,
        row,
        banner: view.banner,
        banner_task_id: view.banner_task_id,
        flash: view.flash,
        task_id: view.task_id,
        form_error: view.form_error,
    }
}

/// Renders the list partial after a create: the reconcile (if any) runs in the
/// background, so `result` carries its task id for the notice's "view task"
/// link.
async fn finish<P: ExportProtocol>(
    state: &AppState,
    result: anyhow::Result<Option<i64>>,
    success: String,
) -> Response {
    let (flash, error, task_id) = match result {
        Ok(task_id) => (Some(success), None, task_id),
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    P::render_list_partial(P::gather(state, flash, error, task_id).await)
}

/// The shared create flow: parse, validate (the protocol hooks supply the
/// identifier check and transport rule), insert, reconcile. A validation or
/// insert error re-renders the list partial with the form error.
pub async fn create<P: ExportProtocol>(
    State(state): State<Arc<AppState>>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let f = parse_create_fields(fields);
    let valid = validate_create(&f, P::initiator_ok, P::has_transport(&f));
    let (name, device, initiators, allow_any_host) = match valid {
        Ok(v) => v,
        Err(msg) => return P::render_list_partial(P::gather(&state, None, Some(msg), None).await),
    };
    let success = format!("created export {name}");
    let result = match P::insert(&state.db, &name, &device, allow_any_host, initiators, f) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish::<P>(&state, result, success).await
}

/// Enable/disable stays on the export's own page, re-rendering its detail
/// partial.
pub async fn toggle<P: ExportProtocol>(
    State(state): State<Arc<AppState>>,
    Form(form): Form<IdForm>,
) -> Response {
    let enable = form.enable.unwrap_or(false);
    let success = format!("export {}", if enable { "enabled" } else { "disabled" });
    let (flash, error, task_id) = match P::set_enabled(&state.db, form.id, enable) {
        Ok(()) => match reconcile_state(&state).await {
            Ok(task_id) => (Some(success), None, task_id),
            Err(e) => (None, Some(format!("{e:#}")), None),
        },
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    P::render_detail_partial(gather_detail::<P>(&state, form.id, flash, error, task_id).await)
}

/// Sets the export's pinned listen interfaces (repeated `interfaces` keys),
/// then reconciles. Stays on the export's page, re-rendering its detail
/// partial.
pub async fn edit_interfaces<P: ExportProtocol>(
    State(state): State<Arc<AppState>>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let mut id: Option<i64> = None;
    let mut interfaces: Vec<String> = Vec::new();
    for (k, v) in fields {
        match k.as_str() {
            "id" => id = v.trim().parse().ok(),
            "interfaces" => interfaces.push(v),
            _ => {}
        }
    }
    // A missing or unparsable id must not fall through to export id 0 —
    // set_interfaces would match no row yet still flash success. Reject it the
    // way the Form(IdForm) handlers reject theirs.
    let Some(id) = id else {
        return (StatusCode::UNPROCESSABLE_ENTITY, "missing or invalid id").into_response();
    };
    if let Some(bad) = interfaces
        .iter()
        .find(|s| crate::state::parse_listen_iface(s).is_none())
    {
        let err = format!("invalid interface selector {bad:?}");
        return P::render_detail_partial(
            gather_detail::<P>(&state, id, None, Some(err), None).await,
        );
    }
    let (flash, error, task_id) = match P::set_interfaces(&state.db, id, &interfaces) {
        Ok(()) => match reconcile_state(&state).await {
            Ok(task_id) => (Some("listen interfaces updated".to_owned()), None, task_id),
            Err(e) => (None, Some(format!("{e:#}")), None),
        },
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    P::render_detail_partial(gather_detail::<P>(&state, id, flash, error, task_id).await)
}

/// Deleting an export removes its page, so on success redirect back to the
/// list; a failed DB delete leaves the row in place and re-renders the detail
/// partial.
pub async fn delete<P: ExportProtocol>(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Response {
    match P::delete(&state.db, form.id) {
        Ok(()) => {
            // A reconcile failure surfaces on the list-page banner, not here.
            let _ = reconcile_state(&state).await;
            nav_redirect(&headers, P::LIST_PATH)
        }
        Err(e) => P::render_detail_partial(
            gather_detail::<P>(&state, form.id, None, Some(format!("{e:#}")), None).await,
        ),
    }
}

/// The create form's raw fields, read from the pair list because the "listen
/// interfaces" picker arrives as repeated `interfaces` keys (the same pattern
/// as the pool/VG create forms). `want_loop` is only offered by NVMe-oF and
/// simply stays false for iSCSI.
#[derive(Default)]
pub struct CreateFields {
    pub name: String,
    pub device: String,
    pub initiators_raw: String,
    pub want_rdma: bool,
    pub want_tcp: bool,
    pub want_loop: bool,
    pub allow_any_host: bool,
    pub interfaces: Vec<String>,
}

fn parse_create_fields(fields: Vec<(String, String)>) -> CreateFields {
    let mut f = CreateFields::default();
    for (k, v) in fields {
        match k.as_str() {
            "name" => f.name = v,
            "device" => f.device = v,
            "initiators" => f.initiators_raw = v,
            "want_rdma" => f.want_rdma = true,
            "want_tcp" => f.want_tcp = true,
            "want_loop" => f.want_loop = true,
            "allow_any_host" => f.allow_any_host = true,
            "interfaces" => f.interfaces.push(v),
            _ => {}
        }
    }
    f
}

/// Validates the shared create-form fields: `(name, device, initiators,
/// allow_any_host)` on success, the user-facing form error otherwise.
/// `initiator_ok` is the protocol's identifier check (NQN vs IQN);
/// `has_transport` is protocol-computed because loop counts only for NVMe-oF.
fn validate_create(
    f: &CreateFields,
    initiator_ok: impl Fn(&str) -> bool,
    has_transport: bool,
) -> Result<(ExportName, DevicePath, Vec<String>, bool), String> {
    let name = ExportName::new(f.name.trim()).map_err(|_| {
        format!(
            "invalid export name {:?} (lowercase letters, digits, '-', '.')",
            f.name
        )
    })?;
    let device = DevicePath::new(f.device.trim())
        .map_err(|_| format!("invalid device path {:?}", f.device))?;
    let initiators: Vec<String> = f
        .initiators_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(Into::into)
        .collect();
    if let Some(bad) = initiators.iter().find(|i| !initiator_ok(i)) {
        return Err(format!("invalid initiator name {bad:?}"));
    }
    if let Some(bad) = f
        .interfaces
        .iter()
        .find(|s| crate::state::parse_listen_iface(s).is_none())
    {
        return Err(format!("invalid interface selector {bad:?}"));
    }
    if !has_transport {
        return Err("select at least one transport".into());
    }
    let allow_any_host = f.allow_any_host || initiators.is_empty();
    Ok((name, device, initiators, allow_any_host))
}

/// NICs that are RoCE-capable but have RoCE switched off — surfaced by the
/// Diagnose checklists when no RDMA device exists, so they explain why and
/// point at Settings.
pub async fn capable_disabled_nics(state: &AppState) -> Vec<String> {
    actual::nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter(|n| matches!(n.kind, actual::nic::NicRdmaKind::CapableDisabled { .. }))
        .map(|n| n.netdev)
        .collect()
}

/// The graceful unknown-id Diagnose page.
pub fn diagnose_not_found(protocol: &'static str, back_href: &'static str) -> DiagnoseView {
    DiagnoseView {
        name: String::new(),
        protocol,
        dot_class: "dot-gray",
        dot_reason: String::new(),
        criteria: vec![],
        not_found: true,
        back_href,
    }
}

/// One row in a block-export table — shared shape for both protocols and for the
/// read-only foreign exports each page surfaces.
pub struct ExportRow {
    pub id: i64,
    pub name: String,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub device: String,
    pub transports: String,
    pub hosts: String,
    /// Connected client count for iSCSI (live sessions); `None` for NVMe-oF,
    /// whose RDMA peers can't be attributed per-export on this kernel.
    pub clients: Option<usize>,
    pub enabled: bool,
    /// RDMA was requested but the export isn't fully serving over RDMA — offer
    /// the per-criterion Diagnose page.
    pub diagnose: bool,
    /// Copy-paste commands a client runs to connect, one per network transport.
    pub client: Vec<ClientCmd>,
    /// Present on the box but not managed by greendot (foreign NQN/IQN, e.g.
    /// provisioned by democratic-csi). Rendered read-only with an "External"
    /// badge; its dot reflects only the observed transport.
    pub external: bool,
    /// The reconcile task to link from this export's dot when it isn't fully
    /// realized (`/tasks/{id}`); `None` for green/disabled/foreign rows.
    pub task_id: Option<i64>,
}

/// A labelled client-side connect command shown under each export.
pub struct ClientCmd {
    /// Which transport this connects over, e.g. "RDMA", "TCP", "iSER (RDMA)".
    pub label: String,
    /// The multi-line command block to run: load the fabrics module, connect
    /// (discovery + login for iSCSI), and a `# disconnect:` hint.
    pub cmd: String,
}

/// The configured default listen address, or the unspecified address (all
/// interfaces). Exports that pin no interface bind here.
pub fn listen_addr(state: &AppState) -> IpAddr {
    state
        .db
        .get_setting("listen_addr")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED.into())
}

/// One selectable physical port in an export's "listen interfaces" picker. The
/// `value` is the stored scheme-tagged selector (`pci:0000:00:10.0`); the label
/// shows the friendly netdev/IP/RDMA status so the user can pick by sight.
pub struct IfaceChoice {
    pub value: String,
    pub label: String,
    pub checked: bool,
}

/// A short, vendor-free RDMA-readiness label for the interface picker.
fn iface_status(kind: &actual::nic::NicRdmaKind) -> &'static str {
    use actual::nic::NicRdmaKind::*;
    match kind {
        Active => "RDMA active",
        Inactive => "RDMA down",
        CapableDisabled { .. } => "RoCE off",
        SoftRoceable => "no RDMA",
        Unsupported => "other",
    }
}

/// The physical NICs an export can be pinned to, with the ones in `selected`
/// pre-checked. Only interfaces with a PCI address (physical ports) are offered;
/// the PCI address is the stable identity that survives IP churn and NIC swaps.
pub async fn iface_choices(state: &AppState, selected: &[String]) -> Vec<IfaceChoice> {
    let sel: std::collections::HashSet<&str> = selected.iter().map(String::as_str).collect();
    let mut choices: Vec<IfaceChoice> = actual::nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter_map(|n| {
            let value = format!("pci:{}", n.pci?);
            let addrs = if n.addrs.is_empty() {
                "no IP".to_owned()
            } else {
                n.addrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            Some(IfaceChoice {
                checked: sel.contains(value.as_str()),
                label: format!("{} — {} ({})", n.netdev, addrs, iface_status(&n.kind)),
                value,
            })
        })
        .collect();
    choices.sort_by(|a, b| a.label.cmp(&b.label));
    choices
}

/// CSS class for a dot state. The disabled (gray) case is handled by the caller.
pub fn dot_class(state: DotState) -> &'static str {
    match state {
        DotState::Green => "dot-green",
        DotState::Yellow => "dot-yellow",
        DotState::Red => "dot-red",
    }
}

/// Joins backing-device paths for display, collapsing the empty set to an em dash.
pub fn join_devices<'a>(devices: impl Iterator<Item = &'a str>) -> String {
    let devices: Vec<&str> = devices.filter(|d| !d.is_empty()).collect();
    if devices.is_empty() {
        "—".to_owned()
    } else {
        devices.join(", ")
    }
}

/// The Diagnose page is identical for both protocols — an ordered RDMA-readiness
/// checklist — so the two pages share one view and template, differing only in
/// the protocol label and the back link.
pub struct DiagnoseView {
    pub name: String,
    pub protocol: &'static str,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub criteria: Vec<Criterion>,
    pub not_found: bool,
    /// Where the "← Back" link returns to: `/nvme` or `/iscsi`.
    pub back_href: &'static str,
}

#[derive(Template)]
#[template(path = "diagnose.html")]
struct DiagnoseTemplate {
    user: CurrentUser,
    view: DiagnoseView,
}

/// Renders the shared Diagnose page from a protocol-specific [`DiagnoseView`].
pub fn render_diagnose(user: CurrentUser, view: DiagnoseView) -> Response {
    page(DiagnoseTemplate { user, view })
}
