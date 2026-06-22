//! Shared machinery for the two block-device export concepts (NVMe-oF and
//! iSCSI). The protocols are first-class concepts with their own pages, structs
//! and tables (see [`super::nvme`] / [`super::iscsi`]); only the genuinely
//! protocol-agnostic pieces live here: the cross-protocol reconcile pass, the
//! row/command view types both pages render, and the shared Diagnose page.

use super::{AppState, page};
use crate::actual;
use crate::auth::CurrentUser;
use crate::dot::Criterion;
use crate::reconcile::{self, RECONCILE_ERROR_KEY};
use askama::Template;
use axum::response::Response;
use greendot_proto::{DotState, NFS_RDMA_PORT};
use std::net::{IpAddr, Ipv4Addr};

/// Serialized full reconcile against current desired state. A cheap in-process
/// drift pre-check keeps the steady state (and the 60 s timer) silent; on drift
/// it runs `greendot-cli reconcile` as a recorded, streamable task and surfaces
/// the outcome on the export dots and the settings banner. The web stays the
/// sole writer of the config — the CLI only reads it.
pub async fn reconcile_state(state: &AppState) -> anyhow::Result<()> {
    let _guard = state.reconcile_lock.lock().await;
    let nvme_exports = state.db.list_nvme_exports()?;
    let iscsi_exports = state.db.list_iscsi_exports()?;
    let listen: IpAddr = state
        .db
        .get_setting("listen_addr")?
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED.into());

    let nfs_exports = state.db.list_nfs_exports()?;
    let nvmet_ok = reconcile::nvmet_satisfied(
        &reconcile::render_nvmet(&nvme_exports, listen),
        &actual::nvmet::read(&state.nvmet_root),
    );
    let lio_ok = reconcile::lio_satisfied(
        &reconcile::render_lio(&iscsi_exports, listen),
        &actual::lio::read(&state.lio_root),
    );
    // NFS actual state needs root, so this pre-check makes one helper round-trip
    // (only matters when NFS exports exist; the steady state stays silent).
    let nfs_ok = reconcile::nfs_satisfied(
        &reconcile::render_nfs(&nfs_exports, NFS_RDMA_PORT),
        &actual::nfs::read(&state.helper).await,
    );
    if nvmet_ok && lio_ok && nfs_ok {
        return Ok(()); // already realized — emit no task
    }

    let outcome = crate::task_runner::run_local(
        state,
        &state.reconcile_cmd,
        "reconcile",
        "Reconcile exports",
    )
    .await?;
    let err = (!outcome.ok).then(|| outcome.error.unwrap_or_else(|| "reconcile failed".into()));

    // Surface the result on the dots of the protocols that drifted (the task's
    // output carries the detail) and on the settings banner.
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
}

/// A labelled client-side connect command shown under each export.
pub struct ClientCmd {
    /// Which transport this connects over, e.g. "RDMA", "TCP", "iSER (RDMA)".
    pub label: String,
    /// The multi-line command block to run: load the fabrics module, connect
    /// (discovery + login for iSCSI), and a `# disconnect:` hint.
    pub cmd: String,
}

/// The configured listen address, or the unspecified address (all interfaces).
pub fn listen_addr(state: &AppState) -> IpAddr {
    state
        .db
        .get_setting("listen_addr")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED.into())
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
