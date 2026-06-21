use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::dot::{Criterion, iscsi_diagnostics, iscsi_dot, nvme_diagnostics, nvme_dot};
use crate::reconcile::RECONCILE_ERROR_KEY;
use crate::state::{ExportKind, NewExport};
use crate::{actual, reconcile};
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DevicePath, DotState, ExportName, Nqn};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/exports", get(exports_page))
        .route("/exports/create", post(create))
        .route("/exports/toggle", post(toggle))
        .route("/exports/delete", post(delete))
        .route("/exports/{id}/diagnose", get(diagnose_page))
        .route("/partials/exports", get(dots_partial))
}

/// Serialized full reconcile against current desired state. Emits helper tasks
/// only when actual configfs has drifted from desired.
pub async fn reconcile_state(state: &AppState) -> anyhow::Result<()> {
    let _guard = state.reconcile_lock.lock().await;
    reconcile::run(state).await
}

pub struct ExportRow {
    pub id: i64,
    pub name: String,
    pub protocol: &'static str,
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
}

pub struct ExportsView {
    pub rows: Vec<ExportRow>,
    pub devices: Vec<crate::actual::block::AvailDevice>,
    pub banner: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

pub async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
) -> ExportsView {
    let mut view = ExportsView {
        rows: vec![],
        devices: vec![],
        banner: None,
        flash,
        form_error,
    };
    let actual_nvmet = actual::nvmet::read(&state.nvmet_root);
    let actual_lio = actual::lio::read(&state.lio_root);
    let iscsi_sessions = actual::lio::sessions(&state.lio_root);
    let rdma = actual::rdma::devices();
    let mut in_use: HashSet<String> = HashSet::new();
    match state.db.list_exports() {
        Ok(exports) => {
            in_use.extend(exports.iter().map(|e| e.device_path.clone()));
            view.rows = exports
                .iter()
                .map(|e| {
                    let (dot_class, dot_reason, diagnose) = if !e.enabled {
                        ("dot-gray", "disabled".to_owned(), false)
                    } else {
                        let dot = match e.kind {
                            ExportKind::Nvme => nvme_dot(e, &actual_nvmet, &rdma),
                            ExportKind::Iscsi => iscsi_dot(e, &actual_lio, &rdma),
                        };
                        let class = match dot.state {
                            DotState::Green => "dot-green",
                            DotState::Yellow => "dot-yellow",
                            DotState::Red => "dot-red",
                        };
                        (
                            class,
                            dot.reason,
                            e.want_rdma && dot.state != DotState::Green,
                        )
                    };
                    let mut transports = Vec::new();
                    for (want, label) in [
                        (e.want_rdma, "RDMA"),
                        (e.want_tcp, "TCP"),
                        (e.want_loop, "loop"),
                    ] {
                        if want {
                            transports.push(label);
                        }
                    }
                    let clients = match e.kind {
                        ExportKind::Iscsi => {
                            let iqn = e.iqn();
                            Some(
                                iscsi_sessions
                                    .iter()
                                    .filter(|s| s.target_iqn == iqn.as_str())
                                    .count(),
                            )
                        }
                        ExportKind::Nvme => None,
                    };
                    ExportRow {
                        id: e.id,
                        name: e.name.clone(),
                        protocol: match e.kind {
                            ExportKind::Nvme => "NVMe-oF",
                            ExportKind::Iscsi => "iSCSI",
                        },
                        dot_class,
                        dot_reason,
                        device: e.device_path.clone(),
                        transports: transports.join(" + "),
                        hosts: if e.allow_any_host {
                            "any host".into()
                        } else {
                            format!("{} allowed", e.initiators.len())
                        },
                        clients,
                        enabled: e.enabled,
                        diagnose,
                    }
                })
                .collect();
        }
        Err(e) => view.banner = Some(format!("could not read export store: {e:#}")),
    }
    if let Ok(Some(err)) = state.db.get_setting(RECONCILE_ERROR_KEY)
        && !err.is_empty()
    {
        view.banner = Some(format!("reconcile problem: {err}"));
    }
    view.devices = actual::block::available_block_devices(&state.helper, &in_use).await;
    view
}

#[derive(Template)]
#[template(path = "exports.html")]
struct ExportsTemplate {
    user: CurrentUser,
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_exports.html")]
struct ExportsPartial {
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_dots.html")]
struct DotsPartial {
    view: ExportsView,
}

pub struct DiagnoseView {
    pub name: String,
    pub protocol: &'static str,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub criteria: Vec<Criterion>,
    pub not_found: bool,
}

#[derive(Template)]
#[template(path = "diagnose.html")]
struct DiagnoseTemplate {
    user: CurrentUser,
    view: DiagnoseView,
}

async fn gather_diagnose(state: &AppState, id: i64) -> DiagnoseView {
    let export = state
        .db
        .list_exports()
        .ok()
        .and_then(|exports| exports.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return DiagnoseView {
            name: String::new(),
            protocol: "",
            dot_class: "dot-gray",
            dot_reason: String::new(),
            criteria: vec![],
            not_found: true,
        };
    };
    let rdma = actual::rdma::devices();
    // NICs that are RoCE-capable but have RoCE switched off — surfaced when no
    // RDMA device exists, so the checklist explains why and points at Settings.
    let capable_disabled: Vec<String> = actual::nic::interfaces()
        .into_iter()
        .filter(|n| matches!(n.kind, actual::nic::NicRdmaKind::CapableDisabled { .. }))
        .map(|n| n.netdev)
        .collect();
    let (criteria, dot, protocol) = match export.kind {
        ExportKind::Nvme => {
            let nvmet = actual::nvmet::read(&state.nvmet_root);
            (
                nvme_diagnostics(&export, &nvmet, &rdma, &capable_disabled),
                nvme_dot(&export, &nvmet, &rdma),
                "NVMe-oF",
            )
        }
        ExportKind::Iscsi => {
            let lio = actual::lio::read(&state.lio_root);
            (
                iscsi_diagnostics(&export, &lio, &rdma, &capable_disabled),
                iscsi_dot(&export, &lio, &rdma),
                "iSCSI",
            )
        }
    };
    DiagnoseView {
        name: export.name,
        protocol,
        dot_class: match dot.state {
            DotState::Green => "dot-green",
            DotState::Yellow => "dot-yellow",
            DotState::Red => "dot-red",
        },
        dot_reason: dot.reason,
        criteria,
        not_found: false,
    }
}

async fn diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(DiagnoseTemplate {
        user,
        view: gather_diagnose(&state, id).await,
    })
}

async fn exports_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(ExportsTemplate {
        user,
        view: gather(&state, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(DotsPartial {
        view: gather(&state, None, None).await,
    })
}

async fn finish(state: &AppState, result: anyhow::Result<()>, success: String) -> Response {
    let (flash, error) = match result {
        Ok(()) => (Some(success), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(ExportsPartial {
        view: gather(state, flash, error).await,
    })
}

#[derive(Deserialize)]
struct CreateForm {
    name: String,
    device: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    want_rdma: Option<String>,
    #[serde(default)]
    want_tcp: Option<String>,
    #[serde(default)]
    want_loop: Option<String>,
    #[serde(default)]
    allow_any_host: Option<String>,
    #[serde(default)]
    initiators: String,
}

async fn create(State(state): State<Arc<AppState>>, Form(form): Form<CreateForm>) -> Response {
    let view_err = |msg: String| async {
        page(ExportsPartial {
            view: gather(&state, None, Some(msg)).await,
        })
    };
    let Ok(name) = ExportName::new(form.name.trim()) else {
        return view_err(format!(
            "invalid export name {:?} (lowercase letters, digits, '-', '.')",
            form.name
        ))
        .await;
    };
    let Ok(device) = DevicePath::new(form.device.trim()) else {
        return view_err(format!("invalid device path {:?}", form.device)).await;
    };
    let kind = match form.kind.as_str() {
        "iscsi" => ExportKind::Iscsi,
        _ => ExportKind::Nvme,
    };
    let initiators: Vec<String> = form
        .initiators
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(Into::into)
        .collect();
    let bad = initiators.iter().find(|i| match kind {
        ExportKind::Nvme => Nqn::new((*i).clone()).is_err(),
        ExportKind::Iscsi => greendot_proto::Iqn::new((*i).clone()).is_err(),
    });
    if let Some(bad) = bad {
        return view_err(format!("invalid initiator name {bad:?}")).await;
    }
    let allow_any_host = form.allow_any_host.is_some() || initiators.is_empty();
    if !(form.want_rdma.is_some() || form.want_tcp.is_some() || form.want_loop.is_some()) {
        return view_err("select at least one transport".into()).await;
    }
    let new = NewExport {
        kind,
        name: name.to_string(),
        device_path: device.to_string(),
        want_rdma: form.want_rdma.is_some(),
        want_tcp: form.want_tcp.is_some(),
        want_loop: form.want_loop.is_some(),
        allow_any_host,
        initiators,
    };
    let result = match state.db.insert_export(&new) {
        Ok(_) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(&state, result, format!("created export {name}")).await
}

#[derive(Deserialize)]
struct IdForm {
    id: i64,
    #[serde(default)]
    enable: Option<bool>,
}

async fn toggle(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let enable = form.enable.unwrap_or(false);
    let result = match state.db.set_export_enabled(form.id, enable) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(
        &state,
        result,
        format!("export {}", if enable { "enabled" } else { "disabled" }),
    )
    .await
}

async fn delete(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let result = match state.db.delete_export(form.id) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(&state, result, "export deleted".into()).await
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[tokio::test]
    async fn create_toggle_delete_flow_against_fake_helper() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        // Create: stored, reconciled (fake helper says Ok), red dot because
        // the (empty tempdir) nvmet tree shows nothing configured.
        let req = auth(form_post(
            "/exports/create",
            "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1&want_tcp=1&initiators=nqn.2014-08.org.nvmexpress%3Ahost1",
        ));
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("created export vm1"), "{body}");
        assert!(
            body.contains("dot-red"),
            "nothing actually configured yet: {body}"
        );
        assert!(body.contains("RDMA + TCP"), "{body}");
        // RDMA requested but not yet served → a Diagnose link is offered.
        assert!(body.contains("/exports/1/diagnose"), "{body}");

        // iSCSI export with an IQN initiator works and shows its protocol.
        let req = auth(form_post(
            "/exports/create",
            "kind=iscsi&name=tape&device=%2Fdev%2Fzvol%2Ftank%2Ftape&want_rdma=1&initiators=iqn.1993-08.org.debian%3A01%3Aabc",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("created export tape"), "{body}");
        assert!(body.contains("iSCSI"), "{body}");
        // ...but an NQN-style initiator on an iSCSI export is rejected.
        let req = auth(form_post(
            "/exports/create",
            "kind=iscsi&name=bad&device=%2Fdev%2Fsda&want_tcp=1&initiators=nqn.2014-08.org.nvmexpress%3Ahost1",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid initiator name"), "{body}");

        // Bad device path rejected.
        let req = auth(form_post(
            "/exports/create",
            "name=vm2&device=%2Fetc%2Fshadow&want_tcp=1",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid device path"), "{body}");

        // Dashboard partial shows the export card.
        let req = auth(
            HttpRequest::get("/partials/exports")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("vm1"), "{body}");

        // Toggle off → gray dot; delete → gone.
        let (_, _, body) = send(
            &app,
            auth(form_post("/exports/toggle", "id=1&enable=false")),
        )
        .await;
        assert!(body.contains("dot-gray"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/exports/delete", "id=1"))).await;
        assert!(
            body.contains("tape"),
            "iSCSI export must survive deleting the other: {body}"
        );
        let (_, _, body) = send(&app, auth(form_post("/exports/delete", "id=2"))).await;
        assert!(body.contains("No exports yet"), "{body}");
    }

    #[tokio::test]
    async fn diagnose_page_lists_rdma_criteria() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };
        send(
            &app,
            auth(form_post(
                "/exports/create",
                "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1&want_tcp=1",
            )),
        )
        .await;

        // The checklist renders, with the config rows failing because the
        // (empty tempdir) nvmet tree configures nothing.
        let req = auth(
            HttpRequest::get("/exports/1/diagnose")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("RDMA requested"), "{body}");
        assert!(body.contains("Subsystem configured"), "{body}");
        assert!(body.contains("Listen address served"), "{body}");

        // An unknown id is a graceful not-found, not a 500.
        let req = auth(
            HttpRequest::get("/exports/999/diagnose")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Export not found"), "{body}");
    }
}
