//! iSCSI block-device exports — one RDMA (iSER) dot per target. Create/toggle/
//! delete mutate the desired-state TOML and run the shared reconcile; the dot
//! comes from the LIO configfs tree plus the RDMA device list, and the Clients
//! column counts live sessions. Foreign targets (outside our IQN prefix, e.g.
//! democratic-csi) are surfaced read-only with an honest, observed-transport dot.

use super::block_export::{
    ClientCmd, DiagnoseView, ExportRow, dot_class, join_devices, listen_addr, reconcile_state,
    render_diagnose,
};
use super::{AppState, page};
use crate::actual;
use crate::auth::{CurrentUser, nav_redirect};
use crate::dot::{external_iscsi_dot, iscsi_diagnostics, iscsi_dot};
use crate::reconcile::{RECONCILE_ERROR_KEY, RECONCILE_TASK_KEY};
use crate::state::NewIscsiExport;
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DevicePath, DotState, ExportName, Iqn, OUR_IQN_PREFIX};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/iscsi", get(iscsi_page))
        .route("/iscsi/create", post(create))
        .route("/iscsi/{id}", get(detail_page))
        .route("/iscsi/toggle", post(toggle))
        .route("/iscsi/delete", post(delete))
        .route("/iscsi/{id}/diagnose", get(diagnose_page))
        .route("/partials/iscsi", get(dots_partial))
}

/// Builds the client connect command(s) for an iSCSI export. Ports mirror the
/// server side in [`crate::reconcile`]: iSER on 3260, plain TCP on 3261 when
/// iSER is also on (else 3260). An unspecified listen address (the default —
/// all interfaces) renders a `<server-ip>` placeholder.
fn client_instructions(e: &crate::state::IscsiExport, listen: IpAddr) -> Vec<ClientCmd> {
    let addr = if listen.is_unspecified() {
        "<server-ip>".to_owned()
    } else {
        listen.to_string()
    };
    let iqn = e.iqn();
    let mut cmds = Vec::new();
    if e.want_rdma {
        cmds.push(ClientCmd {
            label: "iSER (RDMA)".to_owned(),
            cmd: format!(
                "modprobe ib_iser\n\
                 iscsiadm -m discovery -t st -p {addr}:3260 -I iser\n\
                 iscsiadm -m node -T {iqn} -p {addr}:3260 -I iser --login\n\
                 # disconnect: iscsiadm -m node -T {iqn} -p {addr}:3260 -I iser --logout"
            ),
        });
    }
    if e.want_tcp {
        let port = if e.want_rdma { 3261 } else { 3260 };
        cmds.push(ClientCmd {
            label: "TCP".to_owned(),
            cmd: format!(
                "iscsiadm -m discovery -t st -p {addr}:{port}\n\
                 iscsiadm -m node -T {iqn} -p {addr}:{port} --login\n\
                 # disconnect: iscsiadm -m node -T {iqn} -p {addr}:{port} --logout"
            ),
        });
    }
    cmds
}

/// Rows for iSCSI targets present in LIO but outside greendot's IQN prefix.
fn foreign_iscsi_rows(
    actual: &actual::lio::ActualLio,
    sessions: &[actual::lio::IscsiSession],
    rdma: &[actual::rdma::RdmaDev],
) -> Vec<ExportRow> {
    actual
        .targets
        .iter()
        .filter(|t| !t.iqn.starts_with(OUR_IQN_PREFIX))
        .map(|t| {
            let dot = external_iscsi_dot(t, rdma);
            let mut transports: Vec<&str> = Vec::new();
            if t.portals.iter().any(|p| p.iser) {
                transports.push("iSER");
            }
            if t.portals.iter().any(|p| !p.iser) {
                transports.push("TCP");
            }
            let devices = t.luns.iter().filter_map(|lun| {
                actual
                    .backstores
                    .iter()
                    .find(|b| &b.name == lun)
                    .map(|b| b.udev_path.as_str())
            });
            ExportRow {
                id: 0,
                name: t.iqn.clone(),
                dot_class: dot_class(dot.state),
                dot_reason: dot.reason,
                device: join_devices(devices),
                transports: transports.join(" + "),
                hosts: if t.demo_mode {
                    "any host".into()
                } else {
                    format!("{} allowed", t.acls.len())
                },
                clients: Some(sessions.iter().filter(|s| s.target_iqn == t.iqn).count()),
                enabled: true,
                diagnose: false,
                client: vec![],
                external: true,
                task_id: None,
            }
        })
        .collect()
}

pub struct IscsiExportsView {
    pub rows: Vec<ExportRow>,
    pub devices: Vec<actual::block::AvailDevice>,
    pub banner: Option<String>,
    /// The reconcile task to link from the banner (`/tasks/{id}`).
    pub banner_task_id: Option<i64>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

pub async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> IscsiExportsView {
    let mut view = IscsiExportsView {
        rows: vec![],
        devices: vec![],
        banner: None,
        banner_task_id: None,
        flash,
        task_id,
        form_error,
    };
    // The most recent reconcile task — linked from the banner and from the dots
    // of any export it left unrealized.
    let reconcile_task = state
        .db
        .get_setting(RECONCILE_TASK_KEY)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok());
    let actual_lio = actual::lio::read(&state.lio_root);
    let sessions = actual::lio::sessions(&state.lio_root);
    let rdma = actual::rdma::devices();
    let listen = listen_addr(state);
    match state.db.list_iscsi_exports() {
        Ok(exports) => {
            view.rows = exports
                .iter()
                .map(|e| {
                    let (dot_class_, dot_reason, diagnose, row_task) = if !e.enabled {
                        ("dot-gray", "disabled".to_owned(), false, None)
                    } else {
                        let dot = iscsi_dot(e, &actual_lio, &rdma);
                        let not_green = dot.state != DotState::Green;
                        (
                            dot_class(dot.state),
                            dot.reason,
                            e.want_rdma && not_green,
                            not_green.then_some(reconcile_task).flatten(),
                        )
                    };
                    let mut transports = Vec::new();
                    for (want, label) in [(e.want_rdma, "iSER"), (e.want_tcp, "TCP")] {
                        if want {
                            transports.push(label);
                        }
                    }
                    let iqn = e.iqn();
                    ExportRow {
                        id: e.id,
                        name: e.name.clone(),
                        dot_class: dot_class_,
                        dot_reason,
                        device: e.device_path.clone(),
                        transports: transports.join(" + "),
                        hosts: if e.allow_any_host {
                            "any host".into()
                        } else {
                            format!("{} allowed", e.initiators.len())
                        },
                        clients: Some(
                            sessions
                                .iter()
                                .filter(|s| s.target_iqn == iqn.as_str())
                                .count(),
                        ),
                        enabled: e.enabled,
                        diagnose,
                        client: client_instructions(e, listen),
                        external: false,
                        task_id: row_task,
                    }
                })
                .collect();
        }
        Err(e) => view.banner = Some(format!("could not read export store: {e:#}")),
    }

    // Foreign targets present on the box that greendot didn't create — observed
    // read-only with the same honest RDMA dot.
    view.rows
        .extend(foreign_iscsi_rows(&actual_lio, &sessions, &rdma));
    if let Ok(Some(err)) = state.db.get_setting(RECONCILE_ERROR_KEY)
        && !err.is_empty()
    {
        view.banner = Some(format!("reconcile problem: {err}"));
        view.banner_task_id = reconcile_task;
    }
    let in_use: HashSet<String> = state.db.export_device_paths().into_iter().collect();
    view.devices = actual::block::available_block_devices(&state.helper, &in_use).await;
    view
}

#[derive(Template)]
#[template(path = "iscsi.html")]
struct IscsiTemplate {
    user: CurrentUser,
    view: IscsiExportsView,
}

#[derive(Template)]
#[template(path = "_iscsi.html")]
struct IscsiPartial {
    view: IscsiExportsView,
}

#[derive(Template)]
#[template(path = "_iscsi_dots.html")]
struct IscsiDotsPartial {
    view: IscsiExportsView,
}

// ---- Per-export page (client instructions + enable/disable/delete) ----

pub struct ExportDetailView {
    pub name: String,
    /// `None` when the export id is unknown (or belongs to a foreign export).
    pub row: Option<ExportRow>,
    pub banner: Option<String>,
    /// The reconcile task to link from the banner (`/tasks/{id}`).
    pub banner_task_id: Option<i64>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "iscsi_detail.html")]
struct IscsiDetailTemplate {
    user: CurrentUser,
    view: ExportDetailView,
}

#[derive(Template)]
#[template(path = "_iscsi_detail.html")]
struct IscsiDetailPartial {
    view: ExportDetailView,
}

async fn gather_detail(
    state: &AppState,
    id: i64,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> ExportDetailView {
    let view = gather(state, flash, form_error, task_id).await;
    let row = view.rows.into_iter().find(|r| r.id == id && !r.external);
    ExportDetailView {
        name: row
            .as_ref()
            .map_or_else(|| id.to_string(), |r| r.name.clone()),
        row,
        banner: view.banner,
        banner_task_id: view.banner_task_id,
        flash: view.flash,
        task_id: view.task_id,
        form_error: view.form_error,
    }
}

async fn detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(IscsiDetailTemplate {
        user,
        view: gather_detail(&state, id, None, None, None).await,
    })
}

async fn gather_diagnose(state: &AppState, id: i64) -> DiagnoseView {
    let export = state
        .db
        .list_iscsi_exports()
        .ok()
        .and_then(|exports| exports.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return DiagnoseView {
            name: String::new(),
            protocol: "iSCSI",
            dot_class: "dot-gray",
            dot_reason: String::new(),
            criteria: vec![],
            not_found: true,
            back_href: "/iscsi",
        };
    };
    let rdma = actual::rdma::devices();
    let capable_disabled: Vec<String> = actual::nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter(|n| matches!(n.kind, actual::nic::NicRdmaKind::CapableDisabled { .. }))
        .map(|n| n.netdev)
        .collect();
    let lio = actual::lio::read(&state.lio_root);
    let criteria = iscsi_diagnostics(&export, &lio, &rdma, &capable_disabled);
    let dot = iscsi_dot(&export, &lio, &rdma);
    DiagnoseView {
        name: export.name,
        protocol: "iSCSI",
        dot_class: dot_class(dot.state),
        dot_reason: dot.reason,
        criteria,
        not_found: false,
        back_href: "/iscsi",
    }
}

async fn diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    render_diagnose(user, gather_diagnose(&state, id).await)
}

async fn iscsi_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(IscsiTemplate {
        user,
        view: gather(&state, None, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(IscsiDotsPartial {
        view: gather(&state, None, None, None).await,
    })
}

/// Renders the list partial after a create: the reconcile (if any) runs in the
/// background, so `result` carries its task id for the notice's "view task" link.
async fn finish(
    state: &AppState,
    result: anyhow::Result<Option<i64>>,
    success: String,
) -> Response {
    let (flash, error, task_id) = match result {
        Ok(task_id) => (Some(success), None, task_id),
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    page(IscsiPartial {
        view: gather(state, flash, error, task_id).await,
    })
}

#[derive(Deserialize)]
struct CreateForm {
    name: String,
    device: String,
    #[serde(default)]
    want_rdma: Option<String>,
    #[serde(default)]
    want_tcp: Option<String>,
    #[serde(default)]
    allow_any_host: Option<String>,
    #[serde(default)]
    initiators: String,
}

async fn create(State(state): State<Arc<AppState>>, Form(form): Form<CreateForm>) -> Response {
    let view_err = |msg: String| async {
        page(IscsiPartial {
            view: gather(&state, None, Some(msg), None).await,
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
    let initiators: Vec<String> = form
        .initiators
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(Into::into)
        .collect();
    if let Some(bad) = initiators.iter().find(|i| Iqn::new((*i).clone()).is_err()) {
        return view_err(format!("invalid initiator name {bad:?}")).await;
    }
    let allow_any_host = form.allow_any_host.is_some() || initiators.is_empty();
    if !(form.want_rdma.is_some() || form.want_tcp.is_some()) {
        return view_err("select at least one transport".into()).await;
    }
    let new = NewIscsiExport {
        name: name.to_string(),
        device_path: device.to_string(),
        want_rdma: form.want_rdma.is_some(),
        want_tcp: form.want_tcp.is_some(),
        allow_any_host,
        initiators,
    };
    let result = match state.db.insert_iscsi_export(&new) {
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

/// Enable/disable stays on the export's own page, re-rendering its detail partial.
async fn toggle(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let enable = form.enable.unwrap_or(false);
    let success = format!("export {}", if enable { "enabled" } else { "disabled" });
    let (flash, error, task_id) = match state.db.set_iscsi_export_enabled(form.id, enable) {
        Ok(()) => match reconcile_state(&state).await {
            Ok(task_id) => (Some(success), None, task_id),
            Err(e) => (None, Some(format!("{e:#}")), None),
        },
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    page(IscsiDetailPartial {
        view: gather_detail(&state, form.id, flash, error, task_id).await,
    })
}

/// Deleting an export removes its page, so on success redirect back to the list;
/// a failed DB delete leaves the row in place and re-renders the detail partial.
async fn delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Response {
    match state.db.delete_iscsi_export(form.id) {
        Ok(()) => {
            // A reconcile failure surfaces on the /iscsi banner, not here.
            let _ = reconcile_state(&state).await;
            nav_redirect(&headers, "/iscsi")
        }
        Err(e) => page(IscsiDetailPartial {
            view: gather_detail(&state, form.id, None, Some(format!("{e:#}")), None).await,
        }),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn client_instructions_iser_tcp_ports_and_address() {
        use crate::state::IscsiExport;
        use std::net::{IpAddr, Ipv4Addr};

        let export = |want_rdma, want_tcp| IscsiExport {
            id: 1,
            name: "vm1".into(),
            device_path: "/dev/zvol/tank/vm1".into(),
            enabled: true,
            want_rdma,
            want_tcp,
            allow_any_host: true,
            initiators: vec![],
            last_error: None,
        };
        let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();

        // iSER on 3260, plain TCP bumped to 3261 because iSER is also on; each is
        // a discovery + login pair against the derived IQN.
        let iscsi = super::client_instructions(&export(true, true), addr);
        assert_eq!(iscsi.len(), 2);
        assert!(
            iscsi[0].cmd.contains("modprobe ib_iser"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[0].cmd.contains("iqn.2026-06.io.greendot:vm1"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[0].cmd.contains("-p 10.0.0.5:3260 -I iser --login"),
            "{}",
            iscsi[0].cmd
        );
        assert!(
            iscsi[1].cmd.contains("-p 10.0.0.5:3261 --login"),
            "{}",
            iscsi[1].cmd
        );
        // TCP-only keeps the standard 3260 port.
        let tcp_only = super::client_instructions(&export(false, true), addr);
        assert_eq!(tcp_only.len(), 1);
        assert!(
            tcp_only[0].cmd.contains("-p 10.0.0.5:3260 --login"),
            "{}",
            tcp_only[0].cmd
        );
    }

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::http::{Request as HttpRequest, StatusCode, header};

        #[tokio::test]
        async fn create_toggle_delete_flow_and_initiator_validation() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // iSCSI export with an IQN initiator works; the page shows iSER.
            let req = auth(form_post(
                "/iscsi/create",
                "name=tape&device=%2Fdev%2Fzvol%2Ftank%2Ftape&want_rdma=1&initiators=iqn.1993-08.org.debian%3A01%3Aabc",
            ));
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("created export tape"), "{body}");
            assert!(body.contains("dot-red"), "nothing configured yet: {body}");
            assert!(body.contains("iSER"), "{body}");
            assert!(body.contains("/iscsi/1\">Manage"), "{body}");

            // An NQN-style initiator on an iSCSI export is rejected.
            let req = auth(form_post(
                "/iscsi/create",
                "name=bad&device=%2Fdev%2Fsda&want_tcp=1&initiators=nqn.2014-08.org.nvmexpress%3Ahost1",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid initiator name"), "{body}");

            // Dashboard partial and detail page work; toggle then delete.
            let req = auth(
                HttpRequest::get("/partials/iscsi")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("tape"), "{body}");

            let req = auth(HttpRequest::get("/iscsi/1").body(Body::empty()).unwrap());
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("Client instruction"), "{body}");
            assert!(body.contains("iscsiadm"), "{body}");

            let (_, _, body) =
                send(&app, auth(form_post("/iscsi/toggle", "id=1&enable=false"))).await;
            assert!(
                body.contains("dot-gray") && body.contains("Enable"),
                "{body}"
            );

            let (status, headers, _) = send(&app, auth(form_post("/iscsi/delete", "id=1"))).await;
            assert_eq!(status, StatusCode::SEE_OTHER);
            assert_eq!(headers[header::LOCATION], "/iscsi");
            let req = auth(HttpRequest::get("/iscsi").body(Body::empty()).unwrap());
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("No iSCSI exports yet"), "{body}");
        }
    }
}
