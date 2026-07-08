//! iSCSI block-device exports — one RDMA (iSER) dot per target. Create/toggle/
//! delete mutate the desired-state TOML and run the shared reconcile; the dot
//! comes from the LIO configfs tree plus the RDMA device list, and the Clients
//! column counts live sessions. Foreign targets (outside our IQN prefix, e.g.
//! democratic-csi) are surfaced read-only with an honest, observed-transport dot.

use super::block_export::{
    self, ClientCmd, CreateFields, DiagnoseView, ExportDetailView, ExportProtocol, ExportRow,
    ExportsView, capable_disabled_nics, diagnose_not_found, dot_class, gather_view, hosts_cell,
    join_devices, listen_addr, managed_dot, render_diagnose,
};
use super::{AppState, page};
use crate::actual;
use crate::auth::CurrentUser;
use crate::dot::{external_iscsi_dot, iscsi_diagnostics, iscsi_dot};
use crate::state::{Db, NewIscsiExport};
use askama::Template;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DevicePath, ExportName, Iqn, OUR_IQN_PREFIX};
use std::net::IpAddr;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/iscsi", get(iscsi_page))
        .route("/iscsi/create", post(block_export::create::<Iscsi>))
        .route("/iscsi/{id}", get(detail_page))
        .route("/iscsi/toggle", post(block_export::toggle::<Iscsi>))
        .route(
            "/iscsi/interfaces",
            post(block_export::edit_interfaces::<Iscsi>),
        )
        .route("/iscsi/delete", post(block_export::delete::<Iscsi>))
        .route("/iscsi/{id}/diagnose", get(diagnose_page))
        .route("/partials/iscsi", get(dots_partial))
}

/// The iSCSI bindings for the shared export handlers.
struct Iscsi;

impl ExportProtocol for Iscsi {
    const LIST_PATH: &'static str = "/iscsi";

    async fn gather(
        state: &AppState,
        flash: Option<String>,
        form_error: Option<String>,
        task_id: Option<i64>,
    ) -> ExportsView {
        // Actual state comes from the daemon (configfs/sysfs reads); fetch it up
        // front so the sync row-builder closure can just render it.
        let actual_lio = actual::lio::read(&state.helper).await;
        let sessions = actual::lio::sessions(&state.helper).await;
        let rdma = actual::rdma::devices(&state.helper).await;
        let pci_addrs = actual::nic::pci_addrs(&state.helper).await;
        gather_view(state, flash, form_error, task_id, move |reconcile_task| {
            let listen = listen_addr(state);
            let (mut rows, error): (Vec<ExportRow>, Option<String>) =
                match state.db.list_iscsi_exports() {
                    Ok(exports) => (
                        exports
                            .iter()
                            .map(|e| {
                                let (dot_class_, dot_reason, diagnose, row_task) =
                                    managed_dot(e.enabled, e.want_rdma, reconcile_task, || {
                                        iscsi_dot(e, &actual_lio, &rdma)
                                    });
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
                                    hosts: hosts_cell(e.allow_any_host, e.initiators.len()),
                                    clients: Some(
                                        sessions
                                            .iter()
                                            .filter(|s| s.target_iqn == iqn.as_str())
                                            .count(),
                                    ),
                                    enabled: e.enabled,
                                    diagnose,
                                    client: client_instructions(
                                        e,
                                        &crate::reconcile::listen_addrs(
                                            &e.interfaces,
                                            listen,
                                            &pci_addrs,
                                        ),
                                    ),
                                    external: false,
                                    task_id: row_task,
                                }
                            })
                            .collect(),
                        None,
                    ),
                    Err(e) => (vec![], Some(format!("could not read export store: {e:#}"))),
                };
            // Foreign targets present on the box that greendot didn't create —
            // observed read-only with the same honest RDMA dot.
            rows.extend(foreign_iscsi_rows(&actual_lio, &sessions, &rdma));
            (rows, error)
        })
        .await
    }

    fn initiator_ok(i: &str) -> bool {
        Iqn::new(i.to_owned()).is_ok()
    }

    fn has_transport(f: &CreateFields) -> bool {
        f.want_rdma || f.want_tcp
    }

    fn insert(
        db: &Db,
        name: &ExportName,
        device: &DevicePath,
        allow_any_host: bool,
        initiators: Vec<String>,
        f: CreateFields,
    ) -> anyhow::Result<()> {
        db.insert_iscsi_export(&NewIscsiExport {
            name: name.to_string(),
            device_path: device.to_string(),
            want_rdma: f.want_rdma,
            want_tcp: f.want_tcp,
            allow_any_host,
            initiators,
            interfaces: f.interfaces,
        })
        .map(|_| ())
    }

    fn render_list_partial(view: ExportsView) -> Response {
        page(IscsiPartial { view })
    }

    fn render_detail_partial(view: ExportDetailView) -> Response {
        page(IscsiDetailPartial { view })
    }

    fn stored_interfaces(db: &Db, id: i64) -> Vec<String> {
        db.list_iscsi_exports()
            .ok()
            .and_then(|es| es.into_iter().find(|e| e.id == id))
            .map(|e| e.interfaces)
            .unwrap_or_default()
    }

    fn set_enabled(db: &Db, id: i64, enable: bool) -> anyhow::Result<()> {
        db.set_iscsi_export_enabled(id, enable)
    }

    fn set_interfaces(db: &Db, id: i64, interfaces: &[String]) -> anyhow::Result<()> {
        db.set_iscsi_export_interfaces(id, interfaces)
    }

    fn delete(db: &Db, id: i64) -> anyhow::Result<()> {
        db.delete_iscsi_export(id)
    }
}

/// Builds the client connect command(s) for an iSCSI export. Ports mirror the
/// server side in [`crate::reconcile`]: iSER on 3260, plain TCP on 3261 when
/// iSER is also on (else 3260). `addrs` are the export's resolved listen IPs;
/// the first concrete one is advertised, falling back to a `<server-ip>`
/// placeholder when none is concrete.
fn client_instructions(e: &crate::state::IscsiExport, addrs: &[IpAddr]) -> Vec<ClientCmd> {
    let addr = addrs
        .iter()
        .find(|a| !a.is_unspecified())
        .map_or_else(|| "<server-ip>".to_owned(), ToString::to_string);
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
                hosts: hosts_cell(t.demo_mode, t.acls.len()),
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

#[derive(Template)]
#[template(path = "iscsi.html")]
struct IscsiTemplate {
    user: CurrentUser,
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_iscsi.html")]
struct IscsiPartial {
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_iscsi_dots.html")]
struct IscsiDotsPartial {
    view: ExportsView,
}

// ---- Per-export page (client instructions + enable/disable/delete) ----

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

async fn detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(IscsiDetailTemplate {
        user,
        view: block_export::gather_detail::<Iscsi>(&state, id, None, None, None).await,
    })
}

async fn gather_diagnose(state: &AppState, id: i64) -> DiagnoseView {
    let export = state
        .db
        .list_iscsi_exports()
        .ok()
        .and_then(|exports| exports.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return diagnose_not_found("iSCSI", "/iscsi");
    };
    let rdma = actual::rdma::devices(&state.helper).await;
    let capable_disabled = capable_disabled_nics(state).await;
    let lio = actual::lio::read(&state.helper).await;
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
        view: Iscsi::gather(&state, None, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(IscsiDotsPartial {
        view: Iscsi::gather(&state, None, None, None).await,
    })
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
            interfaces: vec![],
            last_error: None,
        };
        let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();

        // iSER on 3260, plain TCP bumped to 3261 because iSER is also on; each is
        // a discovery + login pair against the derived IQN.
        let iscsi = super::client_instructions(&export(true, true), &[addr]);
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
        let tcp_only = super::client_instructions(&export(false, true), &[addr]);
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
