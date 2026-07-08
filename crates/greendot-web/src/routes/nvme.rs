//! NVMe-oF block-device exports — one RDMA dot per subsystem. Create/toggle/
//! delete mutate the desired-state TOML and run the shared reconcile; the dot
//! comes from the nvmet configfs tree plus the RDMA device list. Foreign
//! subsystems (outside our NQN prefix, e.g. democratic-csi) are surfaced
//! read-only with an honest, observed-transport dot.

use super::block_export::{
    self, ClientCmd, CreateFields, DiagnoseView, ExportDetailView, ExportProtocol, ExportRow,
    ExportsView, capable_disabled_nics, diagnose_not_found, dot_class, gather_view, hosts_cell,
    join_devices, listen_addr, managed_dot, render_diagnose,
};
use super::{AppState, page};
use crate::actual;
use crate::auth::CurrentUser;
use crate::dot::{external_nvme_dot, nvme_diagnostics, nvme_dot};
use crate::state::{Db, NewNvmeExport};
use askama::Template;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DevicePath, ExportName, Nqn, OUR_NQN_PREFIX};
use std::net::IpAddr;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/nvme", get(nvme_page))
        .route("/nvme/create", post(block_export::create::<Nvme>))
        .route("/nvme/{id}", get(detail_page))
        .route("/nvme/toggle", post(block_export::toggle::<Nvme>))
        .route(
            "/nvme/interfaces",
            post(block_export::edit_interfaces::<Nvme>),
        )
        .route("/nvme/delete", post(block_export::delete::<Nvme>))
        .route("/nvme/{id}/diagnose", get(diagnose_page))
        .route("/partials/nvme", get(dots_partial))
}

/// The NVMe-oF bindings for the shared export handlers.
struct Nvme;

impl ExportProtocol for Nvme {
    const LIST_PATH: &'static str = "/nvme";

    async fn gather(
        state: &AppState,
        flash: Option<String>,
        form_error: Option<String>,
        task_id: Option<i64>,
    ) -> ExportsView {
        // Actual state comes from the daemon (configfs/sysfs reads); fetch it up
        // front so the sync row-builder closure can just render it.
        let actual_nvmet = actual::nvmet::read(&state.helper).await;
        let rdma = actual::rdma::devices(&state.helper).await;
        let pci_addrs = actual::nic::pci_addrs(&state.helper).await;
        gather_view(state, flash, form_error, task_id, move |reconcile_task| {
            let listen = listen_addr(state);
            let (mut rows, error): (Vec<ExportRow>, Option<String>) =
                match state.db.list_nvme_exports() {
                    Ok(exports) => (
                        exports
                            .iter()
                            .map(|e| {
                                let (dot_class_, dot_reason, diagnose, row_task) =
                                    managed_dot(e.enabled, e.want_rdma, reconcile_task, || {
                                        nvme_dot(e, &actual_nvmet, &rdma)
                                    });
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
                                ExportRow {
                                    id: e.id,
                                    name: e.name.clone(),
                                    dot_class: dot_class_,
                                    dot_reason,
                                    device: e.device_path.clone(),
                                    transports: transports.join(" + "),
                                    hosts: hosts_cell(e.allow_any_host, e.initiators.len()),
                                    clients: None,
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
            // Foreign subsystems present on the box that greendot didn't create —
            // observed read-only with the same honest RDMA dot.
            rows.extend(foreign_nvme_rows(&actual_nvmet, &rdma));
            (rows, error)
        })
        .await
    }

    fn initiator_ok(i: &str) -> bool {
        Nqn::new(i.to_owned()).is_ok()
    }

    fn has_transport(f: &CreateFields) -> bool {
        f.want_rdma || f.want_tcp || f.want_loop
    }

    fn insert(
        db: &Db,
        name: &ExportName,
        device: &DevicePath,
        allow_any_host: bool,
        initiators: Vec<String>,
        f: CreateFields,
    ) -> anyhow::Result<()> {
        db.insert_nvme_export(&NewNvmeExport {
            name: name.to_string(),
            device_path: device.to_string(),
            want_rdma: f.want_rdma,
            want_tcp: f.want_tcp,
            want_loop: f.want_loop,
            allow_any_host,
            initiators,
            interfaces: f.interfaces,
        })
        .map(|_| ())
    }

    fn render_list_partial(view: ExportsView) -> Response {
        page(NvmePartial { view })
    }

    fn render_detail_partial(view: ExportDetailView) -> Response {
        page(NvmeDetailPartial { view })
    }

    fn stored_interfaces(db: &Db, id: i64) -> Vec<String> {
        db.list_nvme_exports()
            .ok()
            .and_then(|es| es.into_iter().find(|e| e.id == id))
            .map(|e| e.interfaces)
            .unwrap_or_default()
    }

    fn set_enabled(db: &Db, id: i64, enable: bool) -> anyhow::Result<()> {
        db.set_nvme_export_enabled(id, enable)
    }

    fn set_interfaces(db: &Db, id: i64, interfaces: &[String]) -> anyhow::Result<()> {
        db.set_nvme_export_interfaces(id, interfaces)
    }

    fn delete(db: &Db, id: i64) -> anyhow::Result<()> {
        db.delete_nvme_export(id)
    }
}

/// Builds the per-transport `nvme connect` command(s) for an export. Ports
/// mirror the server side in [`crate::reconcile`] (`TRSVCID` 4420); the `loop`
/// transport is local-only testing and is omitted. `addrs` are the export's
/// resolved listen IPs; the first concrete one is advertised, falling back to a
/// `<server-ip>` placeholder when none is concrete (unspecified default, or a
/// pinned interface with no current IP).
fn client_instructions(e: &crate::state::NvmeExport, addrs: &[IpAddr]) -> Vec<ClientCmd> {
    let addr = addrs
        .iter()
        .find(|a| !a.is_unspecified())
        .map_or_else(|| "<server-ip>".to_owned(), ToString::to_string);
    let nqn = e.nqn();
    // Each transport needs its own fabrics module loaded first, or the connect
    // fails with "/dev/nvme-fabrics: No such file or directory".
    [
        (e.want_rdma, "rdma", "RDMA", "nvme-rdma"),
        (e.want_tcp, "tcp", "TCP", "nvme-tcp"),
    ]
    .into_iter()
    .filter(|(want, ..)| *want)
    .map(|(_, trtype, label, module)| ClientCmd {
        label: label.to_owned(),
        cmd: format!(
            "modprobe {module}\n\
             nvme connect -t {trtype} -a {addr} -s 4420 -n {nqn}\n\
             # disconnect: nvme disconnect -n {nqn}"
        ),
    })
    .collect()
}

/// Rows for NVMe-oF subsystems present in nvmet but outside greendot's NQN
/// prefix. Their dot reflects only the observed transport (see [`external_nvme_dot`]).
fn foreign_nvme_rows(
    actual: &actual::nvmet::ActualNvmet,
    rdma: &[actual::rdma::RdmaDev],
) -> Vec<ExportRow> {
    actual
        .subsystems
        .iter()
        .filter(|s| !s.nqn.starts_with(OUR_NQN_PREFIX))
        .map(|s| {
            let dot = external_nvme_dot(&s.nqn, actual, rdma);
            let mut transports: Vec<&str> = actual
                .ports
                .iter()
                .filter(|p| p.subsystems.iter().any(|n| n == &s.nqn))
                .map(|p| match p.trtype.as_str() {
                    "rdma" => "RDMA",
                    "tcp" => "TCP",
                    "loop" => "loop",
                    other => other,
                })
                .collect();
            transports.sort_unstable();
            transports.dedup();
            ExportRow {
                id: 0,
                name: s.nqn.clone(),
                dot_class: dot_class(dot.state),
                dot_reason: dot.reason,
                device: join_devices(s.namespaces.iter().map(|n| n.device_path.as_str())),
                transports: transports.join(" + "),
                hosts: hosts_cell(s.allow_any_host, s.allowed_hosts.len()),
                clients: None,
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
#[template(path = "nvme.html")]
struct NvmeTemplate {
    user: CurrentUser,
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_nvme.html")]
struct NvmePartial {
    view: ExportsView,
}

#[derive(Template)]
#[template(path = "_nvme_dots.html")]
struct NvmeDotsPartial {
    view: ExportsView,
}

// ---- Per-export page (client instructions + enable/disable/delete) ----

#[derive(Template)]
#[template(path = "nvme_detail.html")]
struct NvmeDetailTemplate {
    user: CurrentUser,
    view: ExportDetailView,
}

#[derive(Template)]
#[template(path = "_nvme_detail.html")]
struct NvmeDetailPartial {
    view: ExportDetailView,
}

async fn detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(NvmeDetailTemplate {
        user,
        view: block_export::gather_detail::<Nvme>(&state, id, None, None, None).await,
    })
}

async fn gather_diagnose(state: &AppState, id: i64) -> DiagnoseView {
    let export = state
        .db
        .list_nvme_exports()
        .ok()
        .and_then(|exports| exports.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return diagnose_not_found("NVMe-oF", "/nvme");
    };
    let rdma = actual::rdma::devices(&state.helper).await;
    let capable_disabled = capable_disabled_nics(state).await;
    let nvmet = actual::nvmet::read(&state.helper).await;
    let criteria = nvme_diagnostics(&export, &nvmet, &rdma, &capable_disabled);
    let dot = nvme_dot(&export, &nvmet, &rdma);
    DiagnoseView {
        name: export.name,
        protocol: "NVMe-oF",
        dot_class: dot_class(dot.state),
        dot_reason: dot.reason,
        criteria,
        not_found: false,
        back_href: "/nvme",
    }
}

async fn diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    render_diagnose(user, gather_diagnose(&state, id).await)
}

async fn nvme_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(NvmeTemplate {
        user,
        view: Nvme::gather(&state, None, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(NvmeDotsPartial {
        view: Nvme::gather(&state, None, None, None).await,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn client_instructions_per_transport_and_address() {
        use crate::state::NvmeExport;
        use std::net::{IpAddr, Ipv4Addr};

        let export = |want_rdma, want_tcp| NvmeExport {
            id: 1,
            name: "vm1".into(),
            device_path: "/dev/zvol/tank/vm1".into(),
            enabled: true,
            want_rdma,
            want_tcp,
            want_loop: true, // local-only — must never surface as a client command
            allow_any_host: true,
            initiators: vec![],
            interfaces: vec![],
            last_error: None,
        };
        let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();

        // One block per network transport (loop omitted), each with its fabrics
        // module prerequisite, the connect (derived NQN, port 4420, the concrete
        // listen address), and a disconnect hint.
        let nvme = super::client_instructions(&export(true, true), &[addr]);
        assert_eq!(nvme.len(), 2);
        for (cmd, module, trtype) in [
            (&nvme[0].cmd, "nvme-rdma", "rdma"),
            (&nvme[1].cmd, "nvme-tcp", "tcp"),
        ] {
            assert!(cmd.contains(&format!("modprobe {module}")), "{cmd}");
            assert!(
                cmd.contains(&format!(
                    "nvme connect -t {trtype} -a 10.0.0.5 -s 4420 -n nqn.2026-06.io.greendot:vm1"
                )),
                "{cmd}"
            );
            assert!(
                cmd.contains("# disconnect: nvme disconnect -n nqn.2026-06.io.greendot:vm1"),
                "{cmd}"
            );
        }

        // An unspecified listen address renders the <server-ip> placeholder.
        let unspec =
            super::client_instructions(&export(true, false), &[Ipv4Addr::UNSPECIFIED.into()]);
        assert!(
            unspec[0].cmd.contains("-a <server-ip> -s 4420"),
            "{}",
            unspec[0].cmd
        );
    }

    mod routes {
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
                "/nvme/create",
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
            // The list's action cell is just a Manage link to the row's page.
            assert!(body.contains("/nvme/1\">Manage"), "{body}");

            // An NQN-style initiator is fine; an IQN-style one is rejected.
            let req = auth(form_post(
                "/nvme/create",
                "name=bad&device=%2Fdev%2Fsda&want_tcp=1&initiators=iqn.1993-08.org.debian%3A01%3Aabc",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid initiator name"), "{body}");

            // Bad device path rejected.
            let req = auth(form_post(
                "/nvme/create",
                "name=vm2&device=%2Fetc%2Fshadow&want_tcp=1",
            ));
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("invalid device path"), "{body}");

            // Dashboard partial shows the export card.
            let req = auth(
                HttpRequest::get("/partials/nvme")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("vm1"), "{body}");

            // Toggle off stays on the export's page → its detail partial with a
            // gray dot and an "Enable" button to turn it back on.
            let (status, _, body) =
                send(&app, auth(form_post("/nvme/toggle", "id=1&enable=false"))).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("dot-gray"), "{body}");
            assert!(body.contains("Enable"), "{body}");

            // Delete is a remove-op: a plain (non-htmx) POST redirects to the list.
            let (status, headers, _) = send(&app, auth(form_post("/nvme/delete", "id=1"))).await;
            assert_eq!(status, StatusCode::SEE_OTHER);
            assert_eq!(headers[header::LOCATION], "/nvme");
            let req = auth(HttpRequest::get("/nvme").body(Body::empty()).unwrap());
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("No NVMe-oF exports yet"), "{body}");
        }

        #[tokio::test]
        async fn create_and_edit_listen_interfaces() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // Create pinning a PCI-tagged interface — the selector is accepted and
            // stored (resolution to a live IP happens at reconcile).
            let req = auth(form_post(
                "/nvme/create",
                "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_tcp=1&interfaces=pci%3A0000%3A00%3A10.0",
            ));
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("created export vm1"), "{body}");

            // A malformed selector on the edit route is rejected.
            let (_, _, body) = send(
                &app,
                auth(form_post("/nvme/interfaces", "id=1&interfaces=garbage")),
            )
            .await;
            assert!(body.contains("invalid interface selector"), "{body}");

            // A valid selector updates and reconciles (fake helper says Ok).
            let (status, _, body) = send(
                &app,
                auth(form_post(
                    "/nvme/interfaces",
                    "id=1&interfaces=pci%3A0000%3A00%3A11.0",
                )),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("listen interfaces updated"), "{body}");

            // A missing (or unparsable) id is a client error — it must not fall
            // through to export id 0 and flash success without updating anything.
            let (status, _, _) = send(
                &app,
                auth(form_post(
                    "/nvme/interfaces",
                    "interfaces=pci%3A0000%3A00%3A11.0",
                )),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }

        #[tokio::test]
        async fn detail_and_diagnose_pages() {
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
                    "/nvme/create",
                    "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1&want_tcp=1",
                )),
            )
            .await;

            // The row page carries the moved controls.
            let req = auth(HttpRequest::get("/nvme/1").body(Body::empty()).unwrap());
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("Client instruction"), "{body}");
            assert!(body.contains("nvme connect"), "{body}");
            assert!(
                body.contains("Disable") && body.contains("Delete"),
                "{body}"
            );

            // Unknown ids are graceful not-found, not 500s.
            let req = auth(HttpRequest::get("/nvme/999").body(Body::empty()).unwrap());
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("not found"), "{body}");

            // Diagnose checklist renders; config rows fail (empty configfs tree).
            let req = auth(
                HttpRequest::get("/nvme/1/diagnose")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("RDMA requested"), "{body}");
            assert!(body.contains("Subsystem configured"), "{body}");
            assert!(body.contains("Listen address served"), "{body}");

            let req = auth(
                HttpRequest::get("/nvme/999/diagnose")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("not found"), "{body}");
        }
    }
}
