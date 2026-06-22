//! NVMe-oF block-device exports — one RDMA dot per subsystem. Create/toggle/
//! delete mutate the desired-state TOML and run the shared reconcile; the dot
//! comes from the nvmet configfs tree plus the RDMA device list. Foreign
//! subsystems (outside our NQN prefix, e.g. democratic-csi) are surfaced
//! read-only with an honest, observed-transport dot.

use super::block_export::{
    ClientCmd, DiagnoseView, ExportRow, dot_class, join_devices, listen_addr, reconcile_state,
    render_diagnose,
};
use super::{AppState, page};
use crate::actual;
use crate::auth::{CurrentUser, nav_redirect};
use crate::dot::{external_nvme_dot, nvme_diagnostics, nvme_dot};
use crate::reconcile::RECONCILE_ERROR_KEY;
use crate::state::NewNvmeExport;
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DevicePath, DotState, ExportName, Nqn, OUR_NQN_PREFIX};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/nvme", get(nvme_page))
        .route("/nvme/create", post(create))
        .route("/nvme/{id}", get(detail_page))
        .route("/nvme/toggle", post(toggle))
        .route("/nvme/delete", post(delete))
        .route("/nvme/{id}/diagnose", get(diagnose_page))
        .route("/partials/nvme", get(dots_partial))
}

/// Builds the per-transport `nvme connect` command(s) for an export. Ports
/// mirror the server side in [`crate::reconcile`] (`TRSVCID` 4420); the `loop`
/// transport is local-only testing and is omitted. An unspecified listen
/// address (the default — all interfaces) renders a `<server-ip>` placeholder.
fn client_instructions(e: &crate::state::NvmeExport, listen: IpAddr) -> Vec<ClientCmd> {
    let addr = if listen.is_unspecified() {
        "<server-ip>".to_owned()
    } else {
        listen.to_string()
    };
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
                hosts: if s.allow_any_host {
                    "any host".into()
                } else {
                    format!("{} allowed", s.allowed_hosts.len())
                },
                clients: None,
                enabled: true,
                diagnose: false,
                client: vec![],
                external: true,
            }
        })
        .collect()
}

pub struct NvmeExportsView {
    pub rows: Vec<ExportRow>,
    pub devices: Vec<actual::block::AvailDevice>,
    pub banner: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

pub async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
) -> NvmeExportsView {
    let mut view = NvmeExportsView {
        rows: vec![],
        devices: vec![],
        banner: None,
        flash,
        form_error,
    };
    let actual_nvmet = actual::nvmet::read(&state.nvmet_root);
    let rdma = actual::rdma::devices();
    let listen = listen_addr(state);
    match state.db.list_nvme_exports() {
        Ok(exports) => {
            view.rows = exports
                .iter()
                .map(|e| {
                    let (dot_class_, dot_reason, diagnose) = if !e.enabled {
                        ("dot-gray", "disabled".to_owned(), false)
                    } else {
                        let dot = nvme_dot(e, &actual_nvmet, &rdma);
                        (
                            dot_class(dot.state),
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
                        clients: None,
                        enabled: e.enabled,
                        diagnose,
                        client: client_instructions(e, listen),
                        external: false,
                    }
                })
                .collect();
        }
        Err(e) => view.banner = Some(format!("could not read export store: {e:#}")),
    }

    // Foreign subsystems present on the box that greendot didn't create — observed
    // read-only with the same honest RDMA dot.
    view.rows.extend(foreign_nvme_rows(&actual_nvmet, &rdma));
    if let Ok(Some(err)) = state.db.get_setting(RECONCILE_ERROR_KEY)
        && !err.is_empty()
    {
        view.banner = Some(format!("reconcile problem: {err}"));
    }
    let in_use: HashSet<String> = state.db.export_device_paths().into_iter().collect();
    view.devices = actual::block::available_block_devices(&state.helper, &in_use).await;
    view
}

#[derive(Template)]
#[template(path = "nvme.html")]
struct NvmeTemplate {
    user: CurrentUser,
    view: NvmeExportsView,
}

#[derive(Template)]
#[template(path = "_nvme.html")]
struct NvmePartial {
    view: NvmeExportsView,
}

#[derive(Template)]
#[template(path = "_nvme_dots.html")]
struct NvmeDotsPartial {
    view: NvmeExportsView,
}

// ---- Per-export page (client instructions + enable/disable/delete) ----

pub struct ExportDetailView {
    pub name: String,
    /// `None` when the export id is unknown (or belongs to a foreign export).
    pub row: Option<ExportRow>,
    pub banner: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

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

/// Re-reads live state via [`gather`] and picks out the one managed export, so
/// the detail page shows the same dot/transports/client commands as the list.
async fn gather_detail(
    state: &AppState,
    id: i64,
    flash: Option<String>,
    form_error: Option<String>,
) -> ExportDetailView {
    let view = gather(state, flash, form_error).await;
    let row = view.rows.into_iter().find(|r| r.id == id && !r.external);
    ExportDetailView {
        name: row
            .as_ref()
            .map_or_else(|| id.to_string(), |r| r.name.clone()),
        row,
        banner: view.banner,
        flash: view.flash,
        form_error: view.form_error,
    }
}

async fn detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(NvmeDetailTemplate {
        user,
        view: gather_detail(&state, id, None, None).await,
    })
}

async fn gather_diagnose(state: &AppState, id: i64) -> DiagnoseView {
    let export = state
        .db
        .list_nvme_exports()
        .ok()
        .and_then(|exports| exports.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return DiagnoseView {
            name: String::new(),
            protocol: "NVMe-oF",
            dot_class: "dot-gray",
            dot_reason: String::new(),
            criteria: vec![],
            not_found: true,
            back_href: "/nvme",
        };
    };
    let rdma = actual::rdma::devices();
    // NICs that are RoCE-capable but have RoCE switched off — surfaced when no
    // RDMA device exists, so the checklist explains why and points at Settings.
    let capable_disabled: Vec<String> = actual::nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter(|n| matches!(n.kind, actual::nic::NicRdmaKind::CapableDisabled { .. }))
        .map(|n| n.netdev)
        .collect();
    let nvmet = actual::nvmet::read(&state.nvmet_root);
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
        view: gather(&state, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(NvmeDotsPartial {
        view: gather(&state, None, None).await,
    })
}

async fn finish(state: &AppState, result: anyhow::Result<()>, success: String) -> Response {
    let (flash, error) = match result {
        Ok(()) => (Some(success), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(NvmePartial {
        view: gather(state, flash, error).await,
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
    want_loop: Option<String>,
    #[serde(default)]
    allow_any_host: Option<String>,
    #[serde(default)]
    initiators: String,
}

async fn create(State(state): State<Arc<AppState>>, Form(form): Form<CreateForm>) -> Response {
    let view_err = |msg: String| async {
        page(NvmePartial {
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
    let initiators: Vec<String> = form
        .initiators
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(Into::into)
        .collect();
    if let Some(bad) = initiators.iter().find(|i| Nqn::new((*i).clone()).is_err()) {
        return view_err(format!("invalid initiator name {bad:?}")).await;
    }
    let allow_any_host = form.allow_any_host.is_some() || initiators.is_empty();
    if !(form.want_rdma.is_some() || form.want_tcp.is_some() || form.want_loop.is_some()) {
        return view_err("select at least one transport".into()).await;
    }
    let new = NewNvmeExport {
        name: name.to_string(),
        device_path: device.to_string(),
        want_rdma: form.want_rdma.is_some(),
        want_tcp: form.want_tcp.is_some(),
        want_loop: form.want_loop.is_some(),
        allow_any_host,
        initiators,
    };
    let result = match state.db.insert_nvme_export(&new) {
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
    let (flash, error) = match state.db.set_nvme_export_enabled(form.id, enable) {
        Ok(()) => match reconcile_state(&state).await {
            Ok(()) => (Some(success), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        },
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(NvmeDetailPartial {
        view: gather_detail(&state, form.id, flash, error).await,
    })
}

/// Deleting an export removes its page, so on success redirect back to the list;
/// a failed DB delete leaves the row in place and re-renders the detail partial.
async fn delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Response {
    match state.db.delete_nvme_export(form.id) {
        Ok(()) => {
            // A reconcile failure surfaces on the /nvme banner, not here.
            let _ = reconcile_state(&state).await;
            nav_redirect(&headers, "/nvme")
        }
        Err(e) => page(NvmeDetailPartial {
            view: gather_detail(&state, form.id, None, Some(format!("{e:#}"))).await,
        }),
    }
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
            last_error: None,
        };
        let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();

        // One block per network transport (loop omitted), each with its fabrics
        // module prerequisite, the connect (derived NQN, port 4420, the concrete
        // listen address), and a disconnect hint.
        let nvme = super::client_instructions(&export(true, true), addr);
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
        let unspec = super::client_instructions(&export(true, false), Ipv4Addr::UNSPECIFIED.into());
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
