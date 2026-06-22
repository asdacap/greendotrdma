//! NFS file shares served over RDMA. Mirrors the Exports page (own RDMA dot per
//! share) but for directory paths rather than block devices. Create/toggle/delete
//! mutate the desired-state TOML and run the shared reconcile; actual state and
//! the green dot come from the helper's `NfsReport` (root-only reads) + the RDMA
//! device list.

use super::{AppState, page};
use crate::actual;
use crate::auth::CurrentUser;
use crate::dot::{Criterion, external_nfs_dot, nfs_diagnostics, nfs_dot};
use crate::reconcile::RECONCILE_ERROR_KEY;
use crate::routes::block_export::reconcile_state;
use crate::state::{NewNfsExport, NfsClientEntry};
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DotState, NFS_RDMA_PORT, NfsClient, NfsExportPath};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/nfs", get(nfs_page))
        .route("/nfs/create", post(create))
        .route("/nfs/toggle", post(toggle))
        .route("/nfs/delete", post(delete))
        .route("/nfs/{id}/diagnose", get(diagnose_page))
        .route("/partials/nfs", get(dots_partial))
}

pub struct NfsRow {
    pub id: i64,
    pub path: String,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub clients: String,
    pub enabled: bool,
    /// RDMA isn't fully serving this share — offer the Diagnose page.
    pub diagnose: bool,
    /// Copy-paste client mount command.
    pub mount_cmd: String,
    /// Present in the export table but not managed by greendot.
    pub external: bool,
}

fn dot_class(state: DotState) -> &'static str {
    match state {
        DotState::Green => "dot-green",
        DotState::Yellow => "dot-yellow",
        DotState::Red => "dot-red",
    }
}

/// Summarizes an export's allowed clients, e.g. `192.168.101.0/24 (rw), * (ro)`.
fn clients_summary(clients: &[NfsClientEntry]) -> String {
    if clients.is_empty() {
        return "—".to_owned();
    }
    clients
        .iter()
        .map(|c| format!("{} ({})", c.client, if c.rw { "rw" } else { "ro" }))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The copy-paste command a client runs to mount the share over RDMA. Ports
/// mirror the server side ([`NFS_RDMA_PORT`]). When `listen` is unspecified the
/// service listens on all interfaces, so a `<server-ip>` placeholder is shown.
fn nfs_client_cmd(path: &str, listen: IpAddr) -> String {
    let addr = if listen.is_unspecified() {
        "<server-ip>".to_owned()
    } else {
        listen.to_string()
    };
    format!(
        "modprobe rpcrdma\n\
         mount -o rdma,port={NFS_RDMA_PORT} {addr}:{path} /mnt\n\
         # unmount: umount /mnt"
    )
}

pub struct NfsView {
    pub rows: Vec<NfsRow>,
    pub banner: Option<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

fn listen_addr(state: &AppState) -> IpAddr {
    state
        .db
        .get_setting("listen_addr")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into())
}

pub async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
) -> NfsView {
    let mut view = NfsView {
        rows: vec![],
        banner: None,
        flash,
        form_error,
    };
    let actual_nfs = actual::nfs::read(&state.helper).await;
    let rdma = actual::rdma::devices();
    let listen = listen_addr(state);
    let mut ours: HashSet<String> = HashSet::new();

    match state.db.list_nfs_exports() {
        Ok(exports) => {
            ours.extend(exports.iter().map(|e| e.path.clone()));
            view.rows = exports
                .iter()
                .map(|e| {
                    let (dot_class, dot_reason, diagnose) = if !e.enabled {
                        ("dot-gray", "disabled".to_owned(), false)
                    } else {
                        let dot = nfs_dot(e, &actual_nfs, &rdma, listen);
                        (
                            dot_class(dot.state),
                            dot.reason,
                            dot.state != DotState::Green,
                        )
                    };
                    NfsRow {
                        id: e.id,
                        path: e.path.clone(),
                        dot_class,
                        dot_reason,
                        clients: clients_summary(&e.clients),
                        enabled: e.enabled,
                        diagnose,
                        mount_cmd: nfs_client_cmd(&e.path, listen),
                        external: false,
                    }
                })
                .collect();
        }
        Err(e) => view.banner = Some(format!("could not read NFS export store: {e:#}")),
    }

    // Foreign exports: paths in the export table greendot didn't create. Observed
    // read-only, with a dot that reports only the actual transport.
    for entry in &actual_nfs.exports {
        if ours.contains(&entry.path) {
            continue;
        }
        let dot = external_nfs_dot(&actual_nfs, &rdma, listen);
        view.rows.push(NfsRow {
            id: 0,
            path: entry.path.clone(),
            dot_class: dot_class(dot.state),
            dot_reason: dot.reason,
            clients: if entry.clients.is_empty() {
                "—".to_owned()
            } else {
                entry.clients.join(", ")
            },
            enabled: true,
            diagnose: false,
            mount_cmd: nfs_client_cmd(&entry.path, listen),
            external: true,
        });
    }

    if let Ok(Some(err)) = state.db.get_setting(RECONCILE_ERROR_KEY)
        && !err.is_empty()
    {
        view.banner = Some(format!("reconcile problem: {err}"));
    }
    view
}

#[derive(Template)]
#[template(path = "nfs.html")]
struct NfsTemplate {
    user: CurrentUser,
    view: NfsView,
}

#[derive(Template)]
#[template(path = "_nfs.html")]
struct NfsPartial {
    view: NfsView,
}

pub struct NfsDiagnoseView {
    pub path: String,
    pub dot_class: &'static str,
    pub dot_reason: String,
    pub criteria: Vec<Criterion>,
    pub not_found: bool,
}

#[derive(Template)]
#[template(path = "nfs_diagnose.html")]
struct NfsDiagnoseTemplate {
    user: CurrentUser,
    view: NfsDiagnoseView,
}

async fn gather_diagnose(state: &AppState, id: i64) -> NfsDiagnoseView {
    let export = state
        .db
        .list_nfs_exports()
        .ok()
        .and_then(|es| es.into_iter().find(|e| e.id == id));
    let Some(export) = export else {
        return NfsDiagnoseView {
            path: String::new(),
            dot_class: "dot-gray",
            dot_reason: String::new(),
            criteria: vec![],
            not_found: true,
        };
    };
    let actual_nfs = actual::nfs::read(&state.helper).await;
    let rdma = actual::rdma::devices();
    let capable_disabled: Vec<String> = actual::nic::interfaces()
        .into_iter()
        .filter(|n| matches!(n.kind, actual::nic::NicRdmaKind::CapableDisabled { .. }))
        .map(|n| n.netdev)
        .collect();
    let listen = listen_addr(state);
    let criteria = nfs_diagnostics(&export, &actual_nfs, &rdma, &capable_disabled, listen);
    let dot = nfs_dot(&export, &actual_nfs, &rdma, listen);
    NfsDiagnoseView {
        path: export.path,
        dot_class: dot_class(dot.state),
        dot_reason: dot.reason,
        criteria,
        not_found: false,
    }
}

async fn nfs_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(NfsTemplate {
        user,
        view: gather(&state, None, None).await,
    })
}

async fn dots_partial(State(state): State<Arc<AppState>>) -> Response {
    page(NfsPartial {
        view: gather(&state, None, None).await,
    })
}

async fn diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(NfsDiagnoseTemplate {
        user,
        view: gather_diagnose(&state, id).await,
    })
}

async fn finish(state: &AppState, result: anyhow::Result<()>, success: String) -> Response {
    let (flash, error) = match result {
        Ok(()) => (Some(success), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(NfsPartial {
        view: gather(state, flash, error).await,
    })
}

#[derive(Deserialize)]
struct CreateForm {
    path: String,
    #[serde(default)]
    clients: String,
    #[serde(default)]
    readonly: Option<String>,
}

async fn create(State(state): State<Arc<AppState>>, Form(form): Form<CreateForm>) -> Response {
    let view_err = |msg: String| async {
        page(NfsPartial {
            view: gather(&state, None, Some(msg)).await,
        })
    };
    let Ok(path) = NfsExportPath::new(form.path.trim()) else {
        return view_err(format!(
            "invalid export path {:?} (absolute, no traversal)",
            form.path
        ))
        .await;
    };
    let rw = form.readonly.is_none();
    let mut clients = Vec::new();
    for line in form
        .clients
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        match NfsClient::new(line) {
            Ok(c) => clients.push(NfsClientEntry {
                client: c.to_string(),
                rw,
            }),
            Err(_) => return view_err(format!("invalid client spec {line:?}")).await,
        }
    }
    if clients.is_empty() {
        return view_err("add at least one client (host, IP, CIDR, or *)".into()).await;
    }
    let new = NewNfsExport {
        path: path.to_string(),
        clients,
    };
    let result = match state.db.insert_nfs_export(&new) {
        Ok(_) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(&state, result, format!("created NFS export {path}")).await
}

#[derive(Deserialize)]
struct IdForm {
    id: i64,
    #[serde(default)]
    enable: Option<bool>,
}

async fn toggle(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let enable = form.enable.unwrap_or(false);
    let result = match state.db.set_nfs_export_enabled(form.id, enable) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(
        &state,
        result,
        format!("NFS export {}", if enable { "enabled" } else { "disabled" }),
    )
    .await
}

async fn delete(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let result = match state.db.delete_nfs_export(form.id) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    finish(&state, result, "NFS export deleted".into()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn client_cmd_and_summary() {
        let cmd = nfs_client_cmd("/tank/share", Ipv4Addr::new(10, 0, 0, 5).into());
        assert!(cmd.contains("modprobe rpcrdma"), "{cmd}");
        assert!(
            cmd.contains("mount -o rdma,port=20049 10.0.0.5:/tank/share /mnt"),
            "{cmd}"
        );
        // Unspecified listen → placeholder.
        let cmd = nfs_client_cmd("/srv/x", Ipv4Addr::UNSPECIFIED.into());
        assert!(cmd.contains("<server-ip>:/srv/x"), "{cmd}");

        assert_eq!(clients_summary(&[]), "—");
        assert_eq!(
            clients_summary(&[
                NfsClientEntry {
                    client: "192.168.101.0/24".into(),
                    rw: true
                },
                NfsClientEntry {
                    client: "*".into(),
                    rw: false
                },
            ]),
            "192.168.101.0/24 (rw), * (ro)"
        );
    }

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::http::{Request as HttpRequest, StatusCode, header};

        #[tokio::test]
        async fn create_toggle_delete_flow_and_validation() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // Create a share with one client.
            let (status, _, body) = send(
                &app,
                auth(form_post(
                    "/nfs/create",
                    "path=%2Ftank%2Fshare&clients=192.168.101.0%2F24",
                )),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("created NFS export /tank/share"), "{body}");
            // The fake helper's NfsReport reports nothing exported yet → red dot
            // (reconcile pending), like the NVMe-oF create test.
            assert!(body.contains("dot-red"), "{body}");
            assert!(body.contains("mount -o rdma,port=20049"), "{body}");

            // Invalid path is rejected before the helper.
            let (_, _, body) = send(
                &app,
                auth(form_post("/nfs/create", "path=tank%2Fshare&clients=*")),
            )
            .await;
            assert!(body.contains("invalid export path"), "{body}");

            // No client is rejected.
            let (_, _, body) = send(
                &app,
                auth(form_post("/nfs/create", "path=%2Fsrv%2Fx&clients=")),
            )
            .await;
            assert!(body.contains("at least one client"), "{body}");

            // Partial lists the share.
            let req = auth(
                HttpRequest::get("/partials/nfs")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("/tank/share"), "{body}");

            // Toggle off → gray; delete → gone.
            let (_, _, body) =
                send(&app, auth(form_post("/nfs/toggle", "id=1&enable=false"))).await;
            assert!(body.contains("dot-gray"), "{body}");
            let (_, _, body) = send(&app, auth(form_post("/nfs/delete", "id=1"))).await;
            assert!(body.contains("No NFS exports yet"), "{body}");
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
                auth(form_post("/nfs/create", "path=%2Ftank%2Fshare&clients=*")),
            )
            .await;

            let req = auth(
                HttpRequest::get("/nfs/1/diagnose")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("Path exported by nfsd"), "{body}");
            assert!(body.contains("nfsd RDMA listener active"), "{body}");

            let req = auth(
                HttpRequest::get("/nfs/999/diagnose")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("not found"), "{body}");
        }
    }
}
