//! Live connected-client monitoring. iSCSI sessions come straight from the LIO
//! configfs tree (unprivileged). NVMe-oF has no per-NQN connection interface on
//! a kernel without CONFIG_NVME_TARGET_DEBUGFS, so we surface best-effort RDMA
//! peers (peer IP only) via the `rdma` tool, attributed to the NVMe-oF RDMA
//! listen ports — see the note rendered on the page.

use super::{AppState, page};
use crate::actual;
use crate::auth::CurrentUser;
use askama::Template;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use greendot_proto::{NFS_RDMA_PORT, Request};
use std::collections::HashSet;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/connections", get(connections_page))
        .route("/partials/connections", get(connections_partial))
}

pub struct IscsiRow {
    /// Friendly export name when the target is one of ours, else the raw IQN.
    pub export: String,
    pub target_iqn: String,
    pub initiator_iqn: String,
}

pub struct NvmeRow {
    /// Local listen `addr:port` (or bare addr when no port was reported).
    pub listen: String,
    /// Connected peer IP.
    pub peer: String,
    pub state: String,
}

pub struct ConnectionsView {
    pub iscsi: Vec<IscsiRow>,
    pub nvme: Vec<NvmeRow>,
    /// True when an NVMe-oF RDMA export exists but the helper's `rdma` read
    /// failed — render "unavailable" rather than a misleading empty table.
    pub nvme_unavailable: bool,
    /// NFS-over-RDMA peers (port 20049), same shape as NVMe peers.
    pub nfs: Vec<NvmeRow>,
    pub nfs_unavailable: bool,
}

async fn gather_connections(state: &AppState) -> ConnectionsView {
    let nvme_exports = state.db.list_nvme_exports().unwrap_or_default();
    let iscsi_exports = state.db.list_iscsi_exports().unwrap_or_default();

    // iSCSI sessions: configfs, unprivileged. Map each target IQN back to its
    // friendly export name when it's one of ours.
    let iscsi = actual::lio::sessions(&state.lio_root)
        .into_iter()
        .map(|s| {
            let export = iscsi_exports
                .iter()
                .find(|e| e.iqn().as_str() == s.target_iqn)
                .map_or_else(|| s.target_iqn.clone(), |e| e.name.clone());
            IscsiRow {
                export,
                target_iqn: s.target_iqn,
                initiator_iqn: s.initiator_iqn,
            }
        })
        .collect();

    // NVMe-oF: best-effort RDMA peers. Only worth the helper round-trip when an
    // enabled NVMe-oF RDMA export exists. A peer can't be tied to a subsystem,
    // only to a listen port, so we keep peers whose local port is one of the
    // nvmet RDMA ports (which also excludes iSER peers on 3260).
    let has_nvme = nvme_exports.iter().any(|e| e.enabled && e.want_rdma);
    let has_nfs = state
        .db
        .list_nfs_exports()
        .map(|es| es.iter().any(|e| e.enabled))
        .unwrap_or(false);
    let mut nvme = Vec::new();
    let mut nvme_unavailable = false;
    let mut nfs = Vec::new();
    let mut nfs_unavailable = false;
    // One `rdma resource show cm_id` read serves both NVMe-oF and NFS peers.
    if has_nvme || has_nfs {
        let out = state.helper.collect(Request::RdmaResources).await;
        let peers = actual::rdma::peers_from_json(&out.stdout);
        let row = |p: &actual::rdma::RdmaPeer| NvmeRow {
            listen: match p.src_port {
                Some(port) => format!("{}:{port}", p.src_addr),
                None => p.src_addr.clone(),
            },
            peer: p.dst_addr.clone(),
            state: p.state.clone(),
        };
        if has_nvme {
            let rdma_ports: HashSet<u16> = actual::nvmet::read(&state.nvmet_root)
                .ports
                .iter()
                .filter(|p| p.trtype == "rdma")
                .filter_map(|p| p.trsvcid.parse::<u16>().ok())
                .collect();
            nvme = peers
                .iter()
                .filter(|p| p.src_port.is_some_and(|port| rdma_ports.contains(&port)))
                .map(&row)
                .collect();
            nvme_unavailable = !out.ok && nvme.is_empty();
        }
        if has_nfs {
            nfs = peers
                .iter()
                .filter(|p| p.src_port == Some(NFS_RDMA_PORT))
                .map(&row)
                .collect();
            nfs_unavailable = !out.ok && nfs.is_empty();
        }
    }

    ConnectionsView {
        iscsi,
        nvme,
        nvme_unavailable,
        nfs,
        nfs_unavailable,
    }
}

#[derive(Template)]
#[template(path = "connections.html")]
struct ConnectionsTemplate {
    user: CurrentUser,
    view: ConnectionsView,
}

#[derive(Template)]
#[template(path = "_connections.html")]
struct ConnectionsPartial {
    view: ConnectionsView,
}

async fn connections_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(ConnectionsTemplate {
        user,
        view: gather_connections(&state).await,
    })
}

async fn connections_partial(State(state): State<Arc<AppState>>) -> Response {
    page(ConnectionsPartial {
        view: gather_connections(&state).await,
    })
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[tokio::test]
    async fn connections_page_renders_sections_note_and_partial() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        // An enabled NVMe-oF RDMA export exercises the helper read path.
        send(
            &app,
            auth(form_post(
                "/nvme/create",
                "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1",
            )),
        )
        .await;

        // Both sections, the empty-state copy, and the kernel-limitation note
        // render; the (empty configfs) tree means no live sessions/peers.
        let req = auth(
            HttpRequest::get("/connections")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("iSCSI sessions"), "{body}");
        assert!(body.contains("NVMe-oF (RDMA) peers"), "{body}");
        assert!(body.contains("CONFIG_NVME_TARGET_DEBUGFS"), "{body}");

        // The poll partial returns the same body without the page chrome.
        let req = auth(
            HttpRequest::get("/partials/connections")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("NVMe-oF (RDMA) peers"), "{body}");
        assert!(
            !body.contains("<nav"),
            "partial must omit page chrome: {body}"
        );
    }
}
