//! The token-authenticated JSON API for the greendot-client app, nested at
//! `/api/client/v1` *outside* the cookie/CSRF middleware (like `/metrics`).
//! Auth is `Authorization: Bearer <token>` checked against the hashed tokens
//! from the Client access page. A client can list exports and register itself
//! — its host NQN into an NVMe export's initiators, or its observed peer IP
//! into an NFS export's clients — through the same desired-state setters and
//! background-reconcile flow the HTML routes use.

use super::block_export::{listen_addr, reconcile_state};
use super::{AppState, client_access};
use crate::actual;
use crate::state::NfsClientEntry;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use greendot_proto::{NFS_RDMA_PORT, Nqn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// NVMe-oF fabrics service id, fixed on the server side (`reconcile`).
const TRSVCID: u16 = 4420;

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/target", get(target_info))
        .route("/exports", get(exports))
        .route("/exports/nvme/{id}/register", post(register_nvme))
        .route("/exports/nfs/{id}/register", post(register_nfs))
        .route("/tasks/{id}", get(task_status))
        .layer(middleware::from_fn_with_state(state, bearer_auth))
}

// ---- auth ----

/// Uniform failure: identical body for missing, malformed, and unknown tokens,
/// so the API leaks nothing about which tokens exist.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "unauthorized"})),
    )
        .into_response()
}

/// Fixed-window per-IP failure limiter: after `MAX_FAILURES` bad tokens in a
/// window the peer gets 429s until it expires. In-memory and per-process —
/// adequate for an appliance.
const MAX_FAILURES: u32 = 30;
const WINDOW: Duration = Duration::from_secs(60);

fn too_many_failures(peer: IpAddr) -> bool {
    static FAILURES: Mutex<Option<HashMap<IpAddr, (u32, Instant)>>> = Mutex::new(None);
    let mut guard = FAILURES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    map.retain(|_, (_, start)| now.duration_since(*start) < WINDOW);
    let (count, _) = map.entry(peer).or_insert((0, now));
    *count += 1;
    *count > MAX_FAILURES
}

/// The peer address, when the listener supplied it (ConnectInfo); tests inject
/// it as a request extension.
fn peer_ip(req: &Request) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

async fn bearer_auth(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let authorized = token.is_some_and(|raw| {
        let hash = client_access::token_hash(raw);
        state
            .db
            .list_client_tokens()
            .is_ok_and(|tokens| tokens.iter().any(|t| t.token_hash == hash))
    });
    if !authorized {
        // Unknown peers (no ConnectInfo) share one bucket at 0.0.0.0.
        let peer = peer_ip(&req).unwrap_or(Ipv4Addr::UNSPECIFIED.into());
        if too_many_failures(peer) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "too many failures"})),
            )
                .into_response();
        }
        return unauthorized();
    }
    next.run(req).await
}

// ---- GET /target ----

#[derive(Serialize)]
struct TargetInfo {
    name: String,
    api: u32,
    version: &'static str,
}

async fn target_info() -> Json<TargetInfo> {
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    Json(TargetInfo {
        name,
        api: 1,
        version: env!("CARGO_PKG_VERSION"),
    })
}

// ---- GET /exports ----

#[derive(Serialize)]
struct Listener {
    trtype: &'static str,
    /// `null` = connect to the host from the connection string (the export
    /// listens on the unspecified address, or its pinned port has no IP).
    traddr: Option<IpAddr>,
    trsvcid: u16,
}

#[derive(Serialize)]
struct NvmeExportInfo {
    id: i64,
    name: String,
    nqn: String,
    enabled: bool,
    allow_any_host: bool,
    /// Whether the `?hostnqn=` caller may connect right now (informational —
    /// the real gate is the kernel's allowed-hosts list).
    authorized: bool,
    listeners: Vec<Listener>,
}

#[derive(Serialize)]
struct NfsExportInfo {
    id: i64,
    path: String,
    enabled: bool,
    /// The NFS-over-RDMA port (TCP fallback uses the standard 2049).
    port: u16,
    /// Whether the server's RDMA listener is up.
    rdma: bool,
    /// Whether the caller's observed IP is already whitelisted.
    authorized: bool,
}

#[derive(Serialize)]
struct ExportsReply {
    nvme: Vec<NvmeExportInfo>,
    nfs: Vec<NfsExportInfo>,
}

#[derive(Deserialize)]
struct ExportsQuery {
    hostnqn: Option<String>,
}

/// Whether `ip` matches an NFS client spec: `*`, an exact IP, or an IPv4 CIDR.
/// Hostname and IPv6-CIDR specs are not matched (informational only).
fn nfs_client_matches(spec: &str, ip: IpAddr) -> bool {
    if spec == "*" {
        return true;
    }
    if let Ok(spec_ip) = spec.parse::<IpAddr>() {
        return spec_ip == ip;
    }
    let (Some((net, bits)), IpAddr::V4(ip)) = (spec.split_once('/'), ip) else {
        return false;
    };
    let (Ok(net), Ok(bits)) = (net.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

async fn exports(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<ExportsQuery>,
    req: Request,
) -> Response {
    let peer = peer_ip(&req);
    let pci_addrs = actual::nic::pci_addrs(&state.helper).await;
    let listen = listen_addr(&state);
    let nvme = match state.db.list_nvme_exports() {
        Ok(exports) => exports
            .iter()
            .map(|e| {
                let addrs = crate::reconcile::listen_addrs(&e.interfaces, listen, &pci_addrs);
                let concrete: Vec<IpAddr> = addrs
                    .iter()
                    .copied()
                    .filter(|a| !a.is_unspecified())
                    .collect();
                let mut listeners = Vec::new();
                for (want, trtype) in [(e.want_rdma, "rdma"), (e.want_tcp, "tcp")] {
                    if !want {
                        continue;
                    }
                    if concrete.is_empty() {
                        listeners.push(Listener {
                            trtype,
                            traddr: None,
                            trsvcid: TRSVCID,
                        });
                    } else {
                        listeners.extend(concrete.iter().map(|a| Listener {
                            trtype,
                            traddr: Some(*a),
                            trsvcid: TRSVCID,
                        }));
                    }
                }
                NvmeExportInfo {
                    id: e.id,
                    name: e.name.clone(),
                    nqn: e.nqn().to_string(),
                    enabled: e.enabled,
                    allow_any_host: e.allow_any_host,
                    authorized: e.allow_any_host
                        || q.hostnqn
                            .as_deref()
                            .is_some_and(|h| e.initiators.iter().any(|i| i == h)),
                    listeners,
                }
            })
            .collect(),
        Err(e) => return store_error(e),
    };
    let rdma_up = actual::nfs::read(&state.helper).await.rdma_port.is_some();
    let nfs = match state.db.list_nfs_exports() {
        Ok(exports) => exports
            .iter()
            .map(|e| NfsExportInfo {
                id: e.id,
                path: e.path.clone(),
                enabled: e.enabled,
                port: NFS_RDMA_PORT,
                rdma: rdma_up,
                authorized: peer
                    .is_some_and(|ip| e.clients.iter().any(|c| nfs_client_matches(&c.client, ip))),
            })
            .collect(),
        Err(e) => return store_error(e),
    };
    Json(ExportsReply { nvme, nfs }).into_response()
}

fn store_error(e: anyhow::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": format!("{e:#}")})),
    )
        .into_response()
}

// ---- POST register ----

#[derive(Serialize)]
struct RegisterReply {
    status: &'static str,
    /// The dispatched reconcile task, when the ACL actually changed and drift
    /// was found — poll `GET /tasks/{id}` before connecting.
    task_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<String>,
}

/// The registered/already-authorized reply after an ACL append: reconcile only
/// when something changed.
async fn finish_register(state: &Arc<AppState>, changed: bool, client: Option<String>) -> Response {
    if !changed {
        return Json(RegisterReply {
            status: "already-authorized",
            task_id: None,
            client,
        })
        .into_response();
    }
    match reconcile_state(state).await {
        Ok(task_id) => Json(RegisterReply {
            status: "registered",
            task_id,
            client,
        })
        .into_response(),
        Err(e) => store_error(e),
    }
}

#[derive(Deserialize)]
struct RegisterNvmeBody {
    hostnqn: String,
}

async fn register_nvme(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<RegisterNvmeBody>,
) -> Response {
    if Nqn::new(body.hostnqn.clone()).is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid hostnqn"})),
        )
            .into_response();
    }
    // allow_any_host means every initiator is welcome — don't grow the ACL.
    let any = state
        .db
        .list_nvme_exports()
        .ok()
        .and_then(|es| es.into_iter().find(|e| e.id == id))
        .map(|e| e.allow_any_host);
    match any {
        None => not_found(),
        Some(true) => finish_register(&state, false, None).await,
        Some(false) => match state.db.add_nvme_export_initiator(id, &body.hostnqn) {
            Ok(changed) => finish_register(&state, changed, None).await,
            Err(e) => store_error(e),
        },
    }
}

#[derive(Deserialize, Default)]
struct RegisterNfsBody {
    #[serde(default = "default_rw")]
    rw: bool,
}

fn default_rw() -> bool {
    true
}

async fn register_nfs(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    req: Request,
) -> Response {
    let Some(ip) = peer_ip(&req) else {
        return store_error(anyhow::anyhow!("peer address unknown"));
    };
    // The body is optional; a missing/empty one means rw.
    let body: RegisterNfsBody = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(bytes) if !bytes.is_empty() => match serde_json::from_slice(&bytes) {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": format!("invalid body: {e}")})),
                )
                    .into_response();
            }
        },
        _ => RegisterNfsBody::default(),
    };
    let exists = state
        .db
        .list_nfs_exports()
        .ok()
        .is_some_and(|es| es.iter().any(|e| e.id == id));
    if !exists {
        return not_found();
    }
    let entry = NfsClientEntry {
        client: ip.to_string(),
        rw: body.rw,
    };
    match state.db.add_nfs_export_client(id, entry) {
        Ok(changed) => finish_register(&state, changed, Some(ip.to_string())).await,
        Err(e) => store_error(e),
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "no such export"})),
    )
        .into_response()
}

// ---- GET /tasks/{id} ----

#[derive(Serialize)]
struct TaskInfo {
    id: i64,
    status: &'static str,
    error: Option<String>,
}

async fn task_status(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    match state.db.get_task(id) {
        Ok(Some(t)) => Json(TaskInfo {
            id: t.id,
            status: t.status.as_str(),
            error: t.error,
        })
        .into_response(),
        Ok(None) => not_found(),
        Err(e) => store_error(e),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::net::IpAddr;

    #[rstest]
    #[case("*", "10.0.0.7", true)]
    #[case("10.0.0.7", "10.0.0.7", true)]
    #[case("10.0.0.8", "10.0.0.7", false)]
    #[case("10.0.0.0/24", "10.0.0.7", true)]
    #[case("10.0.1.0/24", "10.0.0.7", false)]
    #[case("0.0.0.0/0", "192.168.1.1", true)]
    #[case("10.0.0.0/33", "10.0.0.7", false)]
    #[case("host.example.com", "10.0.0.7", false)]
    #[case("fd00::1", "fd00::1", true)]
    #[case("fd00::/64", "fd00::1", false)] // IPv6 CIDR: documented no-match
    fn nfs_client_matching(#[case] spec: &str, #[case] ip: &str, #[case] expect: bool) {
        let ip: IpAddr = ip.parse().unwrap();
        assert_eq!(
            super::nfs_client_matches(spec, ip),
            expect,
            "{spec} vs {ip}"
        );
    }

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Request as HttpRequest, StatusCode, header};
        use serde_json::Value;
        use std::net::SocketAddr;

        /// Creates a token through the web flow and scrapes the raw value out
        /// of the revealed connection string.
        async fn make_token(app: &axum::Router) -> String {
            let (cookie, csrf) = login(app).await;
            let mut req = form_post("/client-access/create", "name=test");
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            let (status, _, body) = send(app, req).await;
            assert_eq!(status, StatusCode::OK);
            body.split("greendot://")
                .nth(1)
                .and_then(|s| s.split('@').next())
                .expect("raw token in reveal")
                .to_owned()
        }

        fn api_get(path: &str, token: &str) -> HttpRequest<Body> {
            HttpRequest::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        }

        fn api_post(path: &str, token: &str, body: &str, peer: &str) -> HttpRequest<Body> {
            let mut req = HttpRequest::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap();
            let addr: SocketAddr = peer.parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        }

        #[tokio::test]
        async fn bearer_auth_and_full_register_flow() {
            let app = test_app();
            let token = make_token(&app).await;
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // Closed NVMe export + an NFS export to register against.
            send(
                &app,
                auth(form_post(
                    "/nvme/create",
                    "name=vm1&device=%2Fdev%2Fzvol%2Ftank%2Fvm1&want_rdma=1&want_tcp=1&initiators=nqn.2014-08.org.nvmexpress%3Aother",
                )),
            )
            .await;
            send(
                &app,
                auth(form_post(
                    "/nfs/create",
                    "path=%2Ftank%2Fshare&clients=192.168.101.9",
                )),
            )
            .await;

            // No/garbage bearer → uniform 401 without any cookie (CSRF bypass
            // proof: these POSTs never carry the CSRF header).
            for req in [
                HttpRequest::get("/api/client/v1/exports")
                    .body(Body::empty())
                    .unwrap(),
                api_get("/api/client/v1/exports", "gdt_wrong"),
            ] {
                let (status, _, body) = send(&app, req).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(body, r#"{"error":"unauthorized"}"#);
            }

            // Target info.
            let (status, _, body) = send(&app, api_get("/api/client/v1/target", &token)).await;
            assert_eq!(status, StatusCode::OK);
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["api"], 1);

            // Exports: closed export, caller not authorized; listeners carry
            // rdma+tcp on 4420 with traddr null (unspecified listen).
            let hostnqn = "nqn.2014-08.org.nvmexpress:uuid:client1";
            let (status, _, body) = send(
                &app,
                api_get(&format!("/api/client/v1/exports?hostnqn={hostnqn}"), &token),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let v: Value = serde_json::from_str(&body).unwrap();
            let e = &v["nvme"][0];
            assert_eq!(e["nqn"], "nqn.2026-06.io.greendot:vm1");
            assert_eq!(e["authorized"], false);
            assert_eq!(e["listeners"][0]["trtype"], "rdma");
            assert_eq!(e["listeners"][0]["traddr"], Value::Null);
            assert_eq!(e["listeners"][0]["trsvcid"], 4420);
            assert_eq!(e["listeners"][1]["trtype"], "tcp");
            let nfs = &v["nfs"][0];
            assert_eq!(nfs["path"], "/tank/share");
            assert_eq!(nfs["port"], 20049);
            assert_eq!(nfs["authorized"], false);

            // Register the NVMe hostnqn: first time registers (+reconcile task
            // against the fake helper), second is already-authorized. The
            // initiator lands in the desired state and flips `authorized`.
            let (status, _, body) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nvme/1/register",
                    &token,
                    &format!(r#"{{"hostnqn":"{hostnqn}"}}"#),
                    "10.0.0.7:5555",
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["status"], "registered");
            let task_id = v["task_id"].as_i64().expect("drifted fake → task");
            let (status, _, body) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nvme/1/register",
                    &token,
                    &format!(r#"{{"hostnqn":"{hostnqn}"}}"#),
                    "10.0.0.7:5555",
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                (v["status"].as_str(), v["task_id"].as_i64()),
                (Some("already-authorized"), None)
            );
            let (_, _, body) = send(
                &app,
                api_get(&format!("/api/client/v1/exports?hostnqn={hostnqn}"), &token),
            )
            .await;
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["nvme"][0]["authorized"], true);

            // Bad hostnqn → 422; unknown ids → 404.
            let (status, _, _) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nvme/1/register",
                    &token,
                    r#"{"hostnqn":"iqn.not-an-nqn"}"#,
                    "10.0.0.7:5555",
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            let (status, _, _) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nvme/99/register",
                    &token,
                    &format!(r#"{{"hostnqn":"{hostnqn}"}}"#),
                    "10.0.0.7:5555",
                ),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _, _) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nfs/99/register",
                    &token,
                    "",
                    "10.0.0.7:5555",
                ),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            // NFS register whitelists the observed peer IP (read-only body),
            // then reports already-authorized on repeat.
            let (status, _, body) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nfs/1/register",
                    &token,
                    r#"{"rw":false}"#,
                    "10.0.0.7:5555",
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["status"], "registered");
            assert_eq!(v["client"], "10.0.0.7");
            let (_, _, body) = send(
                &app,
                api_post(
                    "/api/client/v1/exports/nfs/1/register",
                    &token,
                    "",
                    "10.0.0.7:5555",
                ),
            )
            .await;
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["status"], "already-authorized");

            // The reconcile task the register dispatched is pollable.
            let (status, _, body) = send(
                &app,
                api_get(&format!("/api/client/v1/tasks/{task_id}"), &token),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let v: Value = serde_json::from_str(&body).unwrap();
            assert!(
                v["status"] == "success" || v["status"] == "running",
                "{body}"
            );
            let (status, _, _) = send(&app, api_get("/api/client/v1/tasks/9999", &token)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        // Rate limiter uses a process-global map — kept in the same test binary
        // run but a distinct peer bucket so it can't trip the flow test above.
        #[tokio::test]
        async fn repeated_bad_tokens_hit_the_rate_limit() {
            let app = test_app();
            let mut last = StatusCode::UNAUTHORIZED;
            for _ in 0..40 {
                let mut req = api_get("/api/client/v1/target", "gdt_bad");
                let addr: SocketAddr = "192.0.2.99:1".parse().unwrap();
                req.extensions_mut().insert(ConnectInfo(addr));
                let (status, _, _) = send(&app, req).await;
                last = status;
            }
            assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
