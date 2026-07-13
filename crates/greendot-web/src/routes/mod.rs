pub mod block_export;
pub mod charts;
pub mod client_access;
pub mod client_api;
pub mod connections;
pub mod disks;
pub mod docs;
pub mod iscsi;
pub mod lvm;
pub mod nfs;
pub mod nic;
pub mod nvme;
pub mod settings;
pub mod snapshots;
pub mod ssh_access;
pub mod tasks;
pub mod zfs;

use crate::auth::{self, CurrentUser};
use crate::helper_client::HelperClient;
use askama::Template;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router, middleware};
use std::sync::Arc;

const HTMX_JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../static/htmx.min.js"
));
const PICO_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../static/pico.css"
));
const STYLE_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../static/style.css"
));

pub struct AppState {
    pub helper: HelperClient,
    pub sessions: auth::Sessions,
    pub secure_cookies: bool,
    pub db: crate::state::Db,
    pub metrics: crate::metrics::Metrics,
    /// Serializes reconcile passes (UI actions vs the periodic task). Held — via
    /// an owned guard — across the now-backgrounded reconcile run, so two passes
    /// never overlap even though dispatch no longer blocks the caller.
    pub reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    /// Live state of running tasks (for SSE streaming).
    pub tasks: crate::task_runner::TaskHub,
    /// sha256 hex of the TLS leaf cert, embedded in client connection strings
    /// for pinning. `None` when serving plain HTTP.
    pub tls_fingerprint: Option<String>,
    /// The configured listen address — the connection-string host fallback
    /// when a create request carries no Host header.
    pub listen: std::net::SocketAddr,
}

pub fn app(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(dashboard))
        .route("/logout", post(auth::logout))
        .merge(zfs::router())
        .merge(lvm::router())
        .merge(nvme::router())
        .merge(iscsi::router())
        .merge(nfs::router())
        .merge(nic::router())
        .merge(settings::router())
        .merge(disks::router())
        .merge(snapshots::router())
        .merge(charts::router())
        .merge(connections::router())
        .merge(tasks::router())
        .merge(docs::router())
        .merge(client_access::router())
        .merge(ssh_access::router())
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_auth,
        ));
    Router::new()
        .merge(protected)
        // Token-authenticated JSON API for the greendot-client app — outside
        // the cookie/CSRF middleware like /metrics; it carries its own bearer
        // check.
        .nest("/api/client/v1", client_api::router(Arc::clone(&state)))
        .route("/login", get(auth::login_page).post(auth::login_post))
        .route("/healthz", get(async || "ok"))
        // Deliberately unauthenticated, like /healthz: Prometheus scrapers
        // don't carry a session, and the gauges leak no secrets.
        .route("/metrics", get(charts::prometheus))
        .route(
            "/static/htmx.min.js",
            get(async || asset("text/javascript", HTMX_JS)),
        )
        .route(
            "/static/pico.css",
            get(async || asset("text/css", PICO_CSS)),
        )
        .route(
            "/static/style.css",
            get(async || asset("text/css", STYLE_CSS)),
        )
        .with_state(state)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "max-age=3600"),
        ],
        body,
    )
        .into_response()
}

/// Renders an askama template, turning render errors into a 500.
pub fn page<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    user: CurrentUser,
    /// RDMA-capable NICs and their status (empty → "not available").
    nics: Vec<nic::NicRow>,
}

async fn dashboard(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    // The per-protocol export dot grids load themselves from `/partials/nvme`
    // and `/partials/iscsi` (see dashboard.html), so the page only needs NICs.
    let nics = crate::actual::nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter_map(nic::nic_row)
        .collect();
    page(DashboardTemplate { user, nics })
}

/// Shared by the route tests of every page module.
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use crate::auth::Sessions;
    use axum::body::Body;
    use axum::http::Request;
    use greendot_proto::pb;
    use greendot_proto::pb::helper_server::{Helper, HelperServer};
    use greendot_proto::{AuthResult, ErrKind, SubStatus, TaskEvent, ops};
    use http_body_util::BodyExt;
    use std::pin::Pin;
    use std::time::Duration;
    use tokio_stream::wrappers::UnixListenerStream;
    use tower::ServiceExt;

    /// A fake helper — a real in-process tonic server — accepting alice/secret
    /// and answering success to every task rpc, with canned replies for the
    /// reads so the pages build real rows.
    struct FakeHelper;

    type FakeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<pb::TaskEvent, tonic::Status>> + Send>>;

    fn stream_of(events: Vec<TaskEvent>) -> tonic::Response<FakeStream> {
        let events: Vec<Result<pb::TaskEvent, tonic::Status>> = events
            .into_iter()
            .map(|e| Ok(pb::TaskEvent::from(e)))
            .collect();
        tonic::Response::new(Box::pin(tokio_stream::iter(events)))
    }

    fn started() -> TaskEvent {
        TaskEvent::SubtaskStarted {
            name: "fake".into(),
            command: Some("fake".into()),
            args: vec![],
            stdin: None,
        }
    }

    /// Started + one successful subtask + successful Finished — the canned
    /// happy path for every plain task rpc.
    fn ok_events(stdout: Option<&str>) -> Vec<TaskEvent> {
        let mut events = vec![started()];
        if let Some(data) = stdout {
            events.push(TaskEvent::Stdout { data: data.into() });
        }
        events.extend([
            TaskEvent::SubtaskFinished {
                status: SubStatus::Success,
                exit: 0,
                error: None,
            },
            TaskEvent::Finished {
                status: SubStatus::Success,
                error: None,
            },
        ]);
        events
    }

    /// Generates the whole fake `Helper` impl in one macro (like the daemon's
    /// real impl) so `#[tonic::async_trait]` sees expanded methods. Every task
    /// rpc answers the canned success stream; the customs are written inline.
    macro_rules! fake_helper_impl {
        (tasks { $($method:ident, $stream:ident, $wire:ty;)* }
         reads { $($rmethod:ident, $rwire:ty, $reply:ty;)* }) => {
            #[tonic::async_trait]
            impl Helper for FakeHelper {
                async fn ping(
                    &self,
                    _r: tonic::Request<pb::Empty>,
                ) -> Result<tonic::Response<pb::Empty>, tonic::Status> {
                    Ok(tonic::Response::new(pb::Empty {}))
                }

                async fn authenticate(
                    &self,
                    request: tonic::Request<pb::Authenticate>,
                ) -> Result<tonic::Response<pb::AuthReply>, tonic::Status> {
                    let auth = ops::Authenticate::try_from(request.into_inner())
                        .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
                    let result =
                        if auth.username.as_str() == "alice" && auth.password.0 == "secret" {
                            AuthResult::Ok {
                                username: auth.username.to_string(),
                            }
                        } else {
                            AuthResult::err(ErrKind::AuthFailed, "invalid username or password")
                        };
                    Ok(tonic::Response::new(result.into()))
                }

                // SMART full report: smartctl exits nonzero on healthy drives,
                // so the subtask/task finish Failed to prove the web shows
                // stdout regardless.
                type SmartReportStream = FakeStream;
                async fn smart_report(
                    &self,
                    _r: tonic::Request<pb::SmartReport>,
                ) -> Result<tonic::Response<Self::SmartReportStream>, tonic::Status> {
                    Ok(stream_of(vec![
                        started(),
                        TaskEvent::Stdout {
                            data: "smartctl 7.3\nSMART overall-health self-assessment \
                                   test result: PASSED\n"
                                .into(),
                        },
                        TaskEvent::SubtaskFinished {
                            status: SubStatus::Failed,
                            exit: 4,
                            error: None,
                        },
                        TaskEvent::Finished {
                            status: SubStatus::Failed,
                            error: None,
                        },
                    ]))
                }

                // LVM report: canned lvm JSON on stdout so the pages build rows.
                type LvmReportStream = FakeStream;
                async fn lvm_report(
                    &self,
                    request: tonic::Request<pb::LvmReport>,
                ) -> Result<tonic::Response<Self::LvmReportStream>, tonic::Status> {
                    let json = match pb::LvmReportKind::try_from(request.into_inner().what) {
                        Ok(pb::LvmReportKind::Vgs) => {
                            r#"{"report":[{"vg":[{"vg_name":"vg0","vg_size":"107374182400","vg_free":"53687091200","pv_count":"1","lv_count":"2"}]}]}"#
                        }
                        Ok(pb::LvmReportKind::Lvs) => {
                            r#"{"report":[{"lv":[{"vg_name":"vg0","lv_name":"data","lv_size":"10737418240","lv_attr":"-wi-a-----","pool_lv":"","data_percent":""},{"vg_name":"vg0","lv_name":"pool0","lv_size":"53687091200","lv_attr":"twi-aotz--","pool_lv":"","data_percent":"5.00"}]}]}"#
                        }
                        _ => {
                            r#"{"report":[{"pv":[{"pv_name":"/dev/sdb","vg_name":"vg0","pv_size":"107374182400","pv_free":"53687091200"}]}]}"#
                        }
                    };
                    Ok(stream_of(ok_events(Some(json))))
                }

                // Batch SMART health: a small canned inventory (dot + temp).
                async fn smart_health(
                    &self,
                    _r: tonic::Request<pb::SmartHealth>,
                ) -> Result<tonic::Response<pb::SmartHealthReply>, tonic::Status> {
                    Ok(tonic::Response::new(pb::SmartHealthReply {
                        devices: vec![pb::SmartHealthMsg {
                            device: "sda".into(),
                            passed: Some(true),
                            temp_c: Some(38),
                        }],
                    }))
                }

                // RoCE-capable inventory: eth0 with a sample vendor so the NIC
                // table shows a capable-disabled row (rendered opaquely).
                async fn roce_capable_nics(
                    &self,
                    _r: tonic::Request<pb::Empty>,
                ) -> Result<tonic::Response<pb::RoceCapableNicsReply>, tonic::Status> {
                    Ok(tonic::Response::new(pb::RoceCapableNicsReply {
                        nics: vec![pb::RoceCapableNic {
                            netdev: "eth0".into(),
                            vendor: "Acme".into(),
                        }],
                    }))
                }

                // Everything else: plain successful tasks / empty typed replies.
                $(
                    type $stream = FakeStream;
                    async fn $method(
                        &self,
                        _r: tonic::Request<$wire>,
                    ) -> Result<tonic::Response<Self::$stream>, tonic::Status> {
                        Ok(stream_of(ok_events(None)))
                    }
                )*
                $(
                    async fn $rmethod(
                        &self,
                        _r: tonic::Request<$rwire>,
                    ) -> Result<tonic::Response<$reply>, tonic::Status> {
                        Ok(tonic::Response::new(<$reply>::default()))
                    }
                )*
            }
        };
    }

    fake_helper_impl! {
        tasks {
            zvol_create, ZvolCreateStream, pb::ZvolCreate;
            zvol_delete, ZvolDeleteStream, pb::ZvolDelete;
            zvol_resize, ZvolResizeStream, pb::ZvolResize;
            snapshot_create, SnapshotCreateStream, pb::SnapshotCreate;
            snapshot_destroy, SnapshotDestroyStream, pb::SnapshotDestroy;
            zfs_fs_create, ZfsFsCreateStream, pb::ZfsFsCreate;
            zfs_set_mountpoint, ZfsSetMountpointStream, pb::ZfsSetMountpoint;
            zfs_mount, ZfsMountStream, pb::ZfsMount;
            zfs_unmount, ZfsUnmountStream, pb::ZfsUnmount;
            zfs_destroy, ZfsDestroyStream, pb::ZfsDestroy;
            pool_create, PoolCreateStream, pb::PoolCreate;
            pool_vdev_add, PoolVdevAddStream, pb::PoolVdevAdd;
            pool_device_attach, PoolDeviceAttachStream, pb::PoolDeviceAttach;
            pool_device_remove, PoolDeviceRemoveStream, pb::PoolDeviceRemove;
            pool_device_detach, PoolDeviceDetachStream, pb::PoolDeviceDetach;
            pool_device_online, PoolDeviceOnlineStream, pb::PoolDeviceOnline;
            partition_table_create, PartitionTableCreateStream, pb::PartitionTableCreate;
            partition_create, PartitionCreateStream, pb::PartitionCreate;
            partition_delete, PartitionDeleteStream, pb::PartitionDelete;
            partition_shrink, PartitionShrinkStream, pb::PartitionShrink;
            vg_create, VgCreateStream, pb::VgCreate;
            vg_extend, VgExtendStream, pb::VgExtend;
            vg_reduce, VgReduceStream, pb::VgReduce;
            vg_remove, VgRemoveStream, pb::VgRemove;
            lv_create, LvCreateStream, pb::LvCreate;
            thin_pool_create, ThinPoolCreateStream, pb::ThinPoolCreate;
            thin_lv_create, ThinLvCreateStream, pb::ThinLvCreate;
            lv_resize, LvResizeStream, pb::LvResize;
            lv_shrink, LvShrinkStream, pb::LvShrink;
            lv_rename, LvRenameStream, pb::LvRename;
            lv_delete, LvDeleteStream, pb::LvDelete;
            reconcile, ReconcileStream, pb::Reconcile;
            rxe_add, RxeAddStream, pb::RxeAdd;
            enable_roce, EnableRoceStream, pb::EnableRoce;
            set_mtu, SetMtuStream, pb::SetMtu;
            install_packages, InstallPackagesStream, pb::InstallPackages;
            rdma_resources, RdmaResourcesStream, pb::Empty;
            zfs_clone, ZfsCloneStream, pb::ZfsClone;
            csi_nvme_apply, CsiNvmeApplyStream, pb::CsiNvmeApply;
            csi_nvme_delete, CsiNvmeDeleteStream, pb::CsiNvmeDelete;
            csi_host_grant, CsiHostGrantStream, pb::CsiHostGrant;
            csi_host_revoke, CsiHostRevokeStream, pb::CsiHostRevoke;
            csi_volume_expand, CsiVolumeExpandStream, pb::CsiVolumeExpand;
            pipe_key_add, PipeKeyAddStream, pb::PipeKeyAdd;
            pipe_key_revoke, PipeKeyRevokeStream, pb::PipeKeyRevoke;
        }
        reads {
            nfs_report, pb::Empty, pb::NfsReportReply;
            nvmet_report, pb::Empty, pb::NvmetReportReply;
            lio_report, pb::Empty, pb::LioReportReply;
            lio_sessions, pb::Empty, pb::LioSessionsReply;
            rdma_devices, pb::Empty, pb::RdmaDevicesReply;
            nic_pci_addrs, pb::Empty, pb::NicPciAddrsReply;
            nic_interfaces, pb::Empty, pb::NicInterfacesReply;
            nic_network, pb::Empty, pb::NicNetworkReply;
            nic_rdma_advice, pb::Empty, pb::NicRdmaAdviceReply;
            reconcile_dry_run, pb::Empty, pb::ReconcileDryRunReply;
            zvol_info, pb::ZvolInfo, pb::ZvolInfoReply;
            pipe_access_report, pb::Empty, pb::PipeAccessReportReply;
        }
    }

    /// Binds a fake helper on a fresh unix socket and returns its path.
    fn fake_helper_socket() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gd-fake{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(HelperServer::new(FakeHelper))
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await;
        });
        socket
    }

    /// A test `AppState` backed by the fake helper, whose canned streams
    /// answer the `Reconcile` rpc with a successful task — so the drift gate +
    /// record/stream path is exercised without a real daemon.
    pub fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            helper: HelperClient::new(fake_helper_socket()),
            sessions: Sessions::new(Duration::from_secs(3600)),
            secure_cookies: false,
            db: crate::state::Db::in_memory().unwrap(),
            metrics: crate::metrics::Metrics::in_memory().unwrap(),
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            tasks: crate::task_runner::TaskHub::default(),
            tls_fingerprint: Some("aa".repeat(32)),
            listen: "127.0.0.1:8443".parse().unwrap(),
        })
    }

    pub fn test_app() -> Router {
        app(test_state())
    }

    pub async fn send(
        app: &Router,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let body = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        (parts.status, parts.headers, body)
    }

    pub fn form_post(path: &str, body: &str) -> Request<Body> {
        Request::post(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    /// Logs in as alice and returns (cookie, csrf) for authenticated requests.
    pub async fn login(app: &Router) -> (String, String) {
        let (status, headers, _) =
            send(app, form_post("/login", "username=alice&password=secret")).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "test login must succeed");
        let cookie = headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let req = Request::get("/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (_, _, body) = send(app, req).await;
        let csrf = body
            .split(r#"X-Greendot-Csrf":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("csrf token in page")
            .to_owned();
        (cookie, csrf)
    }

    #[tokio::test]
    async fn public_pages_and_unauthenticated_redirect() {
        let app = test_app();
        let (status, headers, _) = send(&app, Request::get("/").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(headers[header::LOCATION], "/login");

        // htmx requests get HX-Redirect instead of a 3xx.
        let req = Request::get("/")
            .header("hx-request", "true")
            .body(Body::empty())
            .unwrap();
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["hx-redirect"], "/login");

        for (path, want) in [("/login", "Sign in"), ("/healthz", "ok")] {
            let (status, _, body) =
                send(&app, Request::get(path).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(body.contains(want), "{path}");
        }
    }

    #[tokio::test]
    async fn dashboard_lists_rdma_capable_nics_section() {
        let app = test_app();
        let (cookie, _) = login(&app).await;
        let req = Request::get("/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        // The section header is always present; its body is either the NIC
        // table or the "not available" fallback depending on the host.
        assert!(body.contains("RDMA-capable NICs"), "{body}");
        assert!(
            body.contains("Not available") || body.contains("<th>Interface</th>"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn login_logout_lifecycle_with_csrf() {
        let app = test_app();

        // Wrong password: 401, error shown, no cookie.
        let (status, headers, body) =
            send(&app, form_post("/login", "username=alice&password=wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.get(header::SET_COOKIE).is_none());
        assert!(body.contains("invalid username or password"), "{body}");

        // Invalid username never reaches the helper but fails the same way.
        let (status, _, _) = send(&app, form_post("/login", "username=a%2Fb&password=x")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Good login: cookie set, redirected to /.
        let (status, headers, _) =
            send(&app, form_post("/login", "username=alice&password=secret")).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let cookie = headers[header::SET_COOKIE].to_str().unwrap().to_owned();
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        let cookie = cookie.split(';').next().unwrap().to_owned(); // gd_session=...

        // Authenticated dashboard shows the user and carries the CSRF token.
        let req = Request::get("/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("alice"), "{body}");
        let csrf = body
            .split(r#"X-Greendot-Csrf":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| panic!("no csrf in body: {body}"))
            .to_owned();

        // Mutating request without the CSRF header is rejected.
        let req = Request::post("/logout")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // With the CSRF header it succeeds and the session dies.
        let req = Request::post("/logout")
            .header(header::COOKIE, &cookie)
            .header("x-greendot-csrf", &csrf)
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let req = Request::get("/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(&app, req).await;
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "session must be gone after logout"
        );
    }
}
