pub mod block_export;
pub mod charts;
pub mod connections;
pub mod disks;
pub mod docs;
pub mod iscsi;
pub mod lvm;
pub mod nfs;
pub mod nvme;
pub mod settings;
pub mod snapshots;
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
    pub nvmet_root: std::path::PathBuf,
    pub lio_root: std::path::PathBuf,
    /// Serializes reconcile passes (UI actions vs the periodic task). Held — via
    /// an owned guard — across the now-backgrounded reconcile run, so two passes
    /// never overlap even though dispatch no longer blocks the caller.
    pub reconcile_lock: Arc<tokio::sync::Mutex<()>>,
    /// Live state of running tasks (for SSE streaming).
    pub tasks: crate::task_runner::TaskHub,
    /// The daemon-local path of the shared config TOML, sent with
    /// `Request::Reconcile` on drift (the web's own config argument, so the
    /// daemon reads the same desired state). `None` = built-in defaults.
    pub reconcile_config: Option<String>,
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
        .merge(settings::router())
        .merge(disks::router())
        .merge(snapshots::router())
        .merge(charts::router())
        .merge(connections::router())
        .merge(tasks::router())
        .merge(docs::router())
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_auth,
        ));
    Router::new()
        .merge(protected)
        .route("/login", get(auth::login_page).post(auth::login_post))
        .route("/healthz", get(async || "ok"))
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
    nics: Vec<settings::NicRow>,
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
        .filter_map(settings::nic_row)
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
    use greendot_proto::{
        ErrKind, LvmReport, Request as HelperRequest, Response as HelperResponse, SubStatus,
        TaskEvent,
    };
    use http_body_util::BodyExt;
    use std::pin::Pin;
    use std::time::Duration;
    use tokio_stream::wrappers::UnixListenerStream;
    use tower::ServiceExt;

    /// A fake helper — a real in-process tonic server — accepting alice/secret
    /// and answering Ok to everything else, with canned reads for the report
    /// ops so the pages build real rows.
    struct FakeHelper;

    /// Canned task-event stream for a request (the read ops carry the JSON the
    /// pages parse; everything else is a Started + successful Finished).
    fn fake_events(req: &HelperRequest) -> Vec<TaskEvent> {
        let started = TaskEvent::SubtaskStarted {
            name: "fake".into(),
            command: Some("fake".into()),
            args: vec![],
            stdin: None,
        };
        let sub_ok = TaskEvent::SubtaskFinished {
            status: SubStatus::Success,
            exit: 0,
            error: None,
        };
        let ok_finished = TaskEvent::Finished {
            status: SubStatus::Success,
            error: None,
        };
        let stdout = |data: &str| TaskEvent::Stdout { data: data.into() };
        match req {
            HelperRequest::LvmReport { what } => {
                let json = match what {
                    LvmReport::Vgs => {
                        r#"{"report":[{"vg":[{"vg_name":"vg0","vg_size":"107374182400","vg_free":"53687091200","pv_count":"1","lv_count":"2"}]}]}"#
                    }
                    LvmReport::Lvs => {
                        r#"{"report":[{"lv":[{"vg_name":"vg0","lv_name":"data","lv_size":"10737418240","lv_attr":"-wi-a-----","pool_lv":"","data_percent":""},{"vg_name":"vg0","lv_name":"pool0","lv_size":"53687091200","lv_attr":"twi-aotz--","pool_lv":"","data_percent":"5.00"}]}]}"#
                    }
                    LvmReport::Pvs => {
                        r#"{"report":[{"pv":[{"pv_name":"/dev/sdb","vg_name":"vg0","pv_size":"107374182400","pv_free":"53687091200"}]}]}"#
                    }
                };
                vec![started, stdout(json), sub_ok, ok_finished]
            }
            // RoCE-capable NIC inventory: eth0 with a sample vendor so the NIC
            // table shows a capable-disabled row (the web renders it opaquely).
            HelperRequest::RoceCapableNics => {
                vec![
                    started,
                    stdout(r#"[{"netdev":"eth0","vendor":"Acme"}]"#),
                    sub_ok,
                    ok_finished,
                ]
            }
            // SMART batch health: a small canned inventory (dot + temperature).
            HelperRequest::SmartHealth { .. } => {
                vec![
                    started,
                    stdout(r#"[{"device":"sda","passed":true,"temp_c":38}]"#),
                    sub_ok,
                    ok_finished,
                ]
            }
            // SMART full report: smartctl exits nonzero on healthy drives, so the
            // subtask/task finish Failed to prove the web shows stdout regardless.
            HelperRequest::SmartReport { .. } => vec![
                started,
                stdout("smartctl 7.3\nSMART overall-health self-assessment test result: PASSED\n"),
                TaskEvent::SubtaskFinished {
                    status: SubStatus::Failed,
                    exit: 4,
                    error: None,
                },
                TaskEvent::Finished {
                    status: SubStatus::Failed,
                    error: None,
                },
            ],
            // Everything else (incl. EnableRoce, EnsureModules) is a task.
            _ => vec![started, sub_ok, ok_finished],
        }
    }

    #[tonic::async_trait]
    impl Helper for FakeHelper {
        async fn call(
            &self,
            request: tonic::Request<pb::Request>,
        ) -> std::result::Result<tonic::Response<pb::Response>, tonic::Status> {
            let req = HelperRequest::try_from(request.into_inner())
                .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
            let resp = match req {
                HelperRequest::Ping => HelperResponse::Ok,
                HelperRequest::Authenticate { username, password } => {
                    if username.as_str() == "alice" && password.0 == "secret" {
                        HelperResponse::OkAuth {
                            username: username.to_string(),
                        }
                    } else {
                        HelperResponse::err(ErrKind::AuthFailed, "invalid username or password")
                    }
                }
                _ => HelperResponse::Ok,
            };
            Ok(tonic::Response::new(resp.into()))
        }

        type RunTaskStream = Pin<
            Box<
                dyn tokio_stream::Stream<Item = std::result::Result<pb::TaskEvent, tonic::Status>>
                    + Send,
            >,
        >;

        #[allow(clippy::result_large_err)] // tonic::Status is large; fine for a test stub
        async fn run_task(
            &self,
            request: tonic::Request<pb::Request>,
        ) -> std::result::Result<tonic::Response<Self::RunTaskStream>, tonic::Status> {
            let req = HelperRequest::try_from(request.into_inner())
                .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
            let events: Vec<std::result::Result<pb::TaskEvent, tonic::Status>> = fake_events(&req)
                .into_iter()
                .map(|e| Ok(pb::TaskEvent::from(e)))
                .collect();
            Ok(tonic::Response::new(Box::pin(tokio_stream::iter(events))))
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

    /// A test `AppState` backed by the fake helper, whose canned `RunTask`
    /// stream answers `Request::Reconcile` with a successful task — so the
    /// drift gate + record/stream path is exercised without a real daemon.
    pub fn test_state() -> Arc<AppState> {
        let nvmet_root =
            std::env::temp_dir().join(format!("gd-nvmet-app{}", rand::random::<u32>()));
        Arc::new(AppState {
            helper: HelperClient::new(fake_helper_socket()),
            sessions: Sessions::new(Duration::from_secs(3600)),
            secure_cookies: false,
            db: crate::state::Db::in_memory().unwrap(),
            metrics: crate::metrics::Metrics::in_memory().unwrap(),
            lio_root: nvmet_root.join("lio"),
            nvmet_root,
            reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
            tasks: crate::task_runner::TaskHub::default(),
            reconcile_config: None,
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
