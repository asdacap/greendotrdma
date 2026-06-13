pub mod exports;
pub mod settings;
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
const STYLE_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../static/style.css"
));

pub struct AppState {
    pub helper: HelperClient,
    pub sessions: auth::Sessions,
    pub secure_cookies: bool,
    pub db: crate::state::Db,
    pub nvmet_root: std::path::PathBuf,
    pub lio_root: std::path::PathBuf,
    /// Serializes reconcile passes (UI actions vs the periodic task).
    pub reconcile_lock: tokio::sync::Mutex<()>,
}

pub fn app(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(dashboard))
        .route("/logout", post(auth::logout))
        .merge(zfs::router())
        .merge(exports::router())
        .merge(settings::router())
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_auth,
        ));
    Router::new()
        .merge(protected)
        .route("/login", get(auth::login_page).post(auth::login_post))
        .route("/healthz", get(async || "ok"))
        .route(
            "/static/htmx.min.js",
            get(async || asset("text/javascript", HTMX_JS)),
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
    view: exports::ExportsView,
}

async fn dashboard(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(DashboardTemplate {
        user,
        view: exports::gather(&state, None, None).await,
    })
}

/// Shared by the route tests of every page module.
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use crate::auth::Sessions;
    use axum::body::Body;
    use axum::http::Request;
    use greendot_proto::{ErrKind, Request as HelperRequest, Response as HelperResponse, wire};
    use http_body_util::BodyExt;
    use std::io::BufReader;
    use std::time::Duration;
    use tower::ServiceExt;

    /// A fake helper accepting alice/secret, answering Ok to everything else.
    fn fake_helper_socket() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gd-fake{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                while let Ok(Some(req)) = wire::read_msg::<HelperRequest, _>(&mut reader) {
                    let resp = match req {
                        HelperRequest::Authenticate { username, password }
                            if username.as_str() == "alice" && password.0 == "secret" =>
                        {
                            HelperResponse::OkAuth {
                                username: username.to_string(),
                            }
                        }
                        HelperRequest::Authenticate { .. } => {
                            HelperResponse::err(ErrKind::AuthFailed, "invalid username or password")
                        }
                        _ => HelperResponse::Ok,
                    };
                    if wire::write_msg(&mut writer, &resp).is_err() {
                        break;
                    }
                }
            }
        });
        socket
    }

    pub fn test_app() -> Router {
        let nvmet_root =
            std::env::temp_dir().join(format!("gd-nvmet-app{}", rand::random::<u32>()));
        app(Arc::new(AppState {
            helper: HelperClient::new(fake_helper_socket()),
            sessions: Sessions::new(Duration::from_secs(3600)),
            secure_cookies: false,
            db: crate::state::Db::in_memory().unwrap(),
            lio_root: nvmet_root.join("lio"),
            nvmet_root,
            reconcile_lock: tokio::sync::Mutex::new(()),
        }))
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
