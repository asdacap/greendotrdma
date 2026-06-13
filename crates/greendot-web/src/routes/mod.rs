use askama::Template;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

const HTMX_JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../static/htmx.min.js"
));
const STYLE_CSS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../static/style.css"
));

pub fn app() -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(async || "ok"))
        .route(
            "/static/htmx.min.js",
            get(async || asset("text/javascript", HTMX_JS)),
        )
        .route(
            "/static/style.css",
            get(async || asset("text/css", STYLE_CSS)),
        )
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
fn page<T: Template>(template: T) -> Response {
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
struct DashboardTemplate;

async fn dashboard() -> Response {
    page(DashboardTemplate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rstest::rstest;
    use tower::ServiceExt;

    async fn get(path: &str) -> (StatusCode, String, String) {
        let resp = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let body = String::from_utf8(resp.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        (status, content_type, body)
    }

    #[rstest]
    #[case::dashboard("/", "text/html", "GreenDotRDMA")]
    #[case::htmx("/static/htmx.min.js", "text/javascript", "htmx")]
    #[case::css("/static/style.css", "text/css", "body")]
    #[case::health("/healthz", "text/plain", "ok")]
    #[tokio::test]
    async fn pages_are_served(
        #[case] path: &str,
        #[case] want_type: &str,
        #[case] want_body: &str,
    ) {
        let (status, content_type, body) = get(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            content_type.starts_with(want_type),
            "{path}: {content_type}"
        );
        assert!(body.contains(want_body), "{path}");
    }
}
