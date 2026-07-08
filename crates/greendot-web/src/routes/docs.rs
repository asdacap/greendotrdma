use super::{AppState, page};
use crate::auth::CurrentUser;
use askama::Template;
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum::{Extension, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/docs/kubernetes-csi", get(kubernetes_csi))
        // The page's old home, from when democratic-csi was the only story.
        .route(
            "/docs/democratic-csi",
            get(|| async { Redirect::permanent("/docs/kubernetes-csi") }),
        )
}

#[derive(Template)]
#[template(path = "docs_kubernetes_csi.html")]
struct KubernetesCsiTemplate {
    user: CurrentUser,
}

async fn kubernetes_csi(Extension(user): Extension<CurrentUser>) -> Response {
    page(KubernetesCsiTemplate { user })
}
