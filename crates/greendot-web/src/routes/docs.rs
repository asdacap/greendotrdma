use super::{AppState, page};
use crate::auth::CurrentUser;
use askama::Template;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/docs/democratic-csi", get(democratic_csi))
}

#[derive(Template)]
#[template(path = "docs_democratic_csi.html")]
struct DemocraticCsiTemplate {
    user: CurrentUser,
}

async fn democratic_csi(Extension(user): Extension<CurrentUser>) -> Response {
    page(DemocraticCsiTemplate { user })
}
