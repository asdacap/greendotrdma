use super::{AppState, page};
use crate::actual;
use crate::auth::{CurrentUser, nav_redirect};
use crate::fmt::human_bytes;
use crate::state::SnapshotPolicy;
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{DatasetName, Request, SnapName};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/snapshots", get(snapshots_page))
        .route("/snapshots/policy/create", post(policy_create))
        .route("/snapshots/policy/{id}", get(policy_detail_page))
        .route("/snapshots/policy/toggle", post(policy_toggle))
        .route("/snapshots/policy/delete", post(policy_delete))
        .route("/snapshots/snap/{*name}", get(snap_detail_page))
        .route("/snapshots/manual", post(manual_snapshot))
        .route("/snapshots/delete", post(snapshot_delete))
}

pub struct PolicyRow {
    pub id: i64,
    pub dataset: String,
    pub cron: String,
    pub prefix: String,
    pub keep: String,
    pub enabled: bool,
    pub last_run: String,
}

impl PolicyRow {
    fn new(p: SnapshotPolicy) -> Self {
        PolicyRow {
            keep: match (p.keep_last, p.keep_days) {
                (None, None) => "everything".into(),
                (last, days) => [
                    last.map(|n| format!("last {n}")),
                    days.map(|d| format!("{d} days")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", "),
            },
            last_run: fmt_time(p.last_run),
            id: p.id,
            dataset: p.dataset,
            cron: p.cron,
            prefix: p.prefix,
            enabled: p.enabled,
        }
    }
}

pub struct SnapRow {
    pub name: String,
    pub used: String,
    pub created: String,
}

impl SnapRow {
    fn new(s: actual::zfs::Snapshot) -> Self {
        SnapRow {
            used: human_bytes(s.used),
            created: fmt_time(s.creation),
            name: s.name,
        }
    }
}

pub struct SnapshotsView {
    pub policies: Vec<PolicyRow>,
    pub snapshots: Vec<SnapRow>,
    pub datasets: Vec<String>,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "snapshots.html")]
struct SnapshotsTemplate {
    user: CurrentUser,
    view: SnapshotsView,
}

#[derive(Template)]
#[template(path = "_snapshots.html")]
struct SnapshotsPartial {
    view: SnapshotsView,
}

fn fmt_time(ts: i64) -> String {
    if ts == 0 {
        return "never".into();
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> SnapshotsView {
    let mut view = SnapshotsView {
        policies: vec![],
        snapshots: vec![],
        datasets: vec![],
        error: None,
        flash,
        task_id,
        form_error,
    };
    match state.db.list_policies() {
        Ok(policies) => view.policies = policies.into_iter().map(PolicyRow::new).collect(),
        Err(e) => view.error = Some(format!("could not read policies: {e:#}")),
    }
    match actual::zfs::snapshots().await {
        Ok(Some(snaps)) => view.snapshots = snaps.into_iter().map(SnapRow::new).collect(),
        // ZFS not installed — leave the snapshot list empty.
        Ok(None) => {}
        Err(e) => {
            if view.error.is_none() {
                view.error = Some(format!("could not list snapshots: {e:#}"));
            }
        }
    }
    view.datasets = actual::zfs::datasets()
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect();
    view
}

async fn snapshots_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(SnapshotsTemplate {
        user,
        view: gather(&state, None, None, None).await,
    })
}

async fn render(
    state: &AppState,
    flash: Option<String>,
    error: Option<String>,
    task_id: Option<i64>,
) -> Response {
    page(SnapshotsPartial {
        view: gather(state, flash, error, task_id).await,
    })
}

// ---- Per-policy page (toggle + delete) ----

#[derive(Default)]
pub struct PolicyDetailView {
    /// `None` when the policy id doesn't exist.
    pub policy: Option<PolicyRow>,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "policy_detail.html")]
struct PolicyDetailTemplate {
    user: CurrentUser,
    view: PolicyDetailView,
}

#[derive(Template)]
#[template(path = "_policy_detail.html")]
struct PolicyDetailPartial {
    view: PolicyDetailView,
}

async fn gather_policy_detail(
    state: &AppState,
    id: i64,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> PolicyDetailView {
    let mut view = PolicyDetailView {
        flash,
        form_error,
        task_id,
        ..Default::default()
    };
    match state.db.list_policies() {
        Ok(policies) => {
            view.policy = policies
                .into_iter()
                .find(|p| p.id == id)
                .map(PolicyRow::new);
        }
        Err(e) => view.error = Some(format!("could not read policies: {e:#}")),
    }
    view
}

async fn policy_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    page(PolicyDetailTemplate {
        user,
        view: gather_policy_detail(&state, id, None, None, None).await,
    })
}

async fn policy_detail(
    state: &AppState,
    id: i64,
    flash: Option<String>,
    form_error: Option<String>,
) -> Response {
    page(PolicyDetailPartial {
        view: gather_policy_detail(state, id, flash, form_error, None).await,
    })
}

// ---- Per-snapshot page (destroy) ----

#[derive(Default)]
pub struct SnapDetailView {
    /// `None` when no snapshot by this name exists on the host.
    pub snap: Option<SnapRow>,
    pub name: String,
    pub error: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "snap_detail.html")]
struct SnapDetailTemplate {
    user: CurrentUser,
    view: SnapDetailView,
}

#[derive(Template)]
#[template(path = "_snap_detail.html")]
struct SnapDetailPartial {
    view: SnapDetailView,
}

async fn gather_snap_detail(
    name: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> SnapDetailView {
    let mut view = SnapDetailView {
        name: name.to_owned(),
        flash,
        form_error,
        task_id,
        ..Default::default()
    };
    match actual::zfs::snapshots().await {
        Ok(Some(snaps)) => {
            view.snap = snaps.into_iter().find(|s| s.name == name).map(SnapRow::new);
        }
        // ZFS not installed — leave the snapshot unset (renders as not found).
        Ok(None) => {}
        Err(e) => view.error = Some(format!("could not list snapshots: {e:#}")),
    }
    view
}

async fn snap_detail_page(
    State(_): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(name): Path<String>,
) -> Response {
    page(SnapDetailTemplate {
        user,
        view: gather_snap_detail(&name, None, None, None).await,
    })
}

async fn snap_detail(
    name: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> Response {
    page(SnapDetailPartial {
        view: gather_snap_detail(name, flash, form_error, task_id).await,
    })
}

#[derive(Deserialize)]
struct PolicyForm {
    dataset: String,
    cron: String,
    prefix: String,
    #[serde(default)]
    keep_last: String,
    #[serde(default)]
    keep_days: String,
}

fn parse_keep(s: &str) -> Result<Option<u32>, ()> {
    match s.trim() {
        "" => Ok(None),
        n => n.parse().map(Some).map_err(|_| ()),
    }
}

async fn policy_create(
    State(state): State<Arc<AppState>>,
    Form(form): Form<PolicyForm>,
) -> Response {
    if DatasetName::new(form.dataset.trim()).is_err() {
        return render(
            &state,
            None,
            Some(format!("invalid dataset {:?}", form.dataset)),
            None,
        )
        .await;
    }
    let cron = form.cron.trim().to_owned();
    if cron.parse::<croner::Cron>().is_err() {
        return render(
            &state,
            None,
            Some(format!("invalid cron expression {cron:?}")),
            None,
        )
        .await;
    }
    if SnapName::new(form.prefix.trim()).is_err() {
        return render(
            &state,
            None,
            Some(format!("invalid prefix {:?}", form.prefix)),
            None,
        )
        .await;
    }
    let (Ok(keep_last), Ok(keep_days)) = (parse_keep(&form.keep_last), parse_keep(&form.keep_days))
    else {
        return render(
            &state,
            None,
            Some("keep limits must be numbers or empty".into()),
            None,
        )
        .await;
    };
    let policy = SnapshotPolicy {
        id: 0,
        dataset: form.dataset.trim().into(),
        cron,
        prefix: form.prefix.trim().into(),
        keep_last,
        keep_days,
        enabled: true,
        last_run: 0,
    };
    match state.db.insert_policy(&policy) {
        Ok(_) => {
            render(
                &state,
                Some(format!("policy created for {}", policy.dataset)),
                None,
                None,
            )
            .await
        }
        Err(e) => render(&state, None, Some(format!("{e:#}")), None).await,
    }
}

#[derive(Deserialize)]
struct IdForm {
    id: i64,
    #[serde(default)]
    enable: Option<bool>,
}

async fn policy_toggle(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let enable = form.enable.unwrap_or(false);
    match state.db.set_policy_enabled(form.id, enable) {
        Ok(()) => {
            let flash = format!("policy {}", if enable { "enabled" } else { "disabled" });
            policy_detail(&state, form.id, Some(flash), None).await
        }
        Err(e) => policy_detail(&state, form.id, None, Some(format!("{e:#}"))).await,
    }
}

async fn policy_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<IdForm>,
) -> Response {
    match state.db.delete_policy(form.id) {
        Ok(()) => nav_redirect(&headers, "/snapshots"),
        Err(e) => policy_detail(&state, form.id, None, Some(format!("{e:#}"))).await,
    }
}

#[derive(Deserialize)]
struct ManualForm {
    dataset: String,
    name: String,
}

async fn manual_snapshot(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ManualForm>,
) -> Response {
    let (Ok(dataset), Ok(snap)) = (
        DatasetName::new(form.dataset.trim()),
        SnapName::new(form.name.trim()),
    ) else {
        return render(
            &state,
            None,
            Some("invalid dataset or snapshot name".into()),
            None,
        )
        .await;
    };
    let req = Request::SnapshotCreate {
        dataset: dataset.clone(),
        snap: snap.clone(),
    };
    let title = format!("snapshot {dataset}@{snap}");
    match crate::task_runner::start(&state, req, "snapshot-create", &title) {
        Ok(id) => render(&state, Some(format!("started {title}")), None, Some(id)).await,
        Err(e) => render(&state, None, Some(format!("{e:#}")), None).await,
    }
}

#[derive(Deserialize)]
struct SnapDeleteForm {
    name: String,
}

async fn snapshot_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SnapDeleteForm>,
) -> Response {
    let parts = form.name.split_once('@');
    let Some((dataset, snap)) = parts else {
        return snap_detail(&form.name, None, Some("invalid snapshot name".into()), None).await;
    };
    let (Ok(dataset), Ok(snap)) = (DatasetName::new(dataset), SnapName::new(snap)) else {
        return snap_detail(&form.name, None, Some("invalid snapshot name".into()), None).await;
    };
    let req = Request::SnapshotDestroy { dataset, snap };
    let title = format!("destroy {}", form.name);
    // Removing the snapshot means its page no longer applies — go back to the
    // index; the destroy task is viewable on /tasks.
    match crate::task_runner::start(&state, req, "snapshot-destroy", &title) {
        Ok(_) => nav_redirect(&headers, "/snapshots"),
        Err(e) => snap_detail(&form.name, None, Some(format!("{e:#}")), None).await,
    }
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[tokio::test]
    async fn policy_crud_and_manual_snapshot() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };
        let get = |path: &str| auth(HttpRequest::get(path).body(Body::empty()).unwrap());

        let (status, _, body) = send(&app, get("/snapshots")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Snapshot policies"), "{body}");

        // Bad cron rejected; good policy created, listed, and linked to its page.
        let req = auth(form_post(
            "/snapshots/policy/create",
            "dataset=tank%2Fvm1&cron=not+a+cron&prefix=greendot-auto&keep_last=&keep_days=",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("invalid cron expression"), "{body}");
        let req = auth(form_post(
            "/snapshots/policy/create",
            "dataset=tank%2Fvm1&cron=0+2+*+*+*&prefix=greendot-auto&keep_last=7&keep_days=30",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("policy created for tank/vm1"), "{body}");
        assert!(body.contains("last 7, 30 days"), "{body}");
        assert!(body.contains("never"), "{body}");
        assert!(body.contains("/snapshots/policy/1"), "{body}");

        // The policy page renders, and an unknown id is a graceful not-found.
        let (status, _, body) = send(&app, get("/snapshots/policy/1")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("tank/vm1"), "{body}");
        let (status, _, body) = send(&app, get("/snapshots/policy/999")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Policy not found"), "{body}");

        // Toggle stays on the policy page; delete redirects back to the list.
        let (_, _, body) = send(
            &app,
            auth(form_post("/snapshots/policy/toggle", "id=1&enable=false")),
        )
        .await;
        assert!(body.contains("policy disabled"), "{body}");
        let (status, headers, _) =
            send(&app, auth(form_post("/snapshots/policy/delete", "id=1"))).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/snapshots");

        // Manual snapshot dispatches a background task and stays on the index,
        // linking to the task it just started.
        let req = auth(form_post(
            "/snapshots/manual",
            "dataset=tank%2Fvm1&name=before-upgrade",
        ));
        let (_, _, body) = send(&app, req).await;
        assert!(
            body.contains("started snapshot tank/vm1@before-upgrade"),
            "{body}"
        );
        assert!(body.contains("view task"), "{body}");

        // An unknown snapshot name renders gracefully (never 500).
        let (status, _, body) = send(&app, get("/snapshots/snap/tank%2Fvm1%40nope")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("not found"), "{body}");

        // Destroy redirects back to the list.
        let req = auth(form_post(
            "/snapshots/delete",
            "name=tank%2Fvm1%40before-upgrade",
        ));
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "non-htmx POST redirects");
        assert_eq!(headers[header::LOCATION], "/snapshots");
    }
}
