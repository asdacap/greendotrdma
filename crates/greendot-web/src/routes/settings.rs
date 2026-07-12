use super::{AppState, page};
use crate::actual::rdma;
use crate::auth::CurrentUser;
use crate::routes::block_export::reconcile_state;
use askama::Template;
use axum::extract::{Form, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::ops;
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings", get(settings_page))
        .route("/settings/reconcile", post(reconcile_now))
        .route("/settings/listen", post(set_listen))
        .route("/settings/install", post(install_deps))
}

pub struct RdmaRow {
    pub name: String,
    pub netdev: String,
    pub state: &'static str,
    pub addrs: String,
}

pub struct DepRow {
    pub cli: &'static str,
    pub package: String,
    pub present: bool,
}

pub struct SettingsView {
    pub listen_addr: String,
    pub rdma_devs: Vec<RdmaRow>,
    pub deps: Vec<DepRow>,
    /// Missing packages apt can install here — the one-click "Install missing".
    pub installable_packages: String,
    /// Missing packages with no apt candidate — must be installed manually.
    pub manual_packages: String,
    /// Detected OS label (for display).
    pub os_pretty: String,
    /// Whether the one-click installer can drive this OS (Debian/Ubuntu).
    pub install_supported: bool,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
}

/// True if `cli` is found on PATH (unprivileged check).
fn cli_present(cli: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(cli).is_file()))
        .unwrap_or(false)
}

/// Split missing packages into those apt can install on this host (first) and
/// those with no apt candidate, which must be installed manually (second).
fn partition_missing(
    missing: Vec<String>,
    available: &std::collections::HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    missing.into_iter().partition(|p| available.contains(p))
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    user: CurrentUser,
    view: SettingsView,
}

#[derive(Template)]
#[template(path = "_settings.html")]
struct SettingsPartial {
    view: SettingsView,
}

async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> SettingsView {
    let devs = rdma::devices(&state.helper).await;
    let deps: Vec<DepRow> = greendot_proto::os::REQUIRED_CLIS
        .iter()
        .map(|&cli| DepRow {
            cli,
            package: greendot_proto::os::package_for_cli(cli)
                .unwrap_or("")
                .to_string(),
            present: cli_present(cli),
        })
        .collect();
    let mut missing: Vec<String> = deps
        .iter()
        .filter(|d| !d.present && !d.package.is_empty())
        .map(|d| d.package.clone())
        .collect();
    missing.sort();
    missing.dedup();
    let os = greendot_proto::os::detect();
    let install_supported = matches!(os.family, greendot_proto::os::PkgFamily::Debian);
    // Only packages apt can actually install belong in the one-click button; the
    // rest (e.g. nvmetcli, which Ubuntu has never packaged) get a manual-install hint.
    // On non-apt distros there is nothing the in-app installer can supply.
    let available = if install_supported {
        crate::actual::apt::available(&missing).await
    } else {
        std::collections::HashSet::new()
    };
    let (installable, manual) = partition_missing(missing, &available);
    SettingsView {
        install_supported,
        os_pretty: os.pretty,
        installable_packages: installable.join(" "),
        manual_packages: manual.join(" "),
        deps,
        listen_addr: state
            .db
            .get_setting("listen_addr")
            .ok()
            .flatten()
            .unwrap_or_else(|| "0.0.0.0".into()),
        rdma_devs: devs
            .into_iter()
            .map(|d| RdmaRow {
                name: d.name,
                netdev: d.netdev.unwrap_or_else(|| "?".into()),
                state: if d.active { "active" } else { "down" },
                addrs: d
                    .addrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            })
            .collect(),
        flash,
        task_id,
        form_error,
    }
}

async fn settings_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(SettingsTemplate {
        user,
        view: gather(&state, None, None, None).await,
    })
}

async fn reconcile_now(State(state): State<Arc<AppState>>) -> Response {
    let (flash, error, task_id) = match reconcile_state(&state).await {
        Ok(Some(id)) => (Some("reconcile started".into()), None, Some(id)),
        Ok(None) => (Some("already reconciled".into()), None, None),
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    page(SettingsPartial {
        view: gather(&state, flash, error, task_id).await,
    })
}

#[derive(Deserialize)]
struct ListenForm {
    listen_addr: String,
}

async fn set_listen(State(state): State<Arc<AppState>>, Form(form): Form<ListenForm>) -> Response {
    let addr = form.listen_addr.trim();
    if addr.parse::<std::net::IpAddr>().is_err() {
        return page(SettingsPartial {
            view: gather(
                &state,
                None,
                Some(format!("invalid IP address {addr:?}")),
                None,
            )
            .await,
        });
    }
    let result = match state.db.set_setting("listen_addr", addr) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    let (flash, error, task_id) = match result {
        Ok(Some(id)) => (
            Some(format!("listen address set to {addr}; reconciling exports")),
            None,
            Some(id),
        ),
        Ok(None) => (Some(format!("listen address set to {addr}")), None, None),
        Err(e) => (None, Some(format!("{e:#}")), None),
    };
    page(SettingsPartial {
        view: gather(&state, flash, error, task_id).await,
    })
}

#[derive(Deserialize)]
struct InstallForm {
    /// Space-separated package names (from the dependency panel).
    packages: String,
}

async fn install_deps(
    State(state): State<Arc<AppState>>,
    Form(form): Form<InstallForm>,
) -> Response {
    let packages: Vec<greendot_proto::PackageName> = form
        .packages
        .split_whitespace()
        .filter_map(|p| greendot_proto::PackageName::new(p).ok())
        .collect();
    if packages.is_empty() {
        return page(SettingsPartial {
            view: gather(
                &state,
                None,
                Some("no valid packages to install".into()),
                None,
            )
            .await,
        });
    }
    let names = packages
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let req = ops::InstallPackages { packages };
    let title = format!("install {names}");
    let view = match crate::task_runner::start(
        &state,
        state.helper.install_packages(req),
        "install",
        &title,
    ) {
        Ok(id) => gather(&state, Some(format!("started {title}")), None, Some(id)).await,
        Err(e) => gather(&state, None, Some(format!("{e:#}")), None).await,
    };
    page(SettingsPartial { view })
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use std::collections::HashSet;

    #[test]
    fn partition_missing_splits_installable_from_manual() {
        // nvmetcli has no apt candidate (Ubuntu has never packaged it); the rest do.
        let missing = ["nvmetcli", "targetcli-fb", "nvme-cli"]
            .map(String::from)
            .to_vec();
        let available: HashSet<String> = ["targetcli-fb", "nvme-cli"].map(String::from).into();
        let (installable, manual) = super::partition_missing(missing, &available);
        assert_eq!(installable, ["targetcli-fb", "nvme-cli"]);
        assert_eq!(manual, ["nvmetcli"]);
    }

    #[tokio::test]
    async fn settings_page_listen_addr() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        // The page renders and links out to the dedicated NIC page (the NIC
        // table itself now lives under /nic).
        let req = auth(HttpRequest::get("/settings").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Default target listen address"), "{body}");
        assert!(body.contains("href=\"/nic\""), "{body}");

        // Valid listen address persists; invalid is rejected.
        let (_, _, body) = send(
            &app,
            auth(form_post("/settings/listen", "listen_addr=10.0.0.5")),
        )
        .await;
        assert!(body.contains("listen address set to 10.0.0.5"), "{body}");
        let (_, _, body) = send(
            &app,
            auth(form_post("/settings/listen", "listen_addr=junk")),
        )
        .await;
        assert!(body.contains("invalid IP address"), "{body}");
    }
}
