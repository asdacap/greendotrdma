use super::{AppState, page};
use crate::actual::rdma;
use crate::auth::CurrentUser;
use crate::routes::exports::reconcile_state;
use askama::Template;
use axum::extract::{Form, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{KernelModule, NetdevName, Request, Response as HelperResponse};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings", get(settings_page))
        .route("/settings/listen", post(set_listen))
        .route("/settings/rxe", post(enable_rxe))
}

pub struct RdmaRow {
    pub name: String,
    pub netdev: String,
    pub state: &'static str,
    pub addrs: String,
}

pub struct SettingsView {
    pub listen_addr: String,
    pub rdma_devs: Vec<RdmaRow>,
    pub plain_netdevs: Vec<String>,
    pub flash: Option<String>,
    pub form_error: Option<String>,
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

fn gather(state: &AppState, flash: Option<String>, form_error: Option<String>) -> SettingsView {
    let devs = rdma::devices();
    let netdev_addrs = rdma::netdev_addrs();
    let rdma_backed: Vec<&str> = devs.iter().filter_map(|d| d.netdev.as_deref()).collect();
    let mut plain_netdevs: Vec<String> = netdev_addrs
        .keys()
        .filter(|n| !rdma_backed.contains(&n.as_str()))
        .cloned()
        .collect();
    plain_netdevs.sort();
    SettingsView {
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
        plain_netdevs,
        flash,
        form_error,
    }
}

async fn settings_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(SettingsTemplate {
        user,
        view: gather(&state, None, None),
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
            view: gather(&state, None, Some(format!("invalid IP address {addr:?}"))),
        });
    }
    let result = match state.db.set_setting("listen_addr", addr) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    let (flash, error) = match result {
        Ok(()) => (
            Some(format!("listen address set to {addr}; exports reconciled")),
            None,
        ),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(SettingsPartial {
        view: gather(&state, flash, error),
    })
}

#[derive(Deserialize)]
struct RxeForm {
    netdev: String,
}

async fn enable_rxe(State(state): State<Arc<AppState>>, Form(form): Form<RxeForm>) -> Response {
    let Ok(netdev) = NetdevName::new(form.netdev.trim()) else {
        return page(SettingsPartial {
            view: gather(
                &state,
                None,
                Some(format!("invalid interface name {:?}", form.netdev)),
            ),
        });
    };
    let steps = [
        Request::EnsureModules {
            modules: vec![KernelModule::Rxe],
        },
        Request::RxeLinkAdd {
            netdev: netdev.clone(),
        },
    ];
    for req in steps {
        match state.helper.call(req).await {
            Ok(HelperResponse::Ok) => {}
            Ok(HelperResponse::Err { message, .. }) => {
                return page(SettingsPartial {
                    view: gather(&state, None, Some(message)),
                });
            }
            Ok(other) => {
                return page(SettingsPartial {
                    view: gather(
                        &state,
                        None,
                        Some(format!("unexpected helper response: {other:?}")),
                    ),
                });
            }
            Err(e) => {
                return page(SettingsPartial {
                    view: gather(&state, None, Some(format!("helper unavailable: {e:#}"))),
                });
            }
        }
    }
    let _ = reconcile_state(&state).await;
    page(SettingsPartial {
        view: gather(&state, Some(format!("Soft-RoCE enabled on {netdev}")), None),
    })
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[tokio::test]
    async fn settings_page_listen_addr_and_rxe_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        let req = auth(HttpRequest::get("/settings").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Listen address"), "{body}");

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

        // Soft-RoCE enable round-trips through the fake helper.
        let (_, _, body) = send(&app, auth(form_post("/settings/rxe", "netdev=eth0"))).await;
        assert!(body.contains("Soft-RoCE enabled on eth0"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/settings/rxe", "netdev=bad%2Fname"))).await;
        assert!(body.contains("invalid interface name"), "{body}");
    }
}
