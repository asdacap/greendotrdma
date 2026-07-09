//! Client access tokens for the `/api/client/v1` JSON API (the greendot-client
//! app). Tokens are named and revocable; only the sha256 lands in the state
//! TOML. Creating one renders the full `greendot://` connection string exactly
//! once, with the host taken from the admin's own Host header (what their
//! browser reaches the box as) and the TLS fingerprint for cert pinning.

use super::{AppState, page};
use crate::auth::CurrentUser;
use askama::Template;
use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use sha2::Digest;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/client-access", get(access_page))
        .route("/client-access/create", post(create))
        .route("/client-access/revoke", post(revoke))
}

/// Lowercase-hex sha256 of a raw token — the only form that is stored.
pub fn token_hash(raw: &str) -> String {
    sha2::Sha256::digest(raw.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The one-way paste string: `greendot://<token>@<host>/?fp=<sha256>`. The
/// token rides in the URL userinfo (its charset is hex + `_`, all allowed);
/// `fp` is omitted on plain HTTP — the client then refuses, or connects
/// insecurely by explicit flag.
pub fn connection_string(host: &str, token: &str, fp: Option<&str>) -> String {
    match fp {
        Some(fp) => format!("greendot://{token}@{host}/?fp={fp}"),
        None => format!("greendot://{token}@{host}/"),
    }
}

/// The connection-string host: the Host header the admin's browser used,
/// falling back to the configured listen address.
fn request_host(state: &AppState, headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| state.listen.to_string())
}

struct TokenRow {
    id: i64,
    name: String,
    created: String,
}

/// The just-created token's reveal block, shown once.
struct NewToken {
    name: String,
    connection_string: String,
}

#[derive(Template)]
#[template(path = "client_access.html")]
struct ClientAccessTemplate {
    user: CurrentUser,
    view: ClientAccessView,
}

#[derive(Template)]
#[template(path = "_client_access.html")]
struct ClientAccessPartial {
    view: ClientAccessView,
}

struct ClientAccessView {
    rows: Vec<TokenRow>,
    new_token: Option<NewToken>,
    form_error: Option<String>,
    /// Plain HTTP: strings carry no fingerprint, warn the admin.
    no_tls: bool,
}

fn gather(
    state: &AppState,
    new_token: Option<NewToken>,
    form_error: Option<String>,
) -> ClientAccessView {
    let rows = match state.db.list_client_tokens() {
        Ok(tokens) => tokens
            .into_iter()
            .map(|t| TokenRow {
                id: t.id,
                name: t.name,
                created: chrono::DateTime::from_timestamp(t.created_at, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_default(),
            })
            .collect(),
        Err(_) => vec![],
    };
    ClientAccessView {
        rows,
        new_token,
        form_error,
        no_tls: state.tls_fingerprint.is_none(),
    }
}

async fn access_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(ClientAccessTemplate {
        user,
        view: gather(&state, None, None),
    })
}

#[derive(Deserialize)]
struct CreateForm {
    name: String,
}

async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Response {
    let name = form.name.trim();
    if name.is_empty() || name.len() > 64 {
        return page(ClientAccessPartial {
            view: gather(
                &state,
                None,
                Some("token name must be 1-64 characters".into()),
            ),
        });
    }
    let raw = format!("gdt_{}", crate::auth::random_token());
    let created = chrono::Utc::now().timestamp();
    let new_token = match state
        .db
        .insert_client_token(name, &token_hash(&raw), created)
    {
        Ok(_) => NewToken {
            name: name.to_owned(),
            connection_string: connection_string(
                &request_host(&state, &headers),
                &raw,
                state.tls_fingerprint.as_deref(),
            ),
        },
        Err(e) => {
            return page(ClientAccessPartial {
                view: gather(&state, None, Some(format!("{e:#}"))),
            });
        }
    };
    page(ClientAccessPartial {
        view: gather(&state, Some(new_token), None),
    })
}

#[derive(Deserialize)]
struct IdForm {
    id: i64,
}

async fn revoke(State(state): State<Arc<AppState>>, Form(form): Form<IdForm>) -> Response {
    let error = state.db.delete_client_token(form.id).err();
    page(ClientAccessPartial {
        view: gather(&state, None, error.map(|e| format!("{e:#}"))),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn connection_string_grammar_and_token_hash() {
        let s = super::connection_string("10.0.0.5:8443", "gdt_ab12", Some("ff00"));
        assert_eq!(s, "greendot://gdt_ab12@10.0.0.5:8443/?fp=ff00");
        // Standard-URL-parseable: userinfo carries the token.
        let url = s.strip_prefix("greendot://").unwrap();
        assert_eq!(url.split('@').next(), Some("gdt_ab12"));
        // Plain HTTP omits fp entirely.
        assert_eq!(
            super::connection_string("box.local:8080", "gdt_x", None),
            "greendot://gdt_x@box.local:8080/"
        );
        // sha256 of the whole raw string, lowercase hex.
        assert_eq!(
            super::token_hash("gdt_test"),
            "c2e862a649b52dee6b666c4bc7e696f869d839a5b0f3ab448573ffc6235dc873"
        );
    }

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::http::{Request as HttpRequest, StatusCode, header};

        #[tokio::test]
        async fn create_shows_string_once_and_revoke_removes() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut req: HttpRequest<Body>| {
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                req.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                req
            };

            // Page requires login.
            let (status, headers, _) = send(
                &app,
                HttpRequest::get("/client-access")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::SEE_OTHER);
            assert_eq!(headers[header::LOCATION], "/login");

            // Create: the connection string is revealed once, host from the Host
            // header, fp from the test AppState's fingerprint, with a copy button.
            let mut req = auth(form_post("/client-access/create", "name=laptop"));
            req.headers_mut()
                .insert(header::HOST, "box.example:8443".parse().unwrap());
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK);
            let fp = "aa".repeat(32);
            assert!(body.contains("greendot://gdt_"), "{body}");
            assert!(
                body.contains(&format!("@box.example:8443/?fp={fp}")),
                "{body}"
            );
            assert!(body.contains("data-copy"), "{body}");
            assert!(body.contains("will not be shown again"), "{body}");

            // Duplicate name rejected; empty name rejected.
            let (_, _, body) = send(
                &app,
                auth(form_post("/client-access/create", "name=laptop")),
            )
            .await;
            assert!(body.contains("already exists"), "{body}");
            let (_, _, body) = send(&app, auth(form_post("/client-access/create", "name="))).await;
            assert!(body.contains("1-64 characters"), "{body}");

            // A later render of the page lists the token but no raw string.
            let req = auth(
                HttpRequest::get("/client-access")
                    .body(Body::empty())
                    .unwrap(),
            );
            let (_, _, body) = send(&app, req).await;
            assert!(body.contains("laptop"), "{body}");
            assert!(!body.contains("greendot://gdt_"), "{body}");

            // Revoke removes the row (button carries the type-to-confirm gate).
            assert!(body.contains("data-confirm-path=\"laptop\""), "{body}");
            let (_, _, body) = send(&app, auth(form_post("/client-access/revoke", "id=1"))).await;
            assert!(body.contains("No client tokens yet"), "{body}");
        }
    }
}
