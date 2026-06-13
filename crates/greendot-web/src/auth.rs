//! Session auth backed by the helper's PAM check. Sessions live in process
//! memory (a web-service restart logs everyone out, which is fine for an
//! appliance). CSRF: every mutating request must carry the per-session token
//! in the `X-Greendot-Csrf` header; htmx adds it via `hx-headers` on `<body>`.

use crate::routes::{AppState, page};
use askama::Template;
use axum::extract::{Form, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use greendot_proto::{ErrKind, Secret, Username};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const SESSION_COOKIE: &str = "gd_session";
pub const CSRF_HEADER: &str = "x-greendot-csrf";

#[derive(Clone)]
pub struct Session {
    pub username: String,
    pub csrf: String,
    expires: Instant,
}

pub struct Sessions {
    inner: RwLock<HashMap<String, Session>>,
    ttl: Duration,
}

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Sessions {
            inner: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Returns the new session token and its CSRF token.
    pub fn create(&self, username: String, now: Instant) -> (String, String) {
        let (token, csrf) = (random_token(), random_token());
        let session = Session {
            username,
            csrf: csrf.clone(),
            expires: now + self.ttl,
        };
        self.inner.write().unwrap().insert(token.clone(), session);
        (token, csrf)
    }

    /// Looks up a live session and slides its expiry forward.
    pub fn get(&self, token: &str, now: Instant) -> Option<Session> {
        let mut sessions = self.inner.write().unwrap();
        match sessions.get_mut(token) {
            Some(session) if session.expires >= now => {
                session.expires = now + self.ttl;
                Some(session.clone())
            }
            Some(_) => {
                sessions.remove(token);
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, token: &str) {
        self.inner.write().unwrap().remove(token);
    }
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Info about the logged-in user, inserted into request extensions.
#[derive(Clone)]
pub struct CurrentUser {
    pub username: String,
    pub csrf: String,
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

/// Redirect that also works from an htmx request (HX-Redirect full reload).
pub fn nav_redirect(headers: &HeaderMap, to: &str) -> Response {
    if headers.contains_key("hx-request") {
        ([("HX-Redirect", to.to_owned())], StatusCode::OK).into_response()
    } else {
        Redirect::to(to).into_response()
    }
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let session = cookie_value(req.headers(), SESSION_COOKIE)
        .and_then(|token| state.sessions.get(&token, Instant::now()));
    let Some(session) = session else {
        return nav_redirect(req.headers(), "/login");
    };
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD);
    if mutating {
        let sent = req.headers().get(CSRF_HEADER).and_then(|v| v.to_str().ok());
        if sent != Some(session.csrf.as_str()) {
            return (StatusCode::FORBIDDEN, "missing or invalid CSRF token").into_response();
        }
    }
    req.extensions_mut().insert(CurrentUser {
        username: session.username,
        csrf: session.csrf,
    });
    next.run(req).await
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
}

pub async fn login_page() -> Response {
    page(LoginTemplate { error: None })
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login_post(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let Ok(username) = Username::new(form.username) else {
        return login_failed("invalid username or password");
    };
    let req = greendot_proto::Request::Authenticate {
        username,
        password: Secret(form.password),
    };
    match state.helper.call(req).await {
        Ok(greendot_proto::Response::OkAuth { username }) => {
            let (token, _) = state.sessions.create(username, Instant::now());
            (
                [(
                    header::SET_COOKIE,
                    session_cookie(&token, state.secure_cookies),
                )],
                Redirect::to("/"),
            )
                .into_response()
        }
        Ok(greendot_proto::Response::Err {
            kind: ErrKind::Busy,
            message,
        }) => login_failed(message),
        Ok(greendot_proto::Response::Err {
            kind: ErrKind::NotInAdminGroup,
            message,
        }) => login_failed(message),
        Ok(_) => login_failed("invalid username or password"),
        Err(e) => {
            tracing::error!(error = %e, "helper call failed during login");
            login_failed("authentication service unavailable")
        }
    }
}

pub async fn logout(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let headers = req.headers().clone();
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        state.sessions.remove(&token);
    }
    nav_redirect(&headers, "/login")
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/{secure}")
}

fn login_failed(message: impl Into<String>) -> Response {
    let mut resp = page(LoginTemplate {
        error: Some(message.into()),
    });
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_create_get_slide_expire_and_remove() {
        let t0 = Instant::now();
        let sessions = Sessions::new(Duration::from_secs(24 * 3600));
        let (token, csrf) = sessions.create("alice".into(), t0);
        assert_eq!(token.len(), 64, "32 random bytes hex-encoded");
        assert_ne!(token, csrf);

        let s = sessions.get(&token, t0).expect("fresh session resolves");
        assert_eq!(
            (s.username.as_str(), s.csrf.as_str()),
            ("alice", csrf.as_str())
        );
        assert!(sessions.get("wrong-token", t0).is_none());

        // Sliding renewal: active at +12h, so still alive at +30h (12h + 24h TTL)...
        let t12 = t0 + Duration::from_secs(12 * 3600);
        assert!(sessions.get(&token, t12).is_some());
        let t30 = t0 + Duration::from_secs(30 * 3600);
        assert!(sessions.get(&token, t30).is_some());
        // ...but gone after a >24h idle gap.
        let t60 = t0 + Duration::from_secs(60 * 3600);
        assert!(
            sessions.get(&token, t60).is_none(),
            "expired after idle TTL"
        );

        let (token2, _) = sessions.create("bob".into(), t0);
        sessions.remove(&token2);
        assert!(sessions.get(&token2, t0).is_none());
    }

    #[test]
    fn cookie_parsing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "a=1; gd_session=tok123; b=2".parse().unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, "gd_session").as_deref(),
            Some("tok123")
        );
        assert_eq!(cookie_value(&headers, "missing"), None);
        assert_eq!(cookie_value(&HeaderMap::new(), "gd_session"), None);
    }
}
