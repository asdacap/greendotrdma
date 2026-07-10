//! SSH keys authorized to open a `greendotctl pipe` session — the Kubernetes
//! CSI controller's login today, and the only way to drive the helper without
//! a root credential.
//!
//! The page is a thin view over one `PipeAccessReport` read: the box's
//! `authorized_keys` is the single source of truth, so nothing is mirrored in
//! the web's own database and nothing here can drift from what sshd reads.
//!
//! Adding a key is a privileged grant, so the request carries only the pasted
//! public key. The daemon writes the `command="…",restrict` options itself —
//! this module never spells them, and could not widen a grant if it tried.

use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::dot::{Criterion, pipe_access_criteria};
use askama::Template;
use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::ops::SshPublicKeyLine;
use greendot_proto::{SshFingerprint, ops, pb};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ssh-access", get(access_page))
        .route("/ssh-access/add", post(add))
        .route("/ssh-access/revoke", post(revoke))
        .route("/ssh-access/diagnose", get(diagnose_page))
}

struct KeyRow {
    fingerprint: String,
    algorithm: String,
    /// The key's comment. Empty when the paste carried none.
    label: String,
    /// What the revoke dialog asks the admin to type back.
    confirm: String,
    forced_command_ok: bool,
    options: String,
}

/// A `known_hosts` line the admin can paste, with `host` taken from the
/// address their own browser reached the box by — the daemon cannot know it.
struct HostKeyRow {
    algorithm: String,
    fingerprint: String,
    known_hosts_line: String,
}

struct SshAccessView {
    user: String,
    socket_group: String,
    forced_command: String,
    rows: Vec<KeyRow>,
    host_keys: Vec<HostKeyRow>,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
    /// Any criterion failing — the page then offers Diagnose, as the export
    /// pages do when a dot is not green.
    degraded: bool,
}

#[derive(Template)]
#[template(path = "ssh_access.html")]
struct SshAccessTemplate {
    user: CurrentUser,
    view: SshAccessView,
}

#[derive(Template)]
#[template(path = "_ssh_access.html")]
struct SshAccessPartial {
    view: SshAccessView,
}

struct DiagnoseView {
    user: String,
    criteria: Vec<Criterion>,
}

#[derive(Template)]
#[template(path = "ssh_access_diagnose.html")]
struct DiagnoseTemplate {
    user: CurrentUser,
    view: DiagnoseView,
}

/// The host the admin's browser used, falling back to the configured listen
/// address — the same rule the client-access connection string follows.
fn request_host(state: &AppState, headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| state.listen.to_string())
}

/// A `known_hosts` entry keys on the host *without* a port, unless the port is
/// non-standard, in which case OpenSSH wants `[host]:port`. SSH is on 22 here,
/// so strip whatever port the web is listening on.
fn known_hosts_host(host: &str) -> &str {
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

async fn gather(
    state: &AppState,
    headers: &HeaderMap,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> SshAccessView {
    let report = state.helper.pipe_access_report().await;
    let host = known_hosts_host(&request_host(state, headers)).to_owned();
    view_from(report, &host, flash, form_error, task_id)
}

/// The whole page is a projection of one report; `host` only decides which
/// name the `known_hosts` lines are keyed on.
fn view_from(
    report: pb::PipeAccessReportReply,
    host: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> SshAccessView {
    let degraded = pipe_access_criteria(&report).iter().any(|c| !c.ok);

    let rows = report
        .keys
        .iter()
        .map(|k| KeyRow {
            // With no comment there is nothing memorable to type, so the
            // fingerprint is what the revoke dialog asks for.
            confirm: match k.comment.is_empty() {
                true => k.fingerprint.clone(),
                false => k.comment.clone(),
            },
            fingerprint: k.fingerprint.clone(),
            algorithm: k.algorithm.clone(),
            label: k.comment.clone(),
            forced_command_ok: k.forced_command_ok,
            options: k.options.clone(),
        })
        .collect();
    let host_keys = report
        .host_keys
        .iter()
        .map(|h| HostKeyRow {
            algorithm: h.algorithm.clone(),
            fingerprint: h.fingerprint.clone(),
            known_hosts_line: format!("{host} {}", h.key_line),
        })
        .collect();

    SshAccessView {
        user: report.user,
        socket_group: report.socket_group,
        forced_command: report.forced_command,
        rows,
        host_keys,
        flash,
        form_error,
        task_id,
        degraded,
    }
}

async fn access_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
) -> Response {
    page(SshAccessTemplate {
        user,
        view: gather(&state, &headers, None, None, None).await,
    })
}

#[derive(Deserialize)]
struct AddForm {
    public_key: String,
    /// Optional override for the key's own comment.
    label: String,
}

/// Re-label the pasted key when the admin typed one: the comment is the only
/// place a label can live, because `authorized_keys` is the only store.
fn labelled(public_key: &str, label: &str) -> String {
    let label = label.trim();
    if label.is_empty() {
        return public_key.trim().to_owned();
    }
    let mut fields = public_key.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(algorithm), Some(base64)) => format!("{algorithm} {base64} {label}"),
        // Malformed: hand it to the validator unchanged, which will reject it.
        _ => public_key.trim().to_owned(),
    }
}

async fn add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AddForm>,
) -> Response {
    let public_key = match SshPublicKeyLine::new(labelled(&form.public_key, &form.label)) {
        Ok(key) => key,
        Err(_) => {
            // The paste is never echoed back: it may be a private key someone
            // put in the wrong box.
            let msg = "not an OpenSSH public key — paste one line, as in \
                       `ssh-ed25519 AAAA… admin@laptop`";
            return page(SshAccessPartial {
                view: gather(&state, &headers, None, Some(msg.into()), None).await,
            });
        }
    };
    let title = format!("Authorize SSH key {}", public_key.fingerprint());
    let stream = state.helper.pipe_key_add(ops::PipeKeyAdd { public_key });
    let view = match crate::task_runner::start(&state, stream, "pipe-key-add", &title) {
        Ok(id) => {
            gather(
                &state,
                &headers,
                Some(format!("started {title}")),
                None,
                Some(id),
            )
            .await
        }
        Err(e) => gather(&state, &headers, None, Some(format!("{e:#}")), None).await,
    };
    page(SshAccessPartial { view })
}

#[derive(Deserialize)]
struct RevokeForm {
    fingerprint: String,
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    let fingerprint = match SshFingerprint::new(form.fingerprint.trim()) {
        Ok(fp) => fp,
        Err(e) => {
            return page(SshAccessPartial {
                view: gather(&state, &headers, None, Some(e.to_string()), None).await,
            });
        }
    };
    let title = format!("Revoke SSH key {fingerprint}");
    let stream = state
        .helper
        .pipe_key_revoke(ops::PipeKeyRevoke { fingerprint });
    let view = match crate::task_runner::start(&state, stream, "pipe-key-revoke", &title) {
        Ok(id) => {
            gather(
                &state,
                &headers,
                Some(format!("started {title}")),
                None,
                Some(id),
            )
            .await
        }
        Err(e) => gather(&state, &headers, None, Some(format!("{e:#}")), None).await,
    };
    page(SshAccessPartial { view })
}

async fn diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let report: pb::PipeAccessReportReply = state.helper.pipe_access_report().await;
    page(DiagnoseTemplate {
        user,
        view: DiagnoseView {
            user: report.user.clone(),
            criteria: pipe_access_criteria(&report),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{SshAccessPartial, known_hosts_host, labelled, view_from};
    use askama::Template;
    use greendot_proto::pb;

    /// The populated page: a key we wrote, a key we did not (which must be
    /// flagged rather than silently listed), and a host key rendered into a
    /// pasteable known_hosts line. The route tests only ever see an empty
    /// report, so this is what covers the interesting markup.
    #[test]
    fn populated_page_flags_a_shell_key_and_renders_known_hosts() {
        let report = pb::PipeAccessReportReply {
            user: "greendot-csi".into(),
            socket_group: "greendot".into(),
            forced_command: "command=\"/usr/libexec/greendotrdma/greendotctl pipe\",restrict"
                .into(),
            keys: vec![
                pb::PipeKeyEntry {
                    fingerprint: "SHA256:aaa".into(),
                    algorithm: "ssh-ed25519".into(),
                    comment: "k8s-prod".into(),
                    forced_command_ok: true,
                    options: "command=\"/usr/libexec/greendotrdma/greendotctl pipe\",restrict"
                        .into(),
                },
                pb::PipeKeyEntry {
                    fingerprint: "SHA256:bbb".into(),
                    algorithm: "ssh-rsa".into(),
                    comment: String::new(),
                    forced_command_ok: false,
                    options: String::new(),
                },
            ],
            host_keys: vec![pb::HostKey {
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:hhh".into(),
                key_line: "ssh-ed25519 AAAAC3Nza".into(),
            }],
            ..Default::default()
        };
        let view = view_from(report, "10.0.0.5", None, None, None);
        // A key with no comment is revoked by typing its fingerprint back.
        assert_eq!(view.rows[1].confirm, "SHA256:bbb");
        let html = SshAccessPartial { view }.render().unwrap();

        assert!(html.contains("k8s-prod"));
        assert!(
            html.contains("Full shell"),
            "the bare key is flagged: {html}"
        );
        assert!(
            html.contains("10.0.0.5 ssh-ed25519 AAAAC3Nza"),
            "known_hosts line"
        );
        assert!(html.contains("data-confirm-path=\"SHA256:bbb\""));
        // Report facts are all false here, so the page offers its diagnostic.
        assert!(html.contains("/ssh-access/diagnose"));
    }

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 admin@laptop";

    #[test]
    fn label_replaces_the_pasted_comment_and_host_drops_the_web_port() {
        let base =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26";
        assert_eq!(labelled(KEY, "k8s-prod"), format!("{base} k8s-prod"));
        // No label given: the key's own comment survives.
        assert_eq!(labelled(KEY, "  "), KEY);
        // A comment-less paste gains one.
        assert_eq!(labelled(base, "k8s"), format!("{base} k8s"));
        // known_hosts keys on the ssh host, not the web's listen port.
        assert_eq!(known_hosts_host("10.0.0.5:8443"), "10.0.0.5");
        assert_eq!(known_hosts_host("box.local"), "box.local");
    }

    mod routes {
        use crate::routes::testutil::{form_post, login, send, test_app};
        use axum::body::Body;
        use axum::http::{Request, StatusCode};

        const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 admin@laptop";

        #[tokio::test]
        async fn add_dispatches_a_task_and_a_bad_paste_is_reported_not_echoed() {
            let app = test_app();
            let (cookie, csrf) = login(&app).await;
            let auth = |mut r: Request<Body>| {
                r.headers_mut().insert("cookie", cookie.parse().unwrap());
                r.headers_mut()
                    .insert("x-greendot-csrf", csrf.parse().unwrap());
                r
            };

            let body = format!("public_key={}&label=k8s-prod", urlencoding(KEY));
            let (status, _, html) = send(&app, auth(form_post("/ssh-access/add", &body))).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                html.contains("view task"),
                "the task link is offered: {html}"
            );

            // A private key pasted by mistake must not come back in the page.
            let body = format!(
                "public_key={}&label=",
                urlencoding("-----BEGIN OPENSSH PRIVATE KEY-----")
            );
            let (_, _, html) = send(&app, auth(form_post("/ssh-access/add", &body))).await;
            assert!(html.contains("not an OpenSSH public key"));
            assert!(!html.contains("BEGIN OPENSSH"), "the paste is not echoed");

            // A malformed fingerprint never reaches the daemon.
            let (_, _, html) = send(
                &app,
                auth(form_post("/ssh-access/revoke", "fingerprint=../../etc")),
            )
            .await;
            assert!(html.contains("invalid SSH fingerprint"));
        }

        /// Mutations are state-changing, so they carry the CSRF header.
        #[tokio::test]
        async fn add_without_csrf_is_rejected() {
            let app = test_app();
            let (cookie, _) = login(&app).await;
            let mut req = form_post("/ssh-access/add", "public_key=x&label=");
            req.headers_mut().insert("cookie", cookie.parse().unwrap());
            let (status, _, _) = send(&app, req).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        fn urlencoding(s: &str) -> String {
            s.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect()
        }
    }
}
