use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::state::{Task, TaskStatus};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use greendot_proto::TaskEvent;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/tasks", get(tasks_page))
        .route("/tasks/{id}", get(task_detail))
        .route("/tasks/{id}/stream", get(task_stream))
}

pub struct TaskRow {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub command_line: String,
    pub dot_class: &'static str,
    pub status: &'static str,
    pub started: String,
    pub duration: String,
}

fn dot_class(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Running => "dot-yellow",
        TaskStatus::Success => "dot-green",
        TaskStatus::Failed => "dot-red",
    }
}

fn command_line(t: &Task) -> String {
    if t.command.is_empty() {
        return "(starting…)".into();
    }
    std::iter::once(t.command.clone())
        .chain(t.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn fmt_time(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

fn duration(t: &Task) -> String {
    match t.finished_at {
        Some(end) => format!("{}s", (end - t.started_at).max(0)),
        None => "running".into(),
    }
}

fn row(t: &Task) -> TaskRow {
    TaskRow {
        id: t.id,
        kind: t.kind.clone(),
        title: t.title.clone(),
        command_line: command_line(t),
        dot_class: dot_class(t.status),
        status: t.status.as_str(),
        started: fmt_time(t.started_at),
        duration: duration(t),
    }
}

#[derive(Template)]
#[template(path = "tasks.html")]
struct TasksTemplate {
    user: CurrentUser,
    rows: Vec<TaskRow>,
    error: Option<String>,
}

async fn tasks_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    // The list itself htmx-polls /tasks?partial; serve both from one handler.
    match state.db.list_tasks(200) {
        Ok(tasks) => page(TasksTemplate {
            user,
            rows: tasks.iter().map(row).collect(),
            error: None,
        }),
        Err(e) => page(TasksTemplate {
            user,
            rows: vec![],
            error: Some(format!("{e:#}")),
        }),
    }
}

#[derive(Template)]
#[template(path = "task_detail.html")]
struct TaskDetailTemplate {
    user: CurrentUser,
    task: TaskRow,
    stdin: Option<String>,
    error: Option<String>,
    running: bool,
}

async fn task_detail(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.get_task(id) {
        Ok(Some(t)) => page(TaskDetailTemplate {
            user,
            running: t.status == TaskStatus::Running,
            stdin: t.stdin.clone(),
            error: t.error.clone(),
            task: row(&t),
        }),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

/// SSE stream of a task's output: an initial `output` event with everything so
/// far, then live `output` events, then a `done` event whose data is `ok` or
/// `fail` (so a watcher can refresh only on success).
async fn task_stream(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    if let Some((stdout, stderr, rx)) = state.tasks.snapshot_and_subscribe(id) {
        let initial = output_event(format!("{stdout}{stderr}"));
        let live = BroadcastStream::new(rx).filter_map(|ev| match ev {
            Ok(TaskEvent::Stdout { data }) | Ok(TaskEvent::Stderr { data }) => {
                Some(Ok(output_event(data)))
            }
            Ok(TaskEvent::Finished { ok, .. }) => Some(Ok(done_event(ok))),
            _ => None,
        });
        let stream = tokio_stream::once(Ok(initial)).chain(live);
        return sse(stream);
    }
    // Not running: replay the stored output once, then done.
    match state.db.get_task(id) {
        Ok(Some(t)) => {
            let events = vec![
                Ok(output_event(format!("{}{}", t.stdout, t.stderr))),
                Ok(done_event(t.status == TaskStatus::Success)),
            ];
            sse(tokio_stream::iter(events))
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

fn output_event(data: String) -> Event {
    Event::default().event("output").data(data)
}

fn done_event(ok: bool) -> Event {
    Event::default()
        .event("done")
        .data(if ok { "ok" } else { "fail" })
}

fn sse(stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static) -> Response {
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[tokio::test]
    async fn mutations_are_recorded_as_tasks_and_visible() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        // An empty task list page renders.
        let req = auth(HttpRequest::get("/tasks").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Tasks"), "{body}");

        // A zvol create dispatches a task through the task runner (fake helper =>
        // success). Dispatch is non-blocking, so the run completes on a
        // background task.
        let req = auth(form_post(
            "/zfs/zvol",
            "parent=tank&name=vm1&size=10&unit=GiB&volblocksize=",
        ));
        let (status, _, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);

        // It appears on the tasks page; poll until the background run records it
        // green (it then also shows on its detail + stream).
        let mut body = String::new();
        for _ in 0..100 {
            let req = auth(HttpRequest::get("/tasks").body(Body::empty()).unwrap());
            body = send(&app, req).await.2;
            if body.contains("zvol-create") && body.contains("dot-green") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(body.contains("zvol-create"), "{body}");
        assert!(
            body.contains("dot-green"),
            "task should have succeeded: {body}"
        );

        let req = auth(HttpRequest::get("/tasks/1").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("create zvol") || body.contains("vm1"),
            "{body}"
        );

        let req = auth(
            HttpRequest::get("/tasks/1/stream")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .contains("event-stream")
        );
    }
}
