use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::state::{SubTaskRecord, Task, TaskStatus};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use greendot_proto::{SubStatus, TaskEvent};
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

/// A subtask's dot: pending (yellow) until it finishes, then per its status. The
/// grey `.dot-gray` (already in the stylesheet) marks a `Skipped` step.
fn sub_dot_class(status: Option<SubStatus>) -> &'static str {
    match status {
        Some(SubStatus::Success) => "dot-green",
        Some(SubStatus::Failed) => "dot-red",
        Some(SubStatus::Skipped) => "dot-gray",
        None => "dot-yellow",
    }
}

fn status_str(status: SubStatus) -> &'static str {
    match status {
        SubStatus::Success => "success",
        SubStatus::Failed => "failed",
        SubStatus::Skipped => "skipped",
    }
}

/// The `$ cmd args` header for a command subtask (`None` for a plain multi-step
/// subtask, whose own `$ …` echoes live in its output).
fn sub_command_line(command: &Option<String>, args: &[String]) -> Option<String> {
    command.as_ref().map(|c| {
        if args.is_empty() {
            format!("$ {c}")
        } else {
            format!("$ {c} {}", args.join(" "))
        }
    })
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

/// A server-rendered subtask block on the detail page: its dot, label, optional
/// command header, and an (initially empty) `<pre>` the SSE stream fills. The
/// EventSource `ensure()` adopts these by `data-index`, so live output lands in
/// the existing block rather than duplicating it.
pub struct SubTaskView {
    pub index: usize,
    pub name: String,
    pub command_line: Option<String>,
    pub dot_class: &'static str,
}

fn sub_views(t: &Task) -> Vec<SubTaskView> {
    t.subtasks
        .iter()
        .enumerate()
        .map(|(index, s)| SubTaskView {
            index,
            name: s.name.clone(),
            command_line: sub_command_line(&s.command, &s.args),
            dot_class: sub_dot_class(s.status),
        })
        .collect()
}

#[derive(Template)]
#[template(path = "task_detail.html")]
struct TaskDetailTemplate {
    user: CurrentUser,
    task: TaskRow,
    subtasks: Vec<SubTaskView>,
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
            subtasks: sub_views(&t),
            task: row(&t),
        }),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

/// SSE stream of a task's per-subtask output. Every event's data is JSON so the
/// client routes it by subtask `index`: `subtask {index,name,command}`,
/// `output {index,stream,data}`, `substatus {index,status}`, then a terminal
/// `done` ("ok"/"fail") — whose shape is unchanged, so the base-template 5 s
/// success watcher keeps working. A running task replays its live snapshot then
/// streams; a finished one replays its persisted subtasks.
async fn task_stream(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Response {
    if let Some((subs, rx)) = state.tasks.snapshot_and_subscribe(id) {
        let initial = replay_subtasks(&subs);
        // Seed the live mapper past the snapshot so its indices continue from
        // where the snapshot left off (a wrong seed misroutes reconnect output).
        let mut mapper = LiveMapper {
            next: subs.len(),
            current: subs.len().checked_sub(1),
        };
        let live = BroadcastStream::new(rx)
            .filter_map(move |ev| ev.ok().and_then(|e| mapper.map(e)).map(Ok::<_, Infallible>));
        let stream = tokio_stream::iter(initial.into_iter().map(Ok::<_, Infallible>)).chain(live);
        return sse(stream);
    }
    // Not running: replay the persisted subtasks, then done.
    match state.db.get_task(id) {
        Ok(Some(t)) => {
            let mut events = replay_subtasks(&t.subtasks);
            events.push(done_event(t.status == TaskStatus::Success));
            sse(tokio_stream::iter(events.into_iter().map(Ok)))
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

/// The subtask/output/substatus events that reconstruct a list of subtask
/// records — the snapshot replay shared by the running and finished branches.
fn replay_subtasks(subs: &[SubTaskRecord]) -> Vec<Event> {
    let mut events = Vec::new();
    for (index, s) in subs.iter().enumerate() {
        events.push(subtask_event(
            index,
            &s.name,
            sub_command_line(&s.command, &s.args),
        ));
        if !s.stdout.is_empty() {
            events.push(output_event(index, "stdout", &s.stdout));
        }
        if !s.stderr.is_empty() {
            events.push(output_event(index, "stderr", &s.stderr));
        }
        if let Some(status) = s.status {
            events.push(substatus_event(index, status));
        }
    }
    events
}

/// Maps the live event stream to SSE events, tracking the current subtask index
/// so `output`/`substatus` attach to the right block. Seeded from the snapshot
/// length on (re)subscribe.
struct LiveMapper {
    /// Index the next `SubtaskStarted` will claim.
    next: usize,
    /// The open subtask output attributes to (`None` before any subtask).
    current: Option<usize>,
}

impl LiveMapper {
    fn map(&mut self, ev: TaskEvent) -> Option<Event> {
        match ev {
            TaskEvent::SubtaskStarted {
                name,
                command,
                args,
                ..
            } => {
                let index = self.next;
                self.next += 1;
                self.current = Some(index);
                Some(subtask_event(
                    index,
                    &name,
                    sub_command_line(&command, &args),
                ))
            }
            TaskEvent::Stdout { data } => Some(output_event(self.current_index(), "stdout", &data)),
            TaskEvent::Stderr { data } => Some(output_event(self.current_index(), "stderr", &data)),
            TaskEvent::SubtaskFinished { status, .. } => {
                Some(substatus_event(self.current_index(), status))
            }
            TaskEvent::Finished { status, .. } => Some(done_event(status != SubStatus::Failed)),
        }
    }

    /// The subtask output belongs to, synthesizing an `"output"` index for stray
    /// output before any `SubtaskStarted` (mirrors the persistence reducer).
    fn current_index(&mut self) -> usize {
        match self.current {
            Some(i) => i,
            None => {
                let i = self.next;
                self.next += 1;
                self.current = Some(i);
                i
            }
        }
    }
}

fn subtask_event(index: usize, name: &str, command: Option<String>) -> Event {
    Event::default()
        .event("subtask")
        .data(serde_json::json!({ "index": index, "name": name, "command": command }).to_string())
}

fn output_event(index: usize, stream: &str, data: &str) -> Event {
    Event::default()
        .event("output")
        .data(serde_json::json!({ "index": index, "stream": stream, "data": data }).to_string())
}

fn substatus_event(index: usize, status: SubStatus) -> Event {
    Event::default()
        .event("substatus")
        .data(serde_json::json!({ "index": index, "status": status_str(status) }).to_string())
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
