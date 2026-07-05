//! Runs a helper request as a recorded, streamable task: persists it to the
//! store, mirrors live output to SSE subscribers, and returns the outcome.

use crate::routes::AppState;
use crate::state::{SubTaskRecord, TaskStatus};
use greendot_proto::{Request, SubStatus, TaskEvent};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

/// Folds one task event into the running list of subtask records. Shared by the
/// live broadcast snapshot ([`TaskHub::broadcast`]) and the persisted reducer
/// ([`drive`]) so they can't drift. Stray output before any `SubtaskStarted`
/// synthesizes an `"output"` subtask (never lose bytes). The task-terminal
/// `Finished` drives persistence in `drive` and is not folded here.
pub(crate) fn apply(subs: &mut Vec<SubTaskRecord>, ev: &TaskEvent) {
    match ev {
        TaskEvent::SubtaskStarted {
            name,
            command,
            args,
            stdin,
        } => subs.push(SubTaskRecord {
            name: name.clone(),
            command: command.clone(),
            args: args.clone(),
            stdin: stdin.clone(),
            ..Default::default()
        }),
        TaskEvent::Stdout { data } => current(subs).stdout.push_str(data),
        TaskEvent::Stderr { data } => current(subs).stderr.push_str(data),
        TaskEvent::SubtaskFinished {
            status,
            exit,
            error,
        } => {
            let sub = current(subs);
            sub.status = Some(*status);
            sub.exit_code = Some(i64::from(*exit));
            sub.error = error.clone();
        }
        TaskEvent::Finished { .. } => {}
    }
}

/// The current (last-open) subtask, synthesizing an `"output"` one for stray
/// output that arrived before any `SubtaskStarted`.
fn current(subs: &mut Vec<SubTaskRecord>) -> &mut SubTaskRecord {
    if subs.is_empty() {
        subs.push(SubTaskRecord {
            name: "output".into(),
            ..Default::default()
        });
    }
    subs.last_mut().unwrap()
}

/// The flat stdout/stderr mirror (concatenated across subtasks) kept on the task
/// row as a backstop for `helper_client::collect` and old-row rendering.
fn flat_output(subs: &[SubTaskRecord]) -> (String, String) {
    let mut out = String::new();
    let mut err = String::new();
    for s in subs {
        out.push_str(&s.stdout);
        err.push_str(&s.stderr);
    }
    (out, err)
}

/// Live state of running tasks, for SSE streaming.
#[derive(Default)]
pub struct TaskHub {
    running: Mutex<HashMap<i64, Running>>,
}

struct Running {
    tx: broadcast::Sender<TaskEvent>,
    subs: Vec<SubTaskRecord>,
}

impl TaskHub {
    fn register(&self, id: i64) {
        let (tx, _) = broadcast::channel(512);
        self.running.lock().unwrap().insert(
            id,
            Running {
                tx,
                subs: Vec::new(),
            },
        );
    }

    /// Folds the event into the live subtask snapshot and broadcasts it,
    /// atomically so a subscriber can't miss or duplicate output around its join.
    fn broadcast(&self, id: i64, ev: &TaskEvent) {
        if let Some(r) = self.running.lock().unwrap().get_mut(&id) {
            apply(&mut r.subs, ev);
            let _ = r.tx.send(ev.clone());
        }
    }

    pub(crate) fn unregister(&self, id: i64) {
        self.running.lock().unwrap().remove(&id);
    }

    /// For a running task: its current subtask snapshot plus a receiver for
    /// subsequent events (snapshot and subscribe happen under one lock, so no
    /// gap/dup).
    pub fn snapshot_and_subscribe(
        &self,
        id: i64,
    ) -> Option<(Vec<SubTaskRecord>, broadcast::Receiver<TaskEvent>)> {
        let running = self.running.lock().unwrap();
        let r = running.get(&id)?;
        Some((r.subs.clone(), r.tx.subscribe()))
    }
}

#[derive(Debug)]
pub struct TaskOutcome {
    pub ok: bool,
    pub error: Option<String>,
}

impl TaskOutcome {
    /// A short message for a UI flash line.
    pub fn message(&self, success: &str) -> (Option<String>, Option<String>) {
        if self.ok {
            (Some(success.to_owned()), None)
        } else {
            (
                None,
                Some(self.error.clone().unwrap_or_else(|| "task failed".into())),
            )
        }
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Records a new running task and registers it for live SSE streaming,
/// returning its id. Shared by the blocking and fire-and-forget entry points.
pub(crate) fn begin(state: &AppState, kind: &str, title: &str) -> anyhow::Result<i64> {
    let id = state.db.insert_task(kind, title, now())?;
    state.tasks.register(id);
    Ok(id)
}

/// Dispatches helper request `req` as task `kind`/`title` and returns its id
/// *without* waiting for it: the run is driven to completion — recorded and
/// streamed — on a background task. Handlers respond at once and surface a link
/// to /tasks/{id}.
pub fn start(state: &Arc<AppState>, req: Request, kind: &str, title: &str) -> anyhow::Result<i64> {
    let id = begin(state, kind, title)?;
    let rx = state.helper.run_task(req);
    let state = state.clone();
    tokio::spawn(async move {
        let _ = drive(&state, id, rx).await;
        state.tasks.unregister(id);
    });
    Ok(id)
}

/// Runs helper request `req` as task `kind`/`title`, persisting and streaming
/// it, and awaits completion. For non-HTTP callers (the snapshot scheduler) and
/// tests that need the outcome synchronously; HTTP handlers use [`start`].
pub async fn run(
    state: &AppState,
    req: Request,
    kind: &str,
    title: &str,
) -> anyhow::Result<TaskOutcome> {
    let id = begin(state, kind, title)?;
    let outcome = drive(state, id, state.helper.run_task(req)).await?;
    state.tasks.unregister(id);
    Ok(outcome)
}

/// Consumes a task's event stream: broadcasts each event to SSE subscribers and
/// persists the terminal result. Shared by [`run`], [`start`], and the
/// background reconcile drive in `routes::block_export`.
pub(crate) async fn drive(
    state: &AppState,
    id: i64,
    mut rx: mpsc::Receiver<TaskEvent>,
) -> anyhow::Result<TaskOutcome> {
    let mut subs: Vec<SubTaskRecord> = Vec::new();
    let mut outcome: Option<TaskOutcome> = None;

    while let Some(ev) = rx.recv().await {
        state.tasks.broadcast(id, &ev);
        match &ev {
            TaskEvent::SubtaskStarted {
                name,
                command,
                args,
                stdin,
            } => {
                // Publish the task's summary command line off the first subtask.
                if subs.is_empty() {
                    match command {
                        Some(c) => state.db.set_task_command(id, c, args, stdin.as_deref())?,
                        None => state.db.set_task_command(id, name, &[], stdin.as_deref())?,
                    }
                }
                apply(&mut subs, &ev);
            }
            TaskEvent::Finished { status, error } => {
                // Success or Skipped is "ok" — an all-skipped reconcile must not
                // flash the dot red or block the 5 s success watcher.
                let task_status = match status {
                    SubStatus::Failed => TaskStatus::Failed,
                    _ => TaskStatus::Success,
                };
                let (stdout, stderr) = flat_output(&subs);
                let exit = subs.last().and_then(|s| s.exit_code);
                state.db.finish_task(
                    id,
                    task_status,
                    exit,
                    error.as_deref(),
                    &stdout,
                    &stderr,
                    &subs,
                    now(),
                )?;
                outcome = Some(TaskOutcome {
                    ok: task_status != TaskStatus::Failed,
                    error: error.clone(),
                });
                break;
            }
            _ => apply(&mut subs, &ev),
        }
    }

    Ok(outcome.unwrap_or_else(|| {
        // Channel closed without Finished — mark the open subtask and the task
        // Failed, so a crashed producer doesn't leave a task "running" forever.
        if let Some(open) = subs.last_mut()
            && open.status.is_none()
        {
            open.status = Some(SubStatus::Failed);
            open.error = Some("task ended without a result".into());
        }
        let (stdout, stderr) = flat_output(&subs);
        let _ = state.db.finish_task(
            id,
            TaskStatus::Failed,
            None,
            Some("task ended without a result"),
            &stdout,
            &stderr,
            &subs,
            now(),
        );
        TaskOutcome {
            ok: false,
            error: Some("task ended without a result".into()),
        }
    }))
}
