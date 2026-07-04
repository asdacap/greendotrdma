//! Runs a helper request — or a local command, e.g. `greendotctl reconcile` —
//! as a recorded, streamable task: persists it to the store, mirrors live
//! output to SSE subscribers, and returns the outcome.

use crate::routes::AppState;
use crate::state::{SubTaskRecord, TaskStatus};
use greendot_proto::{Request, SubStatus, TaskEvent};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
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

/// Spawns `argv` (the `greendotctl reconcile` subprocess) and streams its output
/// as task events. Its **stdout is a JSONL `TaskEvent` frame** (one event per
/// line) which we decode; a non-JSON stdout line falls back to `Stdout{data}` so
/// bytes are never lost. stderr is out-of-band and forwarded as `Stderr`. The
/// child emits its own terminal `Finished`; we synthesize one only if it crashed
/// without emitting it.
pub(crate) fn spawn_command_events(argv: &[String]) -> mpsc::Receiver<TaskEvent> {
    let (tx, rx) = mpsc::channel(128);
    let argv = argv.to_vec();
    tokio::spawn(async move {
        let Some((command, args)) = argv.split_first() else {
            let _ = tx
                .send(TaskEvent::Finished {
                    status: SubStatus::Failed,
                    error: Some("empty reconcile command".into()),
                })
                .await;
            return;
        };
        let mut child = match Command::new(command)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let _ = tx
                    .send(TaskEvent::Finished {
                        status: SubStatus::Failed,
                        error: Some(format!("spawning {command} failed: {e}")),
                    })
                    .await;
                return;
            }
        };
        // Drain both pipes concurrently to avoid a full-buffer deadlock, then
        // reap the child for its exit status.
        let out = BufReader::new(child.stdout.take().expect("stdout piped"));
        let err = BufReader::new(child.stderr.take().expect("stderr piped"));
        let saw_finished = Arc::new(AtomicBool::new(false));
        tokio::join!(
            pump_jsonl(out, tx.clone(), saw_finished.clone()),
            pump_stderr(err, tx.clone()),
        );
        // Only synthesize a terminal event if the child never emitted its own.
        let wait = child.wait().await;
        if !saw_finished.load(Ordering::SeqCst) {
            let (status, error) = match wait {
                Ok(s) if s.success() => (SubStatus::Success, None),
                Ok(s) => (
                    SubStatus::Failed,
                    Some(format!("reconcile exited with {s}")),
                ),
                Err(e) => (
                    SubStatus::Failed,
                    Some(format!("waiting on reconcile failed: {e}")),
                ),
            };
            let _ = tx.send(TaskEvent::Finished { status, error }).await;
        }
    });
    rx
}

/// Decodes the subprocess's stdout JSONL: each line is a `TaskEvent`, with a
/// non-JSON line degraded to `Stdout{data}`. Records whether a terminal
/// `Finished` was seen so the caller doesn't double it.
async fn pump_jsonl<R: AsyncRead + Unpin>(
    reader: BufReader<R>,
    tx: mpsc::Sender<TaskEvent>,
    saw_finished: Arc<AtomicBool>,
) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let ev = match serde_json::from_str::<TaskEvent>(&line) {
            Ok(ev) => {
                if matches!(ev, TaskEvent::Finished { .. }) {
                    saw_finished.store(true, Ordering::SeqCst);
                }
                ev
            }
            Err(_) => TaskEvent::Stdout {
                data: format!("{line}\n"),
            },
        };
        if tx.send(ev).await.is_err() {
            break;
        }
    }
}

/// Forwards each subprocess stderr line as a `Stderr` task event.
async fn pump_stderr<R: AsyncRead + Unpin>(reader: BufReader<R>, tx: mpsc::Sender<TaskEvent>) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if tx
            .send(TaskEvent::Stderr {
                data: format!("{line}\n"),
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::test_state;
    use crate::state::TaskStatus;

    fn latest(state: &crate::routes::AppState) -> crate::state::Task {
        state.db.list_tasks(10).unwrap().into_iter().next().unwrap()
    }

    /// Drives a local command to completion synchronously — the same path
    /// `routes::block_export` now drives in the background — for assertions.
    async fn run_local(
        state: &crate::routes::AppState,
        argv: &[String],
        kind: &str,
        title: &str,
    ) -> super::TaskOutcome {
        let id = super::begin(state, kind, title).unwrap();
        let out = super::drive(state, id, super::spawn_command_events(argv))
            .await
            .unwrap();
        state.tasks.unregister(id);
        out
    }

    #[tokio::test]
    async fn run_local_records_output_status_and_spawn_failure() {
        let state = test_state();

        // Success: stdout and stderr are both captured and persisted.
        let argv = [
            "sh".into(),
            "-c".into(),
            "printf 'hello\\n'; printf 'oops\\n' >&2".into(),
        ];
        let out = run_local(&state, &argv, "test", "echo").await;
        assert!(out.ok);
        let task = latest(&state);
        // Non-JSON stdout falls back to Stdout events, so there is no per-command
        // exit code to surface at the task level (exits live on the subtasks in a
        // real JSONL reconcile stream); the run is still Success.
        assert_eq!((task.status, task.exit_code), (TaskStatus::Success, None));
        assert!(task.stdout.contains("hello"), "{}", task.stdout);
        assert!(task.stderr.contains("oops"), "{}", task.stderr);
        // The fallback bytes attribute to a synthesized subtask.
        assert_eq!(task.subtasks.len(), 1);
        assert!(task.subtasks[0].stdout.contains("hello"));

        // Non-zero exit → failed task.
        let out = run_local(&state, &["false".into()], "test", "false").await;
        assert!(!out.ok);
        assert_eq!(latest(&state).status, TaskStatus::Failed);

        // A missing binary is a synthetic failed finish, not a panic.
        let out = run_local(&state, &["gd-no-such-binary-xyz".into()], "test", "missing").await;
        assert!(!out.ok);
        assert!(out.error.unwrap().contains("spawning"));
    }
}
