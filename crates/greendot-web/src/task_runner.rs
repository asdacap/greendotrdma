//! Runs a helper request — or a local command, e.g. `greendot-cli reconcile` —
//! as a recorded, streamable task: persists it to the store, mirrors live
//! output to SSE subscribers, and returns the outcome.

use crate::routes::AppState;
use greendot_proto::{Request, TaskEvent};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, mpsc};

/// Live state of running tasks, for SSE streaming.
#[derive(Default)]
pub struct TaskHub {
    running: Mutex<HashMap<i64, Running>>,
}

struct Running {
    tx: broadcast::Sender<TaskEvent>,
    stdout: String,
    stderr: String,
}

impl TaskHub {
    fn register(&self, id: i64) {
        let (tx, _) = broadcast::channel(512);
        self.running.lock().unwrap().insert(
            id,
            Running {
                tx,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
    }

    /// Appends output to the live buffer and broadcasts the event, atomically
    /// so a subscriber can't miss or duplicate output around its join.
    fn broadcast(&self, id: i64, ev: &TaskEvent) {
        if let Some(r) = self.running.lock().unwrap().get_mut(&id) {
            match ev {
                TaskEvent::Stdout { data } => r.stdout.push_str(data),
                TaskEvent::Stderr { data } => r.stderr.push_str(data),
                _ => {}
            }
            let _ = r.tx.send(ev.clone());
        }
    }

    fn unregister(&self, id: i64) {
        self.running.lock().unwrap().remove(&id);
    }

    /// For a running task: its current output plus a receiver for subsequent
    /// events (snapshot and subscribe happen under one lock, so no gap/dup).
    pub fn snapshot_and_subscribe(
        &self,
        id: i64,
    ) -> Option<(String, String, broadcast::Receiver<TaskEvent>)> {
        let running = self.running.lock().unwrap();
        let r = running.get(&id)?;
        Some((r.stdout.clone(), r.stderr.clone(), r.tx.subscribe()))
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

/// Runs helper request `req` as task `kind`/`title`, persisting and streaming
/// it. Awaits completion (UX stays synchronous; the run is also viewable on
/// /tasks).
pub async fn run(
    state: &AppState,
    req: Request,
    kind: &str,
    title: &str,
) -> anyhow::Result<TaskOutcome> {
    let id = state.db.insert_task(kind, title, now())?;
    state.tasks.register(id);
    let outcome = drive(state, id, state.helper.run_task(req)).await?;
    state.tasks.unregister(id);
    Ok(outcome)
}

/// Runs the local command `argv` (e.g. `greendot-cli reconcile`) as a recorded,
/// streamable task — the same record/broadcast machinery as [`run`], but the
/// events come from a subprocess instead of the helper.
pub async fn run_local(
    state: &AppState,
    argv: &[String],
    kind: &str,
    title: &str,
) -> anyhow::Result<TaskOutcome> {
    let id = state.db.insert_task(kind, title, now())?;
    state.tasks.register(id);
    let outcome = drive(state, id, spawn_command_events(argv)).await?;
    state.tasks.unregister(id);
    Ok(outcome)
}

/// Consumes a task's event stream: broadcasts each event to SSE subscribers and
/// persists the terminal result. Shared by [`run`] and [`run_local`].
async fn drive(
    state: &AppState,
    id: i64,
    mut rx: mpsc::Receiver<TaskEvent>,
) -> anyhow::Result<TaskOutcome> {
    let (mut stdout, mut stderr) = (String::new(), String::new());
    let mut outcome: Option<TaskOutcome> = None;

    while let Some(ev) = rx.recv().await {
        state.tasks.broadcast(id, &ev);
        match ev {
            TaskEvent::Started {
                command,
                args,
                stdin,
            } => {
                state
                    .db
                    .set_task_command(id, &command, &args, stdin.as_deref())?;
            }
            TaskEvent::Stdout { data } => stdout.push_str(&data),
            TaskEvent::Stderr { data } => stderr.push_str(&data),
            TaskEvent::Finished { exit, ok, error } => {
                let status = if ok {
                    crate::state::TaskStatus::Success
                } else {
                    crate::state::TaskStatus::Failed
                };
                state.db.finish_task(
                    id,
                    status,
                    Some(i64::from(exit)),
                    error.as_deref(),
                    &stdout,
                    &stderr,
                    now(),
                )?;
                outcome = Some(TaskOutcome { ok, error });
                break;
            }
        }
    }

    Ok(outcome.unwrap_or_else(|| {
        // Channel closed without Finished — should not happen (both producers
        // always emit one), but keep the store consistent.
        let _ = state.db.finish_task(
            id,
            crate::state::TaskStatus::Failed,
            None,
            Some("task ended without a result"),
            &stdout,
            &stderr,
            now(),
        );
        TaskOutcome {
            ok: false,
            error: Some("task ended without a result".into()),
        }
    }))
}

/// Spawns `argv` as a local subprocess and streams its output as task events,
/// mirroring `HelperClient::run_task`: a `Started`, then line-buffered
/// `Stdout`/`Stderr`, then exactly one `Finished` (synthetic on spawn failure).
fn spawn_command_events(argv: &[String]) -> mpsc::Receiver<TaskEvent> {
    let (tx, rx) = mpsc::channel(128);
    let argv = argv.to_vec();
    tokio::spawn(async move {
        let Some((command, args)) = argv.split_first() else {
            let _ = tx
                .send(TaskEvent::Finished {
                    exit: -1,
                    ok: false,
                    error: Some("empty reconcile command".into()),
                })
                .await;
            return;
        };
        let _ = tx
            .send(TaskEvent::Started {
                command: command.clone(),
                args: args.to_vec(),
                stdin: None,
            })
            .await;
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
                        exit: -1,
                        ok: false,
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
        tokio::join!(pump(out, tx.clone(), true), pump(err, tx.clone(), false),);
        let (exit, ok, error) = match child.wait().await {
            Ok(status) => (
                status.code().unwrap_or(-1),
                status.success(),
                (!status.success()).then(|| format!("reconcile exited with {status}")),
            ),
            Err(e) => (-1, false, Some(format!("waiting on reconcile failed: {e}"))),
        };
        let _ = tx.send(TaskEvent::Finished { exit, ok, error }).await;
    });
    rx
}

/// Forwards each line a subprocess writes as a `Stdout`/`Stderr` task event.
async fn pump<R: tokio::io::AsyncRead + Unpin>(
    reader: BufReader<R>,
    tx: mpsc::Sender<TaskEvent>,
    is_stdout: bool,
) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let data = format!("{line}\n");
        let ev = if is_stdout {
            TaskEvent::Stdout { data }
        } else {
            TaskEvent::Stderr { data }
        };
        if tx.send(ev).await.is_err() {
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

    #[tokio::test]
    async fn run_local_records_output_status_and_spawn_failure() {
        let state = test_state();

        // Success: stdout and stderr are both captured and persisted.
        let argv = [
            "sh".into(),
            "-c".into(),
            "printf 'hello\\n'; printf 'oops\\n' >&2".into(),
        ];
        let out = super::run_local(&state, &argv, "test", "echo")
            .await
            .unwrap();
        assert!(out.ok);
        let task = latest(&state);
        assert_eq!(
            (task.status, task.exit_code),
            (TaskStatus::Success, Some(0))
        );
        assert!(task.stdout.contains("hello"), "{}", task.stdout);
        assert!(task.stderr.contains("oops"), "{}", task.stderr);

        // Non-zero exit → failed task.
        let out = super::run_local(&state, &["false".into()], "test", "false")
            .await
            .unwrap();
        assert!(!out.ok);
        assert_eq!(latest(&state).status, TaskStatus::Failed);

        // A missing binary is a synthetic failed finish, not a panic.
        let out = super::run_local(&state, &["gd-no-such-binary-xyz".into()], "test", "missing")
            .await
            .unwrap();
        assert!(!out.ok);
        assert!(out.error.unwrap().contains("spawning"));
    }
}
