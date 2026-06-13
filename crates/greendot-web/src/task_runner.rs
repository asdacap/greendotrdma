//! Runs a helper request as a recorded, streamable task: persists it to the
//! store, mirrors live output to SSE subscribers, and returns the outcome.

use crate::routes::AppState;
use greendot_proto::{Request, TaskEvent};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::broadcast;

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

/// Runs `req` as task `kind`/`title`, persisting and streaming it. Awaits
/// completion (UX stays synchronous; the run is also viewable on /tasks).
pub async fn run(
    state: &AppState,
    req: Request,
    kind: &str,
    title: &str,
) -> anyhow::Result<TaskOutcome> {
    let id = state.db.insert_task(kind, title, now())?;
    state.tasks.register(id);

    let mut rx = state.helper.run_task(req);
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

    state.tasks.unregister(id);
    Ok(outcome.unwrap_or_else(|| {
        // Channel closed without Finished — should not happen (run_task always
        // emits one), but keep the store consistent.
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
