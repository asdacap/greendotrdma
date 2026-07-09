//! Protocol between greendot-web (unprivileged) and greendotctl (root).
//!
//! This crate holds the *validated domain model*: one op struct per rpc in
//! [`ops`], the newtypes in `types`, the shared actual-state DTOs in
//! [`actual`], and the task event stream ([`TaskEvent`]). Every op is one
//! allowlisted privileged operation, and all strings that end up as path
//! components or command arguments are validated newtypes.
//!
//! The service has one rpc per operation. Mutations (and the reads whose
//! payload is a foreign tool's output) reply with a recorded [`TaskEvent`]
//! stream; the structural reads reply with typed messages mirroring the
//! `actual::*` DTOs; `Ping`/`Authenticate` are one-shot and never recorded.
//!
//! The transport is gRPC (tonic): the generated protobuf types live in [`pb`],
//! and [`ops`]/[`convert`] provide the conversions. Crucially, protobuf
//! messages are plain strings that prost does *not* validate on decode, so
//! every incoming `pb::X` request must pass `TryFrom<pb::X> for ops::X`, which
//! re-runs the validators. The daemon's generic rpc middleware requires that
//! bound on every method, so the security choke point cannot be skipped.

/// Actual-state DTOs and their pure parsers (the read half of the contract).
pub mod actual;
#[cfg(feature = "client")]
pub mod client;
/// The shared `config.toml` subset both the daemon and the web read.
pub mod config;
#[cfg(feature = "grpc")]
mod convert;
/// Desired-state config model and the read-only TOML loader (the write half).
pub mod desired;
/// The validated domain ops — one struct per rpc, with the ingress-validating
/// `TryFrom` conversions that are the security choke point.
#[cfg(feature = "grpc")]
pub mod ops;
/// OS / package-manager knowledge shared by the daemon and the web dep panel.
pub mod os;
mod types;
mod validate;

/// Generated protobuf/gRPC transport types. Kept separate from the validated
/// domain model (`ops`, `actual`, `TaskEvent`); see `ops`/`convert` for the
/// validating conversions between the two.
#[cfg(feature = "grpc")]
pub mod pb {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]
    tonic::include_proto!("greendot.helper.v1");
}

#[cfg(feature = "grpc")]
pub use convert::ConvertError;
pub use types::*;

/// The `Authenticate` rpc's reply: PAM + admin-group verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Ok { username: String },
    Err { kind: ErrKind, message: String },
}

impl AuthResult {
    pub fn err(kind: ErrKind, message: impl Into<String>) -> Self {
        AuthResult::Err {
            kind,
            message: message.into(),
        }
    }
}

/// Receives task events as they happen — the socket writer in the daemon, a
/// stdout writer in the standalone CLI, or a collector in tests. Returning `Err`
/// aborts streaming. Lives here, next to [`TaskEvent`], so both the helper's
/// apply functions and the transport-agnostic reconciler can name one trait.
pub trait EventSink {
    fn emit(&mut self, ev: TaskEvent) -> std::io::Result<()>;
}

/// A typed handle over an [`EventSink`] that structures a run as a task of one
/// or more sequential [`SubTask`]s, each with its own recorded output and
/// terminal [`SubStatus`]. This is a thin layer *on top of* `emit(TaskEvent)` —
/// the sink stays the transport; `Task`/`SubTask`/`Pipe` just guarantee the
/// framing invariants (every task ends with exactly one `Finished` whose status
/// is the worst child; output attributes to the open subtask).
///
/// ```ignore
/// let mut task = Task::new(sink);
/// let mut sub = task.begin_subtask("Load kernel modules");
/// writeln!(sub.stdout(), "$ modprobe nvmet_rdma")?;
/// sub.complete(SubStatus::Success);
/// task.complete()?;
/// ```
///
/// The mutable borrow taken by `begin_*` *is* the sequential guarantee: the
/// previous subtask must drop (finish) before the next one can open.
pub struct Task<'s> {
    sink: &'s mut dyn EventSink,
    /// Folded status of every finished subtask so far (`None` until the first).
    agg: Option<SubStatus>,
    /// First failing subtask's error message — becomes the task-level `error`.
    first_err: Option<String>,
    /// A sink error captured on a path that can't return `io::Result`
    /// (`begin_*`, subtask `Drop`); surfaced by the next `Pipe::write` /
    /// `complete`, preserving "stop streaming the instant the client hangs up".
    pending: Option<std::io::Error>,
}

impl<'s> Task<'s> {
    pub fn new(sink: &'s mut dyn EventSink) -> Self {
        Task {
            sink,
            agg: None,
            first_err: None,
            pending: None,
        }
    }

    /// Open a plain subtask (a human label, no command header). Output written
    /// to its pipes belongs to it until it finishes.
    pub fn begin_subtask(&mut self, name: impl Into<String>) -> SubTask<'_, 's> {
        self.emit_soft(TaskEvent::SubtaskStarted {
            name: name.into(),
            command: None,
            args: Vec::new(),
            stdin: None,
        });
        SubTask::new(self)
    }

    /// Open a subtask that wraps a single process, carrying the `$ cmd` header
    /// fields (`command`/`args`/`stdin`).
    pub fn begin_command(
        &mut self,
        name: impl Into<String>,
        command: impl Into<String>,
        args: Vec<String>,
        stdin: Option<String>,
    ) -> SubTask<'_, 's> {
        self.emit_soft(TaskEvent::SubtaskStarted {
            name: name.into(),
            command: Some(command.into()),
            args,
            stdin,
        });
        SubTask::new(self)
    }

    /// Record an already-satisfied step as a grey `Skipped` dot (opened and
    /// closed with no output).
    pub fn skipped_subtask(&mut self, name: impl Into<String>) {
        self.emit_soft(TaskEvent::SubtaskStarted {
            name: name.into(),
            command: None,
            args: Vec::new(),
            stdin: None,
        });
        self.finish_subtask(SubStatus::Skipped, 0, None);
    }

    /// The worst subtask status seen so far (`Success` if no subtask ran).
    pub fn aggregate(&self) -> SubStatus {
        self.agg.unwrap_or(SubStatus::Success)
    }

    /// Emit the single terminal `Finished` (status = worst child, error = first
    /// failing subtask's message), consuming the task. Surfaces any deferred
    /// sink error first.
    pub fn complete(mut self) -> std::io::Result<()> {
        let status = self.aggregate();
        let error = self.first_err.take();
        self.take_pending()?;
        self.emit(TaskEvent::Finished { status, error })
    }

    /// Close the current subtask: fold its status, remember the first error, and
    /// emit `SubtaskFinished`. Called by `SubTask::complete`/`fail`/`Drop` and by
    /// `skipped_subtask`.
    fn finish_subtask(&mut self, status: SubStatus, exit: i32, error: Option<String>) {
        self.agg = Some(SubStatus::fold(self.agg, status));
        if status == SubStatus::Failed && self.first_err.is_none() {
            self.first_err = error.clone();
        }
        self.emit_soft(TaskEvent::SubtaskFinished {
            status,
            exit,
            error,
        });
    }

    /// Hard emit — the error propagates to the caller (via `Pipe::write`/
    /// `complete`).
    fn emit(&mut self, ev: TaskEvent) -> std::io::Result<()> {
        self.sink.emit(ev)
    }

    /// Soft emit — used where we can't return `io::Result`. The first sink error
    /// is stashed in `pending`; later frames are skipped (client is gone).
    fn emit_soft(&mut self, ev: TaskEvent) {
        if self.pending.is_none()
            && let Err(e) = self.sink.emit(ev)
        {
            self.pending = Some(e);
        }
    }

    fn take_pending(&mut self) -> std::io::Result<()> {
        match self.pending.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// A single step of a [`Task`], holding a mutable borrow of it (so the next
/// subtask can't open until this one finishes). Its `stdout()`/`stderr()` pipes
/// stream output attributed to this subtask. Failures are reported via
/// `complete(Failed)`/`fail(...)` — never via `?` (a `?` fires only on a sink
/// error, i.e. the client is gone, where the terminal status is moot). `Drop`
/// auto-completes as `Success`.
pub struct SubTask<'t, 's> {
    task: &'t mut Task<'s>,
    exit: i32,
    error: Option<String>,
    done: bool,
}

impl<'t, 's> SubTask<'t, 's> {
    fn new(task: &'t mut Task<'s>) -> Self {
        SubTask {
            task,
            exit: 0,
            error: None,
            done: false,
        }
    }

    /// A writer whose every `write` emits one `Stdout` event for this subtask.
    pub fn stdout(&mut self) -> Pipe<'_, 's> {
        Pipe {
            task: self.task,
            stderr: false,
        }
    }

    /// A writer whose every `write` emits one `Stderr` event for this subtask.
    pub fn stderr(&mut self) -> Pipe<'_, 's> {
        Pipe {
            task: self.task,
            stderr: true,
        }
    }

    /// Record the wrapped process's exit code and (optional) error message, to be
    /// carried on this subtask's `SubtaskFinished`.
    pub fn set_result(&mut self, exit: i32, error: Option<String>) {
        self.exit = exit;
        self.error = error;
    }

    /// Finish this subtask with an explicit status.
    pub fn complete(mut self, status: SubStatus) {
        self.finish(status);
    }

    /// Finish this subtask as `Failed` with a human message.
    pub fn fail(mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.finish(SubStatus::Failed);
    }

    fn finish(&mut self, status: SubStatus) {
        if self.done {
            return;
        }
        self.done = true;
        let error = self.error.take();
        self.task.finish_subtask(status, self.exit, error);
    }
}

impl Drop for SubTask<'_, '_> {
    fn drop(&mut self) {
        self.finish(SubStatus::Success);
    }
}

/// An `io::Write` that turns each `write` into one `Stdout`/`Stderr` event on the
/// underlying task (no buffering; `flush` is a no-op). Deferred sink errors
/// surface here so streaming stops the instant the client hangs up.
pub struct Pipe<'p, 's> {
    task: &'p mut Task<'s>,
    stderr: bool,
}

impl std::io::Write for Pipe<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.task.take_pending()?;
        let data = String::from_utf8_lossy(buf).into_owned();
        let ev = if self.stderr {
            TaskEvent::Stderr { data }
        } else {
            TaskEvent::Stdout { data }
        };
        self.task.emit(ev)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrKind {
    AuthFailed,
    NotInAdminGroup,
    Validation,
    Busy,
    Sys,
    CmdFailed,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // Failed dominates regardless of order or accumulator.
    #[case(None, SubStatus::Failed, SubStatus::Failed)]
    #[case(Some(SubStatus::Success), SubStatus::Failed, SubStatus::Failed)]
    #[case(Some(SubStatus::Failed), SubStatus::Success, SubStatus::Failed)]
    // Success beats Skipped in both directions (not a plain max).
    #[case(Some(SubStatus::Skipped), SubStatus::Success, SubStatus::Success)]
    #[case(Some(SubStatus::Success), SubStatus::Skipped, SubStatus::Success)]
    // All-skipped stays skipped.
    #[case(None, SubStatus::Skipped, SubStatus::Skipped)]
    #[case(Some(SubStatus::Skipped), SubStatus::Skipped, SubStatus::Skipped)]
    fn substatus_fold(
        #[case] acc: Option<SubStatus>,
        #[case] s: SubStatus,
        #[case] expected: SubStatus,
    ) {
        assert_eq!(SubStatus::fold(acc, s), expected);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let req = ops::Authenticate {
            username: Username::new("alice").unwrap(),
            password: Secret("hunter2".into()),
        };
        assert!(!format!("{req:?}").contains("hunter2"));
    }
}
