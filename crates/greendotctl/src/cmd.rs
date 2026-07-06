//! Task execution: runs one CLI command as a subtask. The executor streams the
//! child's stdout/stderr into the subtask's pipes and maps a missing binary to
//! an actionable "not installed" message. Two entry points share [`stream_child`]:
//! [`run`] opens its own single-process subtask; [`run_into`] streams one command
//! into an already-open (multi-step) subtask.

pub use greendot_proto::EventSink;
use greendot_proto::{SubStatus, SubTask, Task, TaskEvent};
use greendot_reconcile::os::package_for_cli;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

/// A single command to run as a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    pub command: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    /// Extra environment, not echoed in the task command line.
    pub env: Vec<(String, String)>,
    /// When true, `stdin` is written to a temp file and that path is appended
    /// as the final argument (targetctl reads a config file by name, not from a
    /// pipe).
    pub stdin_to_file: bool,
}

impl TaskSpec {
    pub fn new(command: &str, args: Vec<String>) -> Self {
        TaskSpec {
            command: command.into(),
            args,
            stdin: None,
            env: Vec::new(),
            stdin_to_file: false,
        }
    }

    pub fn with_stdin(command: &str, args: Vec<String>, stdin: String) -> Self {
        TaskSpec {
            command: command.into(),
            args,
            stdin: Some(stdin),
            env: Vec::new(),
            stdin_to_file: false,
        }
    }

    /// `command <args> <tempfile>`, where the temp file holds `content`.
    pub fn with_config_file(command: &str, args: Vec<String>, content: String) -> Self {
        TaskSpec {
            command: command.into(),
            args,
            stdin: Some(content),
            env: Vec::new(),
            stdin_to_file: true,
        }
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
}

/// Removes its path on drop (best effort).
struct TempInput(std::path::PathBuf);

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn spawn_error(command: &str, e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        match package_for_cli(command) {
            Some(pkg) => format!(
                "{command} is not installed — install the {pkg} package (Tasks → Install dependencies)"
            ),
            None => format!("{command} is not installed"),
        }
    } else {
        format!("failed to start {command}: {e}")
    }
}

/// The materialized command: `args` may have a temp-file path appended, in which
/// case `pipe_stdin` is cleared (the tool reads the file, not the pipe).
struct Prepared {
    args: Vec<String>,
    pipe_stdin: Option<String>,
    _temp: Option<TempInput>,
}

/// Materializes stdin to a temp file when the tool wants a path argument. `Err`
/// carries a human message on a write failure.
fn prepare_stdin(spec: &TaskSpec) -> Result<Prepared, String> {
    let mut args = spec.args.clone();
    let mut _temp = None;
    let mut pipe_stdin = spec.stdin.clone();
    if spec.stdin_to_file
        && let Some(content) = &spec.stdin
    {
        // A unique name in a tmpfs the service controls — /tmp gets reused
        // across tasks and is subject to systemd-tmpfiles cleaning, which can
        // race the child opening the file.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = {
            let run = std::path::Path::new("/run/greendotrdma");
            if run.is_dir() {
                run.to_path_buf()
            } else {
                std::env::temp_dir()
            }
        };
        let path = dir.join(format!(
            "greendot-{}-{}.cfg",
            spec.command,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, content)
            .map_err(|e| format!("writing config for {}: {e}", spec.command))?;
        args.push(path.to_string_lossy().into_owned());
        _temp = Some(TempInput(path));
        pipe_stdin = None; // the tool reads the file, not the pipe
    }
    Ok(Prepared {
        args,
        pipe_stdin,
        _temp,
    })
}

/// Runs `spec` as its own single-process subtask: opens a `begin_command`
/// subtask (the `$ cmd` header lives in its fields), streams the child, and
/// completes with the exit-derived status. Returns that status; `Err` only when
/// the sink fails (the client is gone).
pub fn run(task: &mut Task, name: impl Into<String>, spec: &TaskSpec) -> io::Result<SubStatus> {
    let prepared = match prepare_stdin(spec) {
        Ok(p) => p,
        Err(msg) => {
            let mut sub = task.begin_command(
                name,
                spec.command.clone(),
                spec.args.clone(),
                spec.stdin.clone(),
            );
            writeln!(sub.stderr(), "{msg}")?;
            sub.set_result(-1, Some(msg));
            sub.complete(SubStatus::Failed);
            return Ok(SubStatus::Failed);
        }
    };
    let mut sub = task.begin_command(
        name,
        spec.command.clone(),
        prepared.args.clone(),
        spec.stdin.clone(),
    );
    let (status, exit, error) = stream_child(&mut sub, spec, &prepared)?;
    sub.set_result(exit, error);
    sub.complete(status);
    Ok(status)
}

/// Streams one command **into an already-open subtask** (for multi-step subtasks
/// like NFS apply / RoCE enable): echoes `$ cmd args`, streams the child, and —
/// on failure only, so a later success can't clobber an earlier command's error
/// — records the exit/message on the subtask. Never opens or closes the subtask;
/// the caller folds the returned status. A missing binary maps to the same
/// install hint as [`run`].
pub(crate) fn run_into(sub: &mut SubTask, spec: &TaskSpec) -> io::Result<SubStatus> {
    writeln!(sub.stdout(), "$ {} {}", spec.command, spec.args.join(" "))?;
    let prepared = match prepare_stdin(spec) {
        Ok(p) => p,
        Err(msg) => {
            writeln!(sub.stderr(), "{msg}")?;
            sub.set_result(-1, Some(msg));
            return Ok(SubStatus::Failed);
        }
    };
    let (status, exit, error) = stream_child(sub, spec, &prepared)?;
    if status == SubStatus::Failed {
        sub.set_result(exit, error);
    }
    Ok(status)
}

/// Runs `spec` to completion, capturing its stdout for the caller instead of
/// streaming it — for probes and reads whose stdout the caller parses, or
/// whose subtask stdout must stay machine-readable. The `$ cmd` echo and the
/// child's stderr go to the subtask's *stderr* so the run stays visible on the
/// task page without polluting stdout. A missing binary maps to the same
/// install hint as [`run`]. Outer `Err` = sink failure; inner `Err` = the
/// spawn-failure message (already echoed; the caller decides whether that
/// fails the subtask or degrades).
pub(crate) fn capture_into(
    sub: &mut SubTask,
    spec: &TaskSpec,
) -> io::Result<Result<String, String>> {
    writeln!(sub.stderr(), "$ {} {}", spec.command, spec.args.join(" "))?;
    match Command::new(&spec.command).args(&spec.args).output() {
        Ok(out) => {
            sub.stderr().write_all(&out.stderr)?;
            Ok(Ok(String::from_utf8_lossy(&out.stdout).into_owned()))
        }
        Err(e) => {
            let msg = spawn_error(&spec.command, &e);
            writeln!(sub.stderr(), "{msg}")?;
            Ok(Err(msg))
        }
    }
}

/// Spawns the command, streams stdout/stderr into `sub`'s pipes, waits, and
/// returns `(status, exit, error)`. A spawn failure echoes the install hint to
/// the subtask's stderr and returns `(Failed, -1, hint)`. `Err` only when the
/// sink fails.
fn stream_child(
    sub: &mut SubTask,
    spec: &TaskSpec,
    prepared: &Prepared,
) -> io::Result<(SubStatus, i32, Option<String>)> {
    tracing::info!(cmd = %spec.command, args = ?prepared.args, "running task");
    let mut cmd = Command::new(&spec.command);
    cmd.args(&prepared.args)
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = spawn_error(&spec.command, &e);
            writeln!(sub.stderr(), "{msg}")?;
            return Ok((SubStatus::Failed, -1, Some(msg)));
        }
    };

    // Feed stdin from its own thread so a large payload can't deadlock against
    // the child filling its stdout pipe.
    let mut stdin_handle = child.stdin.take();
    let pipe_stdin = prepared.pipe_stdin.clone();
    let stdin_thread = std::thread::spawn(move || {
        // Writing the data (if any) then dropping the handle closes the pipe so
        // the child sees EOF.
        if let (Some(mut s), Some(data)) = (stdin_handle.take(), pipe_stdin) {
            let _ = s.write_all(data.as_bytes());
        }
    });

    let (tx, rx) = std::sync::mpsc::channel::<TaskEvent>();
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let tx_out = tx.clone();
    let h_out = std::thread::spawn(move || pump(stdout, &tx_out, true));
    let h_err = std::thread::spawn(move || pump(stderr, &tx, false));

    let mut sink_err = None;
    for ev in rx {
        let res = match ev {
            TaskEvent::Stdout { data } => sub.stdout().write_all(data.as_bytes()),
            TaskEvent::Stderr { data } => sub.stderr().write_all(data.as_bytes()),
            _ => Ok(()),
        };
        if let Err(e) = res {
            sink_err = Some(e);
            break;
        }
    }
    let _ = h_out.join();
    let _ = h_err.join();
    let _ = stdin_thread.join();
    if let Some(e) = sink_err {
        return Err(e);
    }

    let status = child.wait()?;
    let exit = status.code().unwrap_or(-1);
    let error = (!status.success()).then(|| format!("{} exited with status {exit}", spec.command));
    let sub_status = if status.success() {
        SubStatus::Success
    } else {
        SubStatus::Failed
    };
    Ok((sub_status, exit, error))
}

/// Streams a child pipe to the channel in chunks (partial lines included).
fn pump(mut pipe: impl Read, tx: &std::sync::mpsc::Sender<TaskEvent>, is_stdout: bool) {
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                let ev = if is_stdout {
                    TaskEvent::Stdout { data }
                } else {
                    TaskEvent::Stderr { data }
                };
                if tx.send(ev).is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    /// Collects events; useful for asserting executor behaviour.
    #[derive(Default)]
    pub struct Collector {
        pub events: Vec<TaskEvent>,
    }

    impl EventSink for Collector {
        fn emit(&mut self, ev: TaskEvent) -> io::Result<()> {
            self.events.push(ev);
            Ok(())
        }
    }

    impl Collector {
        fn started(&self) -> &TaskEvent {
            &self.events[0]
        }
        /// The subtask-terminal event (`exit`/subtask `status` live here now).
        fn subtask_finished(&self) -> &TaskEvent {
            self.events
                .iter()
                .find(|e| matches!(e, TaskEvent::SubtaskFinished { .. }))
                .unwrap()
        }
        /// The task-terminal event (worst-child `status`, first error).
        fn finished(&self) -> &TaskEvent {
            self.events.last().unwrap()
        }
        fn stdout(&self) -> String {
            self.events
                .iter()
                .filter_map(|e| match e {
                    TaskEvent::Stdout { data } => Some(data.as_str()),
                    _ => None,
                })
                .collect()
        }
        fn stderr(&self) -> String {
            self.events
                .iter()
                .filter_map(|e| match e {
                    TaskEvent::Stderr { data } => Some(data.as_str()),
                    _ => None,
                })
                .collect()
        }
    }

    /// Runs `spec` as a one-subtask task and collects the whole event stream.
    fn run_spec(spec: &TaskSpec) -> Collector {
        let mut c = Collector::default();
        {
            let mut task = Task::new(&mut c);
            super::run(&mut task, "test", spec).unwrap();
            task.complete().unwrap();
        }
        c
    }

    #[test]
    fn streams_stdout_stderr_and_exit_code() {
        let spec = TaskSpec::new(
            "sh",
            ["-c", "printf out; printf err >&2; exit 3"]
                .map(String::from)
                .to_vec(),
        );
        let c = run_spec(&spec);
        assert!(
            matches!(c.started(), TaskEvent::SubtaskStarted { command: Some(cmd), .. } if cmd == "sh")
        );
        assert_eq!(c.stdout(), "out");
        assert_eq!(c.stderr(), "err");
        assert!(matches!(
            c.subtask_finished(),
            TaskEvent::SubtaskFinished {
                status: SubStatus::Failed,
                exit: 3,
                ..
            }
        ));
        assert!(matches!(
            c.finished(),
            TaskEvent::Finished {
                status: SubStatus::Failed,
                ..
            }
        ));
    }

    #[test]
    fn feeds_stdin() {
        let spec = TaskSpec::with_stdin("cat", vec![], "hello world".into());
        let c = run_spec(&spec);
        assert_eq!(c.stdout(), "hello world");
        assert!(matches!(
            c.finished(),
            TaskEvent::Finished {
                status: SubStatus::Success,
                ..
            }
        ));
    }

    #[test]
    fn config_file_mode_passes_a_real_path() {
        // `cat <tempfile>` should print the materialized content.
        let spec = TaskSpec::with_config_file("cat", vec![], "rendered config".into());
        let c = run_spec(&spec);
        assert_eq!(c.stdout(), "rendered config");
        match c.started() {
            TaskEvent::SubtaskStarted { args, stdin, .. } => {
                assert_eq!(args.len(), 1, "the temp path is appended as an arg");
                assert!(args[0].contains("greendot-cat"), "{args:?}");
                assert_eq!(
                    stdin.as_deref(),
                    Some("rendered config"),
                    "content kept for display"
                );
            }
            other => panic!("expected SubtaskStarted, got {other:?}"),
        }
        assert!(matches!(
            c.finished(),
            TaskEvent::Finished {
                status: SubStatus::Success,
                ..
            }
        ));
    }

    #[test]
    fn missing_binary_reports_install_hint() {
        let c = run_spec(&TaskSpec::new("targetctl", vec!["restore".into()]));
        // The install hint is both the task-terminal error and echoed to stderr.
        match c.finished() {
            TaskEvent::Finished {
                status: SubStatus::Failed,
                error: Some(msg),
            } => {
                assert!(msg.contains("targetctl is not installed"), "{msg}");
                assert!(msg.contains("targetcli-fb package"), "{msg}");
            }
            other => panic!("expected install hint, got {other:?}"),
        }
        assert!(
            c.stderr().contains("targetctl is not installed"),
            "{}",
            c.stderr()
        );
    }
}
