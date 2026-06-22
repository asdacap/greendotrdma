//! Task execution: one task = one CLI command. The executor streams the
//! child's stdout/stderr back as [`TaskEvent`]s and maps a missing binary to
//! an actionable "not installed" message.

use greendot_proto::{TaskEvent, package_for_cli};
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

/// Receives task events as they happen (the socket writer in production, a
/// collector in tests). Returning `Err` aborts streaming.
pub trait EventSink {
    fn emit(&mut self, ev: TaskEvent) -> io::Result<()>;
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

/// Runs the command, emitting Started, then Stdout/Stderr as they stream, then
/// exactly one Finished.
pub fn run_task(spec: &TaskSpec, sink: &mut dyn EventSink) -> io::Result<()> {
    // Materialize stdin to a temp file when the tool wants a path argument.
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
        if let Err(e) = std::fs::write(&path, content) {
            return sink.emit(TaskEvent::Finished {
                exit: -1,
                ok: false,
                error: Some(format!("writing config for {}: {e}", spec.command)),
            });
        }
        args.push(path.to_string_lossy().into_owned());
        _temp = Some(TempInput(path));
        pipe_stdin = None; // the tool reads the file, not the pipe
    }

    sink.emit(TaskEvent::Started {
        command: spec.command.clone(),
        args: args.clone(),
        stdin: spec.stdin.clone(),
    })?;
    tracing::info!(cmd = %spec.command, args = ?args, "running task");

    let mut cmd = Command::new(&spec.command);
    cmd.args(&args)
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return sink.emit(TaskEvent::Finished {
                exit: -1,
                ok: false,
                error: Some(spawn_error(&spec.command, &e)),
            });
        }
    };

    // Feed stdin from its own thread so a large payload can't deadlock against
    // the child filling its stdout pipe.
    let mut stdin_handle = child.stdin.take();
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
        if let Err(e) = sink.emit(ev) {
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
    sink.emit(TaskEvent::Finished {
        exit,
        ok: status.success(),
        error: (!status.success()).then(|| format!("{} exited with status {exit}", spec.command)),
    })
}

/// Runs one command to completion, echoing its command line + output to the task
/// stream — for multi-step tasks (NFS apply, RoCE enable) that emit a single
/// Started/Finished around several commands. Returns `Ok((success, error))`;
/// `Err` only when the sink fails (the client is gone). A missing binary maps to
/// the same install hint as `run_task`.
pub(crate) fn run_cmd(
    command: &str,
    args: &[String],
    sink: &mut dyn EventSink,
) -> io::Result<(bool, String)> {
    sink.emit(TaskEvent::Stdout {
        data: format!("$ {command} {}\n", args.join(" ")),
    })?;
    let output = match Command::new(command).args(args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let msg = match package_for_cli(command) {
                Some(pkg) => format!(
                    "{command} is not installed — install the {pkg} package (Tasks → Install dependencies)"
                ),
                None => format!("{command} is not installed"),
            };
            sink.emit(TaskEvent::Stderr {
                data: format!("{msg}\n"),
            })?;
            return Ok((false, msg));
        }
        Err(e) => {
            let msg = format!("failed to start {command}: {e}");
            sink.emit(TaskEvent::Stderr {
                data: format!("{msg}\n"),
            })?;
            return Ok((false, msg));
        }
    };
    if !output.stdout.is_empty() {
        sink.emit(TaskEvent::Stdout {
            data: String::from_utf8_lossy(&output.stdout).into_owned(),
        })?;
    }
    if !output.stderr.is_empty() {
        sink.emit(TaskEvent::Stderr {
            data: String::from_utf8_lossy(&output.stderr).into_owned(),
        })?;
    }
    let exit = output.status.code().unwrap_or(-1);
    let msg = if output.status.success() {
        String::new()
    } else {
        format!("{command} exited with status {exit}")
    };
    Ok((output.status.success(), msg))
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

    fn run(spec: &TaskSpec) -> Collector {
        let mut c = Collector::default();
        run_task(spec, &mut c).unwrap();
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
        let c = run(&spec);
        assert!(matches!(c.started(), TaskEvent::Started { command, .. } if command == "sh"));
        assert_eq!(c.stdout(), "out");
        assert_eq!(c.stderr(), "err");
        assert!(matches!(
            c.finished(),
            TaskEvent::Finished {
                exit: 3,
                ok: false,
                ..
            }
        ));
    }

    #[test]
    fn feeds_stdin() {
        let spec = TaskSpec::with_stdin("cat", vec![], "hello world".into());
        let c = run(&spec);
        assert_eq!(c.stdout(), "hello world");
        assert!(matches!(c.finished(), TaskEvent::Finished { ok: true, .. }));
    }

    #[test]
    fn config_file_mode_passes_a_real_path() {
        // `cat <tempfile>` should print the materialized content.
        let spec = TaskSpec::with_config_file("cat", vec![], "rendered config".into());
        let c = run(&spec);
        assert_eq!(c.stdout(), "rendered config");
        match c.started() {
            TaskEvent::Started { args, stdin, .. } => {
                assert_eq!(args.len(), 1, "the temp path is appended as an arg");
                assert!(args[0].contains("greendot-cat"), "{args:?}");
                assert_eq!(
                    stdin.as_deref(),
                    Some("rendered config"),
                    "content kept for display"
                );
            }
            other => panic!("expected Started, got {other:?}"),
        }
        assert!(matches!(c.finished(), TaskEvent::Finished { ok: true, .. }));
    }

    #[test]
    fn missing_binary_reports_install_hint() {
        let c = run(&TaskSpec::new("targetctl", vec!["restore".into()]));
        match c.finished() {
            TaskEvent::Finished {
                ok: false,
                error: Some(msg),
                ..
            } => {
                assert!(msg.contains("targetctl is not installed"), "{msg}");
                assert!(msg.contains("targetcli-fb package"), "{msg}");
            }
            other => panic!("expected install hint, got {other:?}"),
        }
    }
}
