//! Thin command execution layer so privileged ops can be tested by
//! asserting the exact argv (and stdin) they produce.

use greendot_proto::{ErrKind, Response};
use std::io::Write;

pub struct CmdOutput {
    pub status: i32,
    /// Unused so far; kept because later ops may read output.
    #[allow(dead_code)]
    pub stdout: String,
    pub stderr: String,
}

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[String], stdin: Option<&str>) -> std::io::Result<CmdOutput>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, argv: &[String], stdin: Option<&str>) -> std::io::Result<CmdOutput> {
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        let output = match stdin {
            None => cmd.stdin(std::process::Stdio::null()).output()?,
            Some(input) => {
                cmd.stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped());
                let mut child = cmd.spawn()?;
                child
                    .stdin
                    .take()
                    .expect("piped stdin")
                    .write_all(input.as_bytes())?;
                child.wait_with_output()?
            }
        };
        Ok(CmdOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn check(argv: &[String], result: std::io::Result<CmdOutput>) -> Response {
    match result {
        Ok(out) if out.status == 0 => Response::Ok,
        Ok(out) => Response::err(
            ErrKind::CmdFailed,
            format!("{} exited {}: {}", argv[0], out.status, out.stderr.trim()),
        ),
        Err(e) => Response::err(ErrKind::Sys, format!("spawning {}: {e}", argv[0])),
    }
}

/// Runs a command, mapping any failure to an error `Response`.
pub fn run_checked(runner: &dyn Runner, argv: &[String]) -> Response {
    tracing::info!(cmd = %argv.join(" "), "executing");
    check(argv, runner.run(argv, None))
}

/// Like [`run_checked`], feeding the given script to stdin.
pub fn run_checked_stdin(runner: &dyn Runner, argv: &[String], stdin: &str) -> Response {
    tracing::info!(cmd = %argv.join(" "), stdin, "executing");
    check(argv, runner.run(argv, Some(stdin)))
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::sync::Mutex;

    /// Records every (argv, stdin); replies success unless told otherwise.
    #[derive(Default)]
    pub struct Recorder {
        pub log: Mutex<Vec<(Vec<String>, Option<String>)>>,
        pub fail_with: Option<(i32, &'static str)>,
    }

    impl Runner for Recorder {
        fn run(&self, argv: &[String], stdin: Option<&str>) -> std::io::Result<CmdOutput> {
            self.log
                .lock()
                .unwrap()
                .push((argv.to_vec(), stdin.map(Into::into)));
            let (status, stderr) = self.fail_with.unwrap_or((0, ""));
            Ok(CmdOutput {
                status,
                stdout: String::new(),
                stderr: stderr.into(),
            })
        }
    }

    impl Recorder {
        /// argv of every call, ignoring stdin.
        pub fn calls(&self) -> Vec<Vec<String>> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(argv, _)| argv.clone())
                .collect()
        }

        pub fn full_calls(&self) -> Vec<(Vec<String>, Option<String>)> {
            self.log.lock().unwrap().clone()
        }
    }
}
