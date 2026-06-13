//! Thin command execution layer so privileged ops can be tested by
//! asserting the exact argv they produce.

use greendot_proto::{ErrKind, Response};

pub struct CmdOutput {
    pub status: i32,
    /// Unused so far; kept because later ops (sfdisk, rdma) read output.
    #[allow(dead_code)]
    pub stdout: String,
    pub stderr: String,
}

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[String]) -> std::io::Result<CmdOutput>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<CmdOutput> {
        let output = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()?;
        Ok(CmdOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Runs a command, mapping any failure to an error `Response`.
pub fn run_checked(runner: &dyn Runner, argv: &[String]) -> Response {
    tracing::info!(cmd = %argv.join(" "), "executing");
    match runner.run(argv) {
        Ok(out) if out.status == 0 => Response::Ok,
        Ok(out) => Response::err(
            ErrKind::CmdFailed,
            format!("{} exited {}: {}", argv[0], out.status, out.stderr.trim()),
        ),
        Err(e) => Response::err(ErrKind::Sys, format!("spawning {}: {e}", argv[0])),
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::sync::Mutex;

    /// Records every argv; replies success unless told otherwise.
    #[derive(Default)]
    pub struct Recorder {
        pub calls: Mutex<Vec<Vec<String>>>,
        pub fail_with: Option<(i32, &'static str)>,
    }

    impl Runner for Recorder {
        fn run(&self, argv: &[String]) -> std::io::Result<CmdOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let (status, stderr) = self.fail_with.unwrap_or((0, ""));
            Ok(CmdOutput {
                status,
                stdout: String::new(),
                stderr: stderr.into(),
            })
        }
    }

    impl Recorder {
        pub fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }
}
