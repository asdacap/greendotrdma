//! Client for the root helper's unix socket. One short-lived connection per
//! request keeps this trivially correct; traffic is a handful of calls per
//! UI action.

use anyhow::{Context, Result};
use greendot_proto::{Request, Response, TaskEvent, wire};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct HelperClient {
    socket: PathBuf,
}

impl HelperClient {
    pub fn new(socket: PathBuf) -> Self {
        HelperClient { socket }
    }

    pub async fn call(&self, req: Request) -> Result<Response> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || {
            let stream = UnixStream::connect(&socket)
                .with_context(|| format!("connecting to helper at {}", socket.display()))?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            wire::write_msg(&mut writer, &req)?;
            wire::read_msg(&mut reader)?.context("helper closed connection without a response")
        })
        .await?
    }

    /// Runs a task request, delivering the helper's streamed events on the
    /// returned channel. A synthetic `Finished` is always sent (even on
    /// transport failure) so the consumer can rely on a terminal event.
    pub fn run_task(&self, req: Request) -> mpsc::Receiver<TaskEvent> {
        let socket = self.socket.clone();
        let (tx, rx) = mpsc::channel(128);
        tokio::task::spawn_blocking(move || {
            let fail = |tx: &mpsc::Sender<TaskEvent>, msg: String| {
                let _ = tx.blocking_send(TaskEvent::Finished {
                    exit: -1,
                    ok: false,
                    error: Some(msg),
                });
            };
            let stream = match UnixStream::connect(&socket) {
                Ok(s) => s,
                Err(e) => return fail(&tx, format!("helper unavailable: {e}")),
            };
            let mut reader = BufReader::new(match stream.try_clone() {
                Ok(s) => s,
                Err(e) => return fail(&tx, format!("helper socket error: {e}")),
            });
            let mut writer = stream;
            if let Err(e) = wire::write_msg(&mut writer, &req) {
                return fail(&tx, format!("helper write failed: {e}"));
            }
            loop {
                match wire::read_msg::<TaskEvent, _>(&mut reader) {
                    Ok(Some(ev)) => {
                        let done = matches!(ev, TaskEvent::Finished { .. });
                        if tx.blocking_send(ev).is_err() || done {
                            break;
                        }
                    }
                    Ok(None) => return fail(&tx, "helper closed the connection".into()),
                    Err(e) => return fail(&tx, format!("helper protocol error: {e}")),
                }
            }
        });
        rx
    }
}
