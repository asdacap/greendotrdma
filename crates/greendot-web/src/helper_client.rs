//! Client for the root helper over gRPC on its unix socket. The tonic channel
//! is lazy and reconnects on its own, so a cloned `HelperClient` is cheap and
//! survives helper restarts. Traffic is a handful of calls per UI action.

use anyhow::{Context, Result, anyhow};
use greendot_proto::pb::helper_client::HelperClient as GrpcClient;
use greendot_proto::{Request, Response, TaskEvent, pb};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tonic::transport::Channel;

#[derive(Clone)]
pub struct HelperClient {
    inner: GrpcClient<Channel>,
}

/// Output of a task run drained by [`HelperClient::collect`].
#[derive(Debug, Default)]
pub struct HelperOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

/// A terminal failure event synthesized when the transport itself fails, so a
/// consumer of [`HelperClient::run_task`] always sees a `Finished`.
fn transport_failure(msg: String) -> TaskEvent {
    TaskEvent::Finished {
        exit: -1,
        ok: false,
        error: Some(msg),
    }
}

impl HelperClient {
    pub fn new(socket: PathBuf) -> Self {
        // `connect_uds` only fails on an invalid static endpoint URI, never here.
        let inner = greendot_proto::client::connect_uds(socket)
            .expect("helper endpoint should always be constructible");
        HelperClient { inner }
    }

    pub async fn call(&self, req: Request) -> Result<Response> {
        let mut client = self.inner.clone();
        let resp = client
            .call(pb::Request::from(req))
            .await
            .context("helper call failed")?
            .into_inner();
        Response::try_from(resp).map_err(|e| anyhow!("bad response from helper: {e}"))
    }

    /// Runs a task request to completion, collecting its output without
    /// recording a DB task. Used for privileged *reads* (e.g. LVM reporting)
    /// that must not clutter the Tasks page.
    pub async fn collect(&self, req: Request) -> HelperOutput {
        let mut rx = self.run_task(req);
        let mut out = HelperOutput::default();
        while let Some(ev) = rx.recv().await {
            match ev {
                TaskEvent::Stdout { data } => out.stdout.push_str(&data),
                TaskEvent::Stderr { data } => out.stderr.push_str(&data),
                TaskEvent::Finished { ok, error, .. } => {
                    out.ok = ok;
                    out.error = error;
                    break;
                }
                TaskEvent::Started { .. } => {}
            }
        }
        out
    }

    /// Runs a task request, delivering the helper's streamed events on the
    /// returned channel. A synthetic `Finished` is always sent (even on
    /// transport failure) so the consumer can rely on a terminal event.
    pub fn run_task(&self, req: Request) -> mpsc::Receiver<TaskEvent> {
        let mut client = self.inner.clone();
        let (tx, rx) = mpsc::channel(128);
        tokio::spawn(async move {
            let mut stream = match client.run_task(pb::Request::from(req)).await {
                Ok(resp) => resp.into_inner(),
                Err(e) => {
                    let _ = tx
                        .send(transport_failure(format!("helper unavailable: {e}")))
                        .await;
                    return;
                }
            };
            loop {
                match stream.message().await {
                    Ok(Some(pb_ev)) => match TaskEvent::try_from(pb_ev) {
                        Ok(ev) => {
                            let done = matches!(ev, TaskEvent::Finished { .. });
                            if tx.send(ev).await.is_err() || done {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = tx
                                .send(transport_failure(format!("helper protocol error: {e}")))
                                .await;
                            break;
                        }
                    },
                    Ok(None) => {
                        let _ = tx
                            .send(transport_failure("helper closed the connection".into()))
                            .await;
                        break;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(transport_failure(format!("helper protocol error: {e}")))
                            .await;
                        break;
                    }
                }
            }
        });
        rx
    }
}
