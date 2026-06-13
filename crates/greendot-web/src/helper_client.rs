//! Client for the root helper's unix socket. One short-lived connection per
//! request keeps this trivially correct; traffic is a handful of calls per
//! UI action.

use anyhow::{Context, Result};
use greendot_proto::{Request, Response, wire};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

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
}
