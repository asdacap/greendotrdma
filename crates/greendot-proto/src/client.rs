//! A gRPC client over the helper's Unix socket. Shared by greendot-web,
//! greendot-reconcile, and the daemon's own integration test so the UDS dialer
//! is written once.

use crate::pb::helper_client::HelperClient;
use hyper_util::rt::TokioIo;
use std::path::PathBuf;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// Message-size ceiling, mirroring the daemon's `MAX_MESSAGE` and the old NDJSON
/// `MAX_LINE` (256 KiB).
pub const MAX_MESSAGE: usize = 256 * 1024;

/// Build a lazily-connecting gRPC client bound to the helper socket at `path`.
///
/// The channel is lazy: it dials the socket on first use and transparently
/// reconnects, so the client survives a helper restart and can be constructed
/// before the daemon is up. The HTTP `:authority` is a placeholder — the
/// connector always dials the Unix socket, ignoring the URI.
pub fn connect_uds(path: PathBuf) -> Result<HelperClient<Channel>, tonic::transport::Error> {
    let channel = Endpoint::try_from("http://[::1]:50051")?.connect_with_connector_lazy(
        service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }),
    );
    Ok(HelperClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE)
        .max_encoding_message_size(MAX_MESSAGE))
}
