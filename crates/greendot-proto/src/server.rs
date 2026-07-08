//! Server-side ingress adapter. [`Validated`] implements the generated gRPC
//! `Helper` service over a domain-level [`DomainHelper`], running every
//! incoming request through the validating `TryFrom` conversion in exactly one
//! place per RPC — daemon code only ever sees the validated domain
//! [`CallRequest`]/[`TaskRequest`], so the choke point cannot be skipped.

use crate::{CallRequest, ErrKind, Response, TaskRequest, pb};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

/// The validated, domain-level service the daemon implements.
#[tonic::async_trait]
pub trait DomainHelper: Send + Sync + 'static {
    /// One-shot request → immediate reply. The request type admits only the ops
    /// that are answered this way, so there is no "wrong RPC" case to reject.
    async fn call(&self, req: CallRequest) -> Response;

    /// Streamed task run. `req` is `Err(reason)` when the peer's protobuf
    /// failed validation — the impl must still emit a failed task carrying
    /// the reason, so it reaches the recorded stream.
    async fn run_task(
        &self,
        req: Result<TaskRequest, String>,
    ) -> mpsc::Receiver<Result<pb::TaskEvent, Status>>;
}

/// Adapter from a [`DomainHelper`] to the generated `pb` service.
pub struct Validated<S>(pub S);

#[tonic::async_trait]
impl<S: DomainHelper> pb::helper_server::Helper for Validated<S> {
    async fn call(
        &self,
        request: TonicRequest<pb::CallRequest>,
    ) -> Result<TonicResponse<pb::Response>, Status> {
        let resp = match CallRequest::try_from(request.into_inner()) {
            Ok(req) => self.0.call(req).await,
            Err(e) => Response::err(ErrKind::Validation, e.to_string()),
        };
        Ok(TonicResponse::new(resp.into()))
    }

    type RunTaskStream = ReceiverStream<Result<pb::TaskEvent, Status>>;

    async fn run_task(
        &self,
        request: TonicRequest<pb::TaskRequest>,
    ) -> Result<TonicResponse<Self::RunTaskStream>, Status> {
        let req = TaskRequest::try_from(request.into_inner()).map_err(|e| e.to_string());
        Ok(TonicResponse::new(ReceiverStream::new(
            self.0.run_task(req).await,
        )))
    }
}
