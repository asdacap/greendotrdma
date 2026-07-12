//! Client for the root helper over gRPC on its unix socket — one typed method
//! per rpc. Task rpcs return the recorded event stream on a channel (with a
//! synthetic terminal `Finished` on transport failure); typed reads return the
//! shared `actual::*` DTOs, degrading to empty on failure like every other
//! read in the web. The tonic channel is lazy and reconnects on its own, so a
//! cloned `HelperClient` is cheap and survives helper restarts.

use anyhow::{Result, anyhow};
use greendot_proto::actual::{lio, nfs, nic, nvmet, rdma};
use greendot_proto::pb::helper_client::HelperClient as GrpcClient;
use greendot_proto::{AuthResult, BlockDev, SubStatus, TaskEvent, ops, pb};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tonic::transport::Channel;

#[derive(Clone)]
pub struct HelperClient {
    inner: GrpcClient<Channel>,
}

/// Output of a task run drained by [`collect`].
#[derive(Debug, Default)]
pub struct HelperOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

/// A terminal failure event synthesized when the transport itself fails, so a
/// consumer of a task rpc always sees a `Finished`.
fn transport_failure(msg: String) -> TaskEvent {
    TaskEvent::Finished {
        status: SubStatus::Failed,
        error: Some(msg),
    }
}

/// Drains a task rpc's stream to completion, concatenating its output without
/// recording a DB task. Used for the tool-output reads (LVM/SMART/rdma dumps)
/// that must not clutter the Tasks page.
pub async fn collect(mut rx: mpsc::Receiver<TaskEvent>) -> HelperOutput {
    let mut out = HelperOutput::default();
    while let Some(ev) = rx.recv().await {
        match ev {
            TaskEvent::Stdout { data } => out.stdout.push_str(&data),
            TaskEvent::Stderr { data } => out.stderr.push_str(&data),
            TaskEvent::Finished { status, error } => {
                out.ok = status != SubStatus::Failed;
                out.error = error;
                break;
            }
            TaskEvent::SubtaskStarted { .. } | TaskEvent::SubtaskFinished { .. } => {}
        }
    }
    out
}

/// One task rpc: sends the validated op, returns the event stream.
macro_rules! task_rpcs {
    ($($method:ident($op:ty => $wire:ty);)*) => {$(
        pub fn $method(&self, op: $op) -> mpsc::Receiver<TaskEvent> {
            let mut client = self.inner.clone();
            Self::stream(async move { client.$method(<$wire>::from(op)).await })
        }
    )*};
}

/// One typed read: answers the shared DTO, empty on any failure (the pages
/// render that as drift/unknown, the same graceful degradation as elsewhere).
macro_rules! read_rpcs {
    ($($method:ident -> $dto:ty;)*) => {$(
        pub async fn $method(&self) -> $dto {
            match self.inner.clone().$method(pb::Empty {}).await {
                Ok(r) => r.into_inner().into(),
                Err(e) => {
                    tracing::warn!(error = %e, rpc = stringify!($method), "helper read failed");
                    <$dto>::default()
                }
            }
        }
    )*};
}

impl HelperClient {
    pub fn new(socket: PathBuf) -> Self {
        // `connect_uds` only fails on an invalid static endpoint URI, never here.
        let inner = greendot_proto::client::connect_uds(socket)
            .expect("helper endpoint should always be constructible");
        HelperClient { inner }
    }

    /// PAM authentication — the one op with a first-class reply and no task
    /// record (recording it would write the password into the task log).
    pub async fn authenticate(&self, op: ops::Authenticate) -> Result<AuthResult> {
        let reply = self
            .inner
            .clone()
            .authenticate(pb::Authenticate::from(op))
            .await
            .map_err(|e| anyhow!("helper call failed: {e}"))?
            .into_inner();
        AuthResult::try_from(reply).map_err(|e| anyhow!("bad response from helper: {e}"))
    }

    /// Runs one task rpc call, delivering the helper's streamed events on the
    /// returned channel. A synthetic `Finished` is always sent (even on
    /// transport failure) so the consumer can rely on a terminal event.
    fn stream<F>(call: F) -> mpsc::Receiver<TaskEvent>
    where
        F: Future<
                Output = std::result::Result<
                    tonic::Response<tonic::Streaming<pb::TaskEvent>>,
                    tonic::Status,
                >,
            > + Send
            + 'static,
    {
        let (tx, rx) = mpsc::channel(128);
        tokio::spawn(async move {
            let mut stream = match call.await {
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

    task_rpcs! {
        zvol_create(ops::ZvolCreate => pb::ZvolCreate);
        zvol_delete(ops::ZvolDelete => pb::ZvolDelete);
        zvol_resize(ops::ZvolResize => pb::ZvolResize);
        snapshot_create(ops::SnapshotCreate => pb::SnapshotCreate);
        snapshot_destroy(ops::SnapshotDestroy => pb::SnapshotDestroy);
        zfs_fs_create(ops::ZfsFsCreate => pb::ZfsFsCreate);
        zfs_set_mountpoint(ops::ZfsSetMountpoint => pb::ZfsSetMountpoint);
        zfs_mount(ops::ZfsMount => pb::ZfsMount);
        zfs_unmount(ops::ZfsUnmount => pb::ZfsUnmount);
        zfs_destroy(ops::ZfsDestroy => pb::ZfsDestroy);
        pool_create(ops::PoolCreate => pb::PoolCreate);
        pool_device_add(ops::PoolDeviceAdd => pb::PoolDeviceAdd);
        pool_device_remove(ops::PoolDeviceRemove => pb::PoolDeviceRemove);
        pool_device_detach(ops::PoolDeviceDetach => pb::PoolDeviceDetach);
        partition_table_create(ops::PartitionTableCreate => pb::PartitionTableCreate);
        partition_create(ops::PartitionCreate => pb::PartitionCreate);
        partition_delete(ops::PartitionDelete => pb::PartitionDelete);
        partition_shrink(ops::PartitionShrink => pb::PartitionShrink);
        lvm_report(ops::LvmReport => pb::LvmReport);
        vg_create(ops::VgCreate => pb::VgCreate);
        vg_extend(ops::VgExtend => pb::VgExtend);
        vg_reduce(ops::VgReduce => pb::VgReduce);
        vg_remove(ops::VgRemove => pb::VgRemove);
        lv_create(ops::LvCreate => pb::LvCreate);
        thin_pool_create(ops::ThinPoolCreate => pb::ThinPoolCreate);
        thin_lv_create(ops::ThinLvCreate => pb::ThinLvCreate);
        lv_resize(ops::LvResize => pb::LvResize);
        lv_shrink(ops::LvShrink => pb::LvShrink);
        lv_rename(ops::LvRename => pb::LvRename);
        lv_delete(ops::LvDelete => pb::LvDelete);
        rxe_add(ops::RxeAdd => pb::RxeAdd);
        enable_roce(ops::EnableRoce => pb::EnableRoce);
        install_packages(ops::InstallPackages => pb::InstallPackages);
        smart_report(ops::SmartReport => pb::SmartReport);
        pipe_key_add(ops::PipeKeyAdd => pb::PipeKeyAdd);
        pipe_key_revoke(ops::PipeKeyRevoke => pb::PipeKeyRevoke);
    }

    /// The full desired-state reconcile pass (fieldless by design: the daemon
    /// reconciles against its own config).
    pub fn reconcile(&self) -> mpsc::Receiver<TaskEvent> {
        let mut client = self.inner.clone();
        Self::stream(async move { client.reconcile(pb::Reconcile {}).await })
    }

    /// Live RDMA connections, streamed as the `rdma` tool's own JSON for
    /// [`collect`] + `actual::rdma::peers_from_json`.
    pub fn rdma_resources(&self) -> mpsc::Receiver<TaskEvent> {
        let mut client = self.inner.clone();
        Self::stream(async move { client.rdma_resources(pb::Empty {}).await })
    }

    read_rpcs! {
        nfs_report -> nfs::ActualNfs;
        nvmet_report -> nvmet::ActualNvmet;
        lio_report -> lio::ActualLio;
        lio_sessions -> Vec<lio::IscsiSession>;
        rdma_devices -> Vec<rdma::RdmaDev>;
        nic_pci_addrs -> HashMap<String, Vec<IpAddr>>;
        nic_interfaces -> Vec<nic::NicStatus>;
        nic_network -> Vec<nic::NicNetwork>;
        roce_capable_nics -> HashMap<String, String>;
        nic_rdma_advice -> HashMap<String, nic::NicAdvice>;
        reconcile_dry_run -> pb::ReconcileDryRunReply;
        pipe_access_report -> pb::PipeAccessReportReply;
    }

    /// Batch SMART health; an empty reply on failure renders every device gray.
    pub async fn smart_health(&self, devices: Vec<BlockDev>) -> pb::SmartHealthReply {
        let op = ops::SmartHealth { devices };
        match self
            .inner
            .clone()
            .smart_health(pb::SmartHealth::from(op))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => {
                tracing::warn!(error = %e, "helper SMART health read failed");
                pb::SmartHealthReply::default()
            }
        }
    }
}
