//! Per-NIC RDMA capability. The structural classification (pure over sysfs) moved
//! to the shared `greendot-reconcile` crate; the one vendor-aware step — overlaying
//! the helper's RoCE-capable / advisory verdicts — stays here on the web's async
//! `HelperClient`. Re-exports the shared pure parts so `crate::actual::nic::*`
//! paths keep working; the web carries no vendor knowledge itself.

use crate::helper_client::HelperClient;
use greendot_proto::Request;
use std::collections::HashMap;
use std::path::Path;

pub use greendot_reconcile::actual::nic::*;

/// Live NIC classification from `/sys`, with the RoCE-capable-hardware verdict
/// supplied by the helper (the only vendor-aware step).
pub async fn interfaces(helper: &HelperClient) -> Vec<NicStatus> {
    let roce_hw = roce_capable(helper).await;
    classify(
        Path::new("/sys/class/net"),
        Path::new("/sys/class/infiniband"),
        &super::rdma::netdev_addrs(),
        &roce_hw,
    )
}

/// The helper's RoCE-capable NIC inventory as `netdev → vendor`. A transport
/// failure or empty inventory yields no capable NICs (every plain NIC then reads
/// as a Soft-RoCE candidate), the same graceful degradation as elsewhere.
async fn roce_capable(helper: &HelperClient) -> HashMap<String, String> {
    parse_roce_capable(&helper.collect(Request::RoceCapableNics).await.stdout)
}

/// The helper's per-NIC advisories as `netdev → advice`. A transport failure or
/// empty inventory yields no advisories, the same graceful degradation as
/// elsewhere.
pub async fn rdma_advice(helper: &HelperClient) -> HashMap<String, NicAdvice> {
    parse_nic_advice(&helper.collect(Request::NicRdmaAdvice).await.stdout)
}
