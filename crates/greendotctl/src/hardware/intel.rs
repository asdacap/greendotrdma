//! Intel NICs. Advisory-only today: no Intel family has a supported one-click
//! enable flow, but irdma-capable SR-IOV VFs get a diagnostic advisory (the
//! host-side driver-ordering requirement is invisible from the VF).

use super::{NetworkHardware, RoceState, device_id, devlink};
use crate::cmd::TaskSpec;
use greendot_proto::PciAddress;
use std::path::Path;

pub(super) struct Intel;

/// PCI device ids of Intel Ethernet *Adaptive Virtual Functions* (`iavf`) — the
/// SR-IOV VFs of the irdma-capable families (E810/`ice`, X7xx/`i40e`). These
/// VFs get RDMA only when the host loads `irdma` before the VF count is set;
/// non-RDMA Intel VFs (igb/ixgbe) use other ids and are deliberately excluded.
/// One entry today; extend the slice to cover more irdma VF ids.
const INTEL_IRDMA_VF_IDS: &[&str] = &["0x1889"];

/// Human advisory for a detected Intel irdma VF that has no RDMA.
pub(super) const IRDMA_VF_LABEL: &str =
    "SR-IOV VF: host must load the RDMA driver before creating VFs";
const IRDMA_VF_DETAIL: &str = "This is an Intel Ethernet Adaptive virtual function. RDMA on the VF \
     works only if the host loads the irdma driver (modprobe irdma) BEFORE the \
     VF count is set via sriov_numvfs. VFs created before irdma is loaded come \
     up without RDMA — on the host, load irdma, then re-create the VFs.";

impl NetworkHardware for Intel {
    fn vendor(&self) -> &'static str {
        "Intel"
    }

    /// Intel's PCI vendor id.
    fn matches(&self, vendor_id: &str) -> bool {
        vendor_id == "0x8086"
    }

    /// No supported one-click enable flow — advisory-only.
    fn enableable(&self, _net_dir: &Path) -> bool {
        false
    }

    // probe/interpret/enable are unreachable while `enableable` is false; they
    // state the honest answer anyway (no settable parameter, nothing to run).
    fn probe(&self, pci: &PciAddress) -> TaskSpec {
        devlink(&["dev", "param", "show", &format!("pci/{pci}"), "-j"])
    }

    fn interpret(&self, _stdout: &str) -> RoceState {
        RoceState::Unavailable
    }

    fn enable(&self, _pci: &PciAddress) -> Vec<TaskSpec> {
        Vec::new()
    }

    /// `irdma` (E810/X7xx RDMA) never auto-loads — the same host-side load the
    /// VF advisory below demands.
    fn rdma_modules(&self) -> &'static [&'static str] {
        &["irdma"]
    }

    fn advice(&self, net_dir: &Path) -> Option<(&'static str, &'static str)> {
        let dev = device_id(net_dir)?;
        INTEL_IRDMA_VF_IDS
            .contains(&dev.as_str())
            .then_some((IRDMA_VF_LABEL, IRDMA_VF_DETAIL))
    }
}
