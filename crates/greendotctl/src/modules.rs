//! Kernel module loading (`modprobe`) and Soft-RoCE setup (`rdma`) as tasks.
//! Hardware-RoCE enablement (`devlink`) lives in [`crate::hardware`], behind the
//! `NetworkHardware` trait.

use crate::cmd::TaskSpec;
use greendot_proto::{KernelModule, NetdevName};

fn modprobe_names(module: KernelModule) -> &'static [&'static str] {
    match module {
        KernelModule::NvmetLoop => &["nvmet", "nvme_loop"],
        KernelModule::NvmetTcp => &["nvmet", "nvmet_tcp"],
        KernelModule::NvmetRdma => &["nvmet", "nvmet_rdma"],
        KernelModule::Iscsi => &["target_core_mod", "iscsi_target_mod"],
        KernelModule::Iser => &["ib_isert"],
        KernelModule::Rxe => &["rdma_rxe"],
        // The real module is `rpcrdma`; `svcrdma`/`xprtrdma` are aliases for it.
        KernelModule::Rpcrdma => &["rpcrdma"],
    }
}

/// `modprobe -a <names>` for the requested set. `None` when the set is empty.
pub fn ensure(modules: &[KernelModule]) -> Option<TaskSpec> {
    let mut names: Vec<String> = vec!["-a".into()];
    for module in modules {
        for name in modprobe_names(*module) {
            if !names.iter().any(|n| n == name) {
                names.push((*name).into());
            }
        }
    }
    (names.len() > 1).then(|| TaskSpec::new("modprobe", names))
}

/// `rdma link add rxe-<netdev> type rxe netdev <netdev>` (Soft-RoCE).
pub fn rxe_link_add(netdev: &NetdevName) -> TaskSpec {
    TaskSpec::new(
        "rdma",
        [
            "link",
            "add",
            &format!("rxe-{netdev}"),
            "type",
            "rxe",
            "netdev",
            netdev.as_str(),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    )
}

/// `rdma -j resource show cm_id` — list live RDMA connections as JSON. A
/// privileged *read* (collected, not recorded) used to surface NVMe-oF/iSER
/// peers; root guarantees peer addresses are visible.
pub fn rdma_resources() -> TaskSpec {
    TaskSpec::new(
        "rdma",
        ["-j", "resource", "show", "cm_id"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modprobe_args_deduped_and_empty_is_none() {
        let spec = ensure(&[
            KernelModule::NvmetRdma,
            KernelModule::NvmetTcp,
            KernelModule::Rxe,
        ])
        .unwrap();
        assert_eq!(spec.command, "modprobe");
        assert_eq!(
            spec.args,
            ["-a", "nvmet", "nvmet_rdma", "nvmet_tcp", "rdma_rxe"]
                .map(String::from)
                .to_vec()
        );
        assert!(ensure(&[]).is_none());
    }

    #[test]
    fn rxe_link_add_args() {
        let spec = rxe_link_add(&NetdevName::new("eth0").unwrap());
        assert_eq!(spec.command, "rdma");
        assert_eq!(
            spec.args,
            ["link", "add", "rxe-eth0", "type", "rxe", "netdev", "eth0"]
                .map(String::from)
                .to_vec()
        );
    }

    #[test]
    fn rdma_resources_args() {
        let spec = rdma_resources();
        assert_eq!(spec.command, "rdma");
        assert_eq!(
            spec.args,
            ["-j", "resource", "show", "cm_id"].map(String::from)
        );
    }
}
