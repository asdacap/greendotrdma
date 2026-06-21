//! Kernel module loading (`modprobe`), Soft-RoCE setup (`rdma`), and hardware
//! RoCE enablement (`devlink`) as tasks.

use crate::cmd::TaskSpec;
use greendot_proto::{KernelModule, NetdevName, PciAddress};

/// Builds a `devlink` task with the given arguments.
fn devlink(args: &[&str]) -> TaskSpec {
    TaskSpec::new("devlink", args.iter().map(|s| s.to_string()).collect())
}

fn modprobe_names(module: KernelModule) -> &'static [&'static str] {
    match module {
        KernelModule::NvmetLoop => &["nvmet", "nvme_loop"],
        KernelModule::NvmetTcp => &["nvmet", "nvmet_tcp"],
        KernelModule::NvmetRdma => &["nvmet", "nvmet_rdma"],
        KernelModule::Iscsi => &["target_core_mod", "iscsi_target_mod"],
        KernelModule::Iser => &["ib_isert"],
        KernelModule::Rxe => &["rdma_rxe"],
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

/// `devlink dev param show pci/<pci> -j` — read params to confirm `enable_roce`
/// before attempting the fix. A privileged *read* (collected, not recorded).
pub fn devlink_params(pci: &PciAddress) -> TaskSpec {
    devlink(&["dev", "param", "show", &format!("pci/{pci}"), "-j"])
}

/// `devlink dev param set pci/<pci> name enable_roce value true cmode driverinit`.
/// Hard-coded to `enable_roce` so the allowlist can't set arbitrary params.
pub fn devlink_roce_enable(pci: &PciAddress) -> TaskSpec {
    devlink(&[
        "dev",
        "param",
        "set",
        &format!("pci/{pci}"),
        "name",
        "enable_roce",
        "value",
        "true",
        "cmode",
        "driverinit",
    ])
}

/// `devlink dev reload pci/<pci>` — re-init the device so a driverinit param
/// takes effect. Resets the device's netdevs.
pub fn devlink_reload(pci: &PciAddress) -> TaskSpec {
    devlink(&["dev", "reload", &format!("pci/{pci}")])
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
    fn devlink_args() {
        let pci = PciAddress::new("0000:00:10.0").unwrap();
        assert_eq!(devlink_params(&pci).command, "devlink");
        assert_eq!(
            devlink_params(&pci).args,
            ["dev", "param", "show", "pci/0000:00:10.0", "-j"].map(String::from)
        );
        assert_eq!(
            devlink_roce_enable(&pci).args,
            [
                "dev",
                "param",
                "set",
                "pci/0000:00:10.0",
                "name",
                "enable_roce",
                "value",
                "true",
                "cmode",
                "driverinit"
            ]
            .map(String::from)
        );
        assert_eq!(
            devlink_reload(&pci).args,
            ["dev", "reload", "pci/0000:00:10.0"].map(String::from)
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
