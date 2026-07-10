//! Kernel module loading (`modprobe`) and Soft-RoCE setup (`rdma`) as tasks.
//! Hardware-RoCE enablement (`devlink`) lives in [`crate::hardware`], behind the
//! `NetworkHardware` trait.

use crate::cmd::{self, TaskSpec};
use greendot_proto::{KernelModule, NetdevName, SubStatus, Task, Transport};
use std::io;

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

/// Whether this module serves traffic over hardware RDMA — i.e. loading it is
/// only useful once the NIC's own RDMA driver is up too. Soft-RoCE (`Rxe`) is
/// deliberately not one: `rdma_rxe` itself is the RDMA device.
fn rides_hardware_rdma(module: KernelModule) -> bool {
    matches!(
        module,
        KernelModule::NvmetRdma | KernelModule::Iser | KernelModule::Rpcrdma
    )
}

/// The nvmet transport module behind one CSI export's transport.
pub fn transport_module(transport: Transport) -> KernelModule {
    match transport {
        Transport::Rdma => KernelModule::NvmetRdma,
        Transport::Tcp => KernelModule::NvmetTcp,
        Transport::Loop => KernelModule::NvmetLoop,
    }
}

/// Every module an apply might need, regardless of what is currently desired.
/// Loaded once at daemon startup so the RDMA device exists *before* the first
/// export is configured — `irdma` never auto-loads, and until it is up the UI
/// cannot offer an RDMA export to create, which would load it.
///
/// `Rxe` is excluded: `rdma_rxe` *is* the Soft-RoCE device, so loading it is
/// part of enabling Soft-RoCE, which [`rxe_add`] does on request.
pub const STARTUP_MODULES: &[KernelModule] = &[
    KernelModule::NvmetLoop,
    KernelModule::NvmetTcp,
    KernelModule::NvmetRdma,
    KernelModule::Iscsi,
    KernelModule::Iser,
    KernelModule::Rpcrdma,
];

/// `modprobe -a` for the requested set, plus `nic_rdma_modules` (the
/// recognized NICs' RDMA drivers, see [`crate::hardware::rdma_driver_modules`])
/// when any requested module rides hardware RDMA. `None` when the whole set is
/// empty.
pub fn ensure(modules: &[KernelModule], nic_rdma_modules: &[&str]) -> Option<TaskSpec> {
    let mut names: Vec<String> = vec!["-a".into()];
    let mut push = |name: &str| {
        if !names.iter().any(|n| n == name) {
            names.push(name.into());
        }
    };
    for module in modules {
        for name in modprobe_names(*module) {
            push(name);
        }
    }
    if modules.iter().copied().any(rides_hardware_rdma) {
        for name in nic_rdma_modules {
            push(name);
        }
    }
    (names.len() > 1).then(|| TaskSpec::new("modprobe", names))
}

/// Enables Soft-RoCE on `netdev` as one task: load the rxe module, then add
/// the rdma link (only if the load succeeded). `Err` only on a sink failure.
pub fn rxe_add(task: &mut Task, netdev: &NetdevName) -> io::Result<()> {
    if let Some(spec) = ensure(&[KernelModule::Rxe], &[])
        && cmd::run(task, "Load rxe module", &spec)? != SubStatus::Success
    {
        return Ok(());
    }
    let spec = rxe_link_add(netdev);
    cmd::run(task, format!("Add Soft-RoCE link on {netdev}"), &spec)?;
    Ok(())
}

/// `rdma link add rxe-<netdev> type rxe netdev <netdev>` (Soft-RoCE).
fn rxe_link_add(netdev: &NetdevName) -> TaskSpec {
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
    fn startup_set_loads_every_transport_and_present_nic_drivers() {
        let spec = ensure(STARTUP_MODULES, &["irdma"]).expect("startup set is never empty");
        assert_eq!(spec.command, "modprobe");
        for name in [
            "nvmet",
            "nvme_loop",
            "nvmet_tcp",
            "nvmet_rdma",
            "target_core_mod",
            "iscsi_target_mod",
            "ib_isert",
            "rpcrdma",
            // The startup set rides hardware RDMA, so a present NIC's driver
            // comes along — this is what breaks the irdma chicken-and-egg.
            "irdma",
        ] {
            assert!(spec.args.iter().any(|a| a == name), "{name} not loaded");
        }
        // Soft-RoCE is enabled on request, never at startup.
        assert!(!spec.args.iter().any(|a| a == "rdma_rxe"));
        // No recognized NIC → no driver modules, transports load regardless.
        let bare = ensure(STARTUP_MODULES, &[]).unwrap();
        assert!(!bare.args.iter().any(|a| a == "irdma"));
        assert!(bare.args.iter().any(|a| a == "nvmet_rdma"));
    }

    #[test]
    fn modprobe_args_deduped_nic_riders_and_empty_is_none() {
        let spec = ensure(
            &[
                KernelModule::NvmetRdma,
                KernelModule::NvmetTcp,
                KernelModule::Rxe,
            ],
            &["irdma", "nvmet"], // rdma rider present → appended, still deduped
        )
        .unwrap();
        assert_eq!(spec.command, "modprobe");
        assert_eq!(
            spec.args,
            [
                "-a",
                "nvmet",
                "nvmet_rdma",
                "nvmet_tcp",
                "rdma_rxe",
                "irdma"
            ]
            .map(String::from)
            .to_vec()
        );
        // No hardware-RDMA rider → NIC drivers stay unloaded; soft-RoCE is
        // deliberately not a rider.
        assert_eq!(
            ensure(&[KernelModule::NvmetTcp, KernelModule::Rxe], &["irdma"])
                .unwrap()
                .args,
            ["-a", "nvmet", "nvmet_tcp", "rdma_rxe"]
                .map(String::from)
                .to_vec()
        );
        assert!(ensure(&[], &["irdma"]).is_none());
    }

    #[test]
    fn transport_maps_to_its_nvmet_module() {
        assert_eq!(
            [Transport::Rdma, Transport::Tcp, Transport::Loop].map(transport_module),
            [
                KernelModule::NvmetRdma,
                KernelModule::NvmetTcp,
                KernelModule::NvmetLoop
            ]
        );
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
