//! On-demand kernel module loading from a fixed table. Failures surface to
//! the UI as dot reasons instead of boot-time errors.

use crate::cmd::{Runner, run_checked};
use greendot_proto::{KernelModule, Response};

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

pub fn ensure(runner: &dyn Runner, modules: &[KernelModule]) -> Response {
    let mut argv: Vec<String> = vec!["modprobe".into(), "-a".into()];
    for module in modules {
        for name in modprobe_names(*module) {
            if !argv.iter().any(|a| a == name) {
                argv.push((*name).into());
            }
        }
    }
    if argv.len() == 2 {
        return Response::Ok;
    }
    run_checked(runner, &argv)
}

/// Creates a Soft-RoCE (rxe) device on top of a netdev, giving real RDMA
/// semantics on any NIC. Idempotent-ish: an existing link of the same name
/// makes `rdma` exit non-zero, which surfaces as a CmdFailed the UI shows.
pub fn rxe_link_add(runner: &dyn Runner, netdev: &greendot_proto::NetdevName) -> Response {
    let argv: Vec<String> = [
        "rdma",
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
    .collect();
    run_checked(runner, &argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Recorder;

    #[test]
    fn modprobe_argv_is_deduplicated_and_empty_list_is_a_noop() {
        let recorder = Recorder::default();
        let resp = ensure(
            &recorder,
            &[
                KernelModule::NvmetRdma,
                KernelModule::NvmetTcp,
                KernelModule::Rxe,
            ],
        );
        assert_eq!(resp, Response::Ok);
        assert_eq!(
            recorder.calls(),
            vec![
                [
                    "modprobe",
                    "-a",
                    "nvmet",
                    "nvmet_rdma",
                    "nvmet_tcp",
                    "rdma_rxe"
                ]
                .map(String::from)
                .to_vec()
            ]
        );

        let recorder = Recorder::default();
        assert_eq!(ensure(&recorder, &[]), Response::Ok);
        assert!(recorder.calls().is_empty(), "no modules, no modprobe");
    }

    #[test]
    fn rxe_link_add_argv() {
        let recorder = Recorder::default();
        let netdev = greendot_proto::NetdevName::new("eth0").unwrap();
        assert_eq!(rxe_link_add(&recorder, &netdev), Response::Ok);
        assert_eq!(
            recorder.calls(),
            vec![
                [
                    "rdma", "link", "add", "rxe-eth0", "type", "rxe", "netdev", "eth0"
                ]
                .map(String::from)
                .to_vec()
            ]
        );
    }
}
