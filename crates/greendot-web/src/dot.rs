//! The green dot: per-export health derived purely from desired state,
//! actual configfs state, and the RDMA device list.

use crate::actual::nvmet::ActualNvmet;
use crate::actual::rdma::{RdmaDev, addr_served_by_rdma};
use crate::state::Export;
use greendot_proto::DotState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot {
    pub state: DotState,
    pub reason: String,
}

fn red(reason: impl Into<String>) -> Dot {
    Dot {
        state: DotState::Red,
        reason: reason.into(),
    }
}

pub fn nvme_dot(export: &Export, actual: &ActualNvmet, rdma: &[RdmaDev]) -> Dot {
    if let Some(error) = &export.last_error {
        return red(format!("reconcile failed: {error}"));
    }
    let nqn = export.nqn();
    let Some(subsys) = actual.subsystems.iter().find(|s| s.nqn == nqn.as_str()) else {
        return red("subsystem not configured (reconcile pending?)");
    };
    let Some(ns) = subsys.namespaces.iter().find(|ns| ns.nsid == 1) else {
        return red("namespace missing");
    };
    if ns.device_path != export.device_path {
        return red(format!(
            "namespace backed by wrong device {:?}",
            ns.device_path
        ));
    }
    if !ns.enabled {
        return red("namespace disabled");
    }

    let linked: Vec<_> = actual
        .ports
        .iter()
        .filter(|p| p.subsystems.iter().any(|s| s == nqn.as_str()))
        .collect();
    let rdma_linked: Vec<_> = linked.iter().filter(|p| p.trtype == "rdma").collect();
    let other_serving = linked.iter().any(|p| p.trtype != "rdma");

    if let Some(port) = rdma_linked
        .iter()
        .find(|p| addr_served_by_rdma(&p.traddr, rdma))
    {
        return Dot {
            state: DotState::Green,
            reason: format!("serving via RDMA on {}:{}", port.traddr, port.trsvcid),
        };
    }
    let rdma_problem = match (export.want_rdma, rdma_linked.is_empty()) {
        (false, _) => "RDMA not requested for this export".to_owned(),
        (true, true) => "RDMA requested but subsystem not linked to an RDMA port".to_owned(),
        (true, false) => {
            format!(
                "no RDMA device backs listen address {}",
                rdma_linked[0].traddr
            )
        }
    };
    if other_serving {
        let transports: Vec<_> = linked
            .iter()
            .filter(|p| p.trtype != "rdma")
            .map(|p| p.trtype.as_str())
            .collect();
        Dot {
            state: DotState::Yellow,
            reason: format!(
                "serving via {} only — {}",
                transports.join("/"),
                rdma_problem
            ),
        }
    } else {
        red(format!("no port serves this subsystem — {rdma_problem}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actual::nvmet::{Namespace, Port, Subsys};
    use crate::state::ExportKind;
    use rstest::rstest;
    use std::net::IpAddr;

    const NQN: &str = "nqn.2026-06.io.greendot:vm1";
    const DEV: &str = "/dev/zvol/tank/vm1";

    fn export(want_rdma: bool, want_tcp: bool, last_error: Option<&str>) -> Export {
        Export {
            id: 1,
            kind: ExportKind::Nvme,
            name: "vm1".into(),
            device_path: DEV.into(),
            enabled: true,
            want_rdma,
            want_tcp,
            want_loop: false,
            allow_any_host: true,
            initiators: vec![],
            last_error: last_error.map(Into::into),
        }
    }

    fn subsys(ns_enabled: bool, device: &str) -> Subsys {
        Subsys {
            nqn: NQN.into(),
            allow_any_host: true,
            allowed_hosts: vec![],
            namespaces: vec![Namespace {
                nsid: 1,
                device_path: device.into(),
                enabled: ns_enabled,
            }],
        }
    }

    fn port(id: u16, trtype: &str, traddr: &str, linked: bool) -> Port {
        Port {
            id,
            trtype: trtype.into(),
            traddr: traddr.into(),
            trsvcid: "4420".into(),
            subsystems: if linked { vec![NQN.into()] } else { vec![] },
        }
    }

    fn rdma_dev(addr: &str) -> RdmaDev {
        RdmaDev {
            name: "rxe0".into(),
            addrs: vec![addr.parse::<IpAddr>().unwrap()],
        }
    }

    #[rstest]
    // Green: RDMA port linked and an RDMA device backs the address.
    #[case::green_rdma(
        export(true, true, None),
        ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "10.0.0.5", true), port(2, "tcp", "10.0.0.5", true)],
        },
        vec![rdma_dev("10.0.0.5")],
        DotState::Green, "rdma"
    )]
    // Green: wildcard listen address counts as served when any RDMA device exists.
    #[case::green_wildcard(
        export(true, false, None),
        ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "0.0.0.0", true)],
        },
        vec![rdma_dev("10.0.0.5")],
        DotState::Green, "rdma"
    )]
    // Yellow: serving TCP, RDMA never requested.
    #[case::yellow_tcp_only(
        export(false, true, None),
        ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(2, "tcp", "10.0.0.5", true)],
        },
        vec![],
        DotState::Yellow, "not requested"
    )]
    // Yellow: RDMA requested but the rdma port has no backing device.
    #[case::yellow_rdma_unbacked(
        export(true, true, None),
        ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "10.0.0.5", true), port(2, "tcp", "10.0.0.5", true)],
        },
        vec![],
        DotState::Yellow, "no RDMA device"
    )]
    // Yellow: RDMA requested but subsystem only linked on the TCP port.
    #[case::yellow_rdma_unlinked(
        export(true, true, None),
        ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "10.0.0.5", false), port(2, "tcp", "10.0.0.5", true)],
        },
        vec![rdma_dev("10.0.0.5")],
        DotState::Yellow, "not linked"
    )]
    // Red: nothing serves the subsystem.
    #[case::red_no_ports(
        export(true, true, None),
        ActualNvmet { subsystems: vec![subsys(true, DEV)], ports: vec![] },
        vec![],
        DotState::Red, "no port"
    )]
    // Red: subsystem missing entirely.
    #[case::red_missing_subsys(
        export(true, true, None),
        ActualNvmet::default(),
        vec![],
        DotState::Red, "not configured"
    )]
    // Red: namespace disabled.
    #[case::red_ns_disabled(
        export(false, true, None),
        ActualNvmet {
            subsystems: vec![subsys(false, DEV)],
            ports: vec![port(2, "tcp", "10.0.0.5", true)],
        },
        vec![],
        DotState::Red, "disabled"
    )]
    // Red: namespace backed by the wrong device.
    #[case::red_wrong_device(
        export(false, true, None),
        ActualNvmet {
            subsystems: vec![subsys(true, "/dev/zvol/tank/other")],
            ports: vec![port(2, "tcp", "10.0.0.5", true)],
        },
        vec![],
        DotState::Red, "device"
    )]
    // Red: a recorded reconcile error wins over everything.
    #[case::red_reconcile_error(
        export(true, true, Some("rdma bind failed: EADDRNOTAVAIL")),
        ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "10.0.0.5", true)],
        },
        vec![rdma_dev("10.0.0.5")],
        DotState::Red, "rdma bind failed"
    )]
    fn nvme_dot_truth_table(
        #[case] export: Export,
        #[case] actual: ActualNvmet,
        #[case] rdma: Vec<RdmaDev>,
        #[case] want_state: DotState,
        #[case] reason_contains: &str,
    ) {
        let dot = nvme_dot(&export, &actual, &rdma);
        assert_eq!(dot.state, want_state, "reason: {}", dot.reason);
        assert!(
            dot.reason
                .to_lowercase()
                .contains(&reason_contains.to_lowercase()),
            "reason {:?} should mention {:?}",
            dot.reason,
            reason_contains
        );
    }
}
