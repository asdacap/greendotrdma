//! The green dot: per-export health derived purely from desired state,
//! actual configfs state, and the RDMA device list.

use crate::actual::lio::{ActualLio, Portal, Target};
use crate::actual::nfs::ActualNfs;
use crate::actual::nvmet::{ActualNvmet, Port};
use crate::actual::rdma::{RdmaDev, addr_served_by_rdma};
use crate::state::{IscsiExport, NfsExport, NvmeExport};
use greendot_proto::DotState;
use std::net::IpAddr;

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

pub fn nvme_dot(export: &NvmeExport, actual: &ActualNvmet, rdma: &[RdmaDev]) -> Dot {
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

pub fn iscsi_dot(export: &IscsiExport, actual: &ActualLio, rdma: &[RdmaDev]) -> Dot {
    if let Some(error) = &export.last_error {
        return red(format!("reconcile failed: {error}"));
    }
    let iqn = export.iqn();
    let Some(backstore) = actual.backstores.iter().find(|b| b.name == export.name) else {
        return red("backstore not configured (reconcile pending?)");
    };
    if backstore.udev_path != export.device_path {
        return red(format!(
            "backstore backed by wrong device {:?}",
            backstore.udev_path
        ));
    }
    if !backstore.enabled {
        return red("backstore disabled");
    }
    let Some(target) = actual.targets.iter().find(|t| t.iqn == iqn.as_str()) else {
        return red("iSCSI target missing");
    };
    if !target.enabled {
        return red("target portal group disabled");
    }
    if !target.luns.iter().any(|l| l == &export.name) {
        return red("LUN not mapped");
    }

    if let Some(portal) = target
        .portals
        .iter()
        .find(|p| p.iser && addr_served_by_rdma(p.addr(), rdma))
    {
        return Dot {
            state: DotState::Green,
            reason: format!("serving via iSER (RDMA) on {}", portal.addr_port),
        };
    }
    let iser_portals: Vec<_> = target.portals.iter().filter(|p| p.iser).collect();
    let rdma_problem = match (export.want_rdma, iser_portals.is_empty()) {
        (false, _) => "RDMA (iSER) not requested for this export".to_owned(),
        (true, true) => "RDMA requested but no iSER portal exists".to_owned(),
        (true, false) => {
            format!(
                "no RDMA device backs iSER portal {}",
                iser_portals[0].addr_port
            )
        }
    };
    if target.portals.iter().any(|p| !p.iser) {
        Dot {
            state: DotState::Yellow,
            reason: format!("serving via plain iSCSI/TCP — {rdma_problem}"),
        }
    } else {
        red(format!("no usable portal — {rdma_problem}"))
    }
}

/// RDMA status for an *external* NVMe-oF subsystem — one greendot neither created
/// nor reconciles (e.g. provisioned by democratic-csi). There is no desired state
/// to compare against, so this reports only what the kernel is actually doing:
/// Green when a linked RDMA port is backed by an RDMA device, Yellow when it
/// serves over another transport (or an unbacked RDMA port) only, Red when
/// nothing serves it. Shares `addr_served_by_rdma` with [`nvme_dot`].
pub fn external_nvme_dot(nqn: &str, actual: &ActualNvmet, rdma: &[RdmaDev]) -> Dot {
    let linked: Vec<&Port> = actual
        .ports
        .iter()
        .filter(|p| p.subsystems.iter().any(|s| s == nqn))
        .collect();
    if let Some(port) = linked
        .iter()
        .filter(|p| p.trtype == "rdma")
        .find(|p| addr_served_by_rdma(&p.traddr, rdma))
    {
        return Dot {
            state: DotState::Green,
            reason: format!("serving via RDMA on {}:{}", port.traddr, port.trsvcid),
        };
    }
    if linked.is_empty() {
        return red("present but no port serves this subsystem");
    }
    let reason = match linked.iter().find(|p| p.trtype == "rdma") {
        Some(p) => format!("no RDMA device backs RDMA port {}", p.traddr),
        None => {
            let transports: Vec<_> = linked.iter().map(|p| p.trtype.as_str()).collect();
            format!("serving via {} only — no RDMA port", transports.join("/"))
        }
    };
    Dot {
        state: DotState::Yellow,
        reason,
    }
}

/// RDMA (iSER) status for an *external* iSCSI target greendot doesn't manage.
/// The same honest, desired-state-free reading as [`external_nvme_dot`].
pub fn external_iscsi_dot(target: &Target, rdma: &[RdmaDev]) -> Dot {
    if let Some(portal) = target
        .portals
        .iter()
        .find(|p| p.iser && addr_served_by_rdma(p.addr(), rdma))
    {
        return Dot {
            state: DotState::Green,
            reason: format!("serving via iSER (RDMA) on {}", portal.addr_port),
        };
    }
    if target.portals.is_empty() {
        return red("present but no portal serves this target");
    }
    let reason = match target.portals.iter().find(|p| p.iser) {
        Some(p) => format!("no RDMA device backs iSER portal {}", p.addr_port),
        None => "serving via plain iSCSI/TCP only — no iSER portal".to_owned(),
    };
    Dot {
        state: DotState::Yellow,
        reason,
    }
}

/// The green dot for an NFS export. Green only when the path is exported, the
/// nfsd RDMA listener is active, and an RDMA device backs the server listen
/// address. NFSoRDMA binds server-wide on `0.0.0.0:<port>` (no per-export
/// listen), so the listen check uses the same "any active device" standard the
/// wildcard nvmet port already uses.
pub fn nfs_dot(export: &NfsExport, actual: &ActualNfs, rdma: &[RdmaDev], listen: IpAddr) -> Dot {
    if let Some(error) = &export.last_error {
        return red(format!("reconcile failed: {error}"));
    }
    if !actual.exported(&export.path) {
        return red("not exported (reconcile pending?)");
    }
    let Some(port) = actual.rdma_port else {
        return Dot {
            state: DotState::Yellow,
            reason: "exported over TCP only — NFSoRDMA transport not active".to_owned(),
        };
    };
    if !addr_served_by_rdma(&listen.to_string(), rdma) {
        return Dot {
            state: DotState::Yellow,
            reason: format!("NFSoRDMA enabled but no RDMA device backs listen address {listen}"),
        };
    }
    Dot {
        state: DotState::Green,
        reason: format!("serving via NFSoRDMA on {listen}:{port}"),
    }
}

/// RDMA status for a foreign NFS export (present in the export table but not
/// managed by greendot). It is exported by definition, so this reports only the
/// observed transport — the desired-state-free reading of [`external_nvme_dot`].
pub fn external_nfs_dot(actual: &ActualNfs, rdma: &[RdmaDev], listen: IpAddr) -> Dot {
    match actual.rdma_port {
        Some(port) if addr_served_by_rdma(&listen.to_string(), rdma) => Dot {
            state: DotState::Green,
            reason: format!("serving via NFSoRDMA on {listen}:{port}"),
        },
        Some(_) => Dot {
            state: DotState::Yellow,
            reason: format!("NFSoRDMA listener active but no RDMA device backs {listen}"),
        },
        None => Dot {
            state: DotState::Yellow,
            reason: "exported over TCP only — no NFSoRDMA listener".to_owned(),
        },
    }
}

/// One checklist row on the Diagnose page: a single RDMA-readiness condition,
/// whether it holds, and the observed value behind that verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Criterion {
    pub label: String,
    pub ok: bool,
    pub detail: String,
}

fn crit(label: &str, ok: bool, detail: impl Into<String>) -> Criterion {
    Criterion {
        label: label.to_owned(),
        ok,
        detail: detail.into(),
    }
}

/// The four steps of RDMA-device readiness, shared by both protocols: a device
/// must exist, expose an ACTIVE port, map to a netdev, and that netdev must
/// carry a usable IP. Pinpoints which link of the chain is broken.
///
/// `capable_disabled` names NICs that are RoCE-capable but have RoCE switched
/// off (no `/sys/class/infiniband` device); when there is no RDMA device at
/// all, that's the actionable explanation, pointing the user at Settings.
fn rdma_device_criteria(rdma: &[RdmaDev], capable_disabled: &[String]) -> Vec<Criterion> {
    let active: Vec<String> = rdma
        .iter()
        .filter(|d| d.active)
        .map(|d| d.name.clone())
        .collect();
    let netdevs: Vec<String> = rdma
        .iter()
        .filter_map(|d| d.netdev.as_ref().map(|nd| format!("{}→{nd}", d.name)))
        .collect();
    let addrs: Vec<String> = rdma
        .iter()
        .flat_map(|d| d.addrs.iter().map(|a| a.to_string()))
        .collect();
    vec![
        crit(
            "RDMA device present",
            !rdma.is_empty(),
            if rdma.is_empty() {
                if capable_disabled.is_empty() {
                    "none under /sys/class/infiniband".to_owned()
                } else {
                    format!(
                        "none under /sys/class/infiniband — but {} is RoCE-capable with RoCE disabled; enable it in Settings",
                        capable_disabled.join(", ")
                    )
                }
            } else {
                rdma.iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ),
        crit(
            "An RDMA port is ACTIVE",
            !active.is_empty(),
            if active.is_empty() {
                "all ports down".to_owned()
            } else {
                active.join(", ")
            },
        ),
        crit(
            "Device bound to a netdev",
            !netdevs.is_empty(),
            if netdevs.is_empty() {
                "no backing netdev".to_owned()
            } else {
                netdevs.join(", ")
            },
        ),
        crit(
            "Backing netdev has a usable IP",
            !addrs.is_empty(),
            if addrs.is_empty() {
                "no non-loopback IP on any RDMA netdev".to_owned()
            } else {
                addrs.join(", ")
            },
        ),
    ]
}

/// Ordered RDMA-readiness checklist for an NVMe-oF export, decomposing the same
/// state `nvme_dot` consults into per-condition pass/fail rows.
pub fn nvme_diagnostics(
    export: &NvmeExport,
    actual: &ActualNvmet,
    rdma: &[RdmaDev],
    capable_disabled: &[String],
) -> Vec<Criterion> {
    let nqn = export.nqn();
    let subsys = actual.subsystems.iter().find(|s| s.nqn == nqn.as_str());
    let ns = subsys.and_then(|s| s.namespaces.iter().find(|ns| ns.nsid == 1));
    let rdma_ports: Vec<&Port> = actual
        .ports
        .iter()
        .filter(|p| p.trtype == "rdma" && p.subsystems.iter().any(|s| s == nqn.as_str()))
        .collect();
    let listen = rdma_ports.first();

    let mut crits = vec![
        crit(
            "RDMA requested for this export",
            export.want_rdma,
            if export.want_rdma {
                "transport flag set"
            } else {
                "export does not request RDMA"
            },
        ),
        crit(
            "Subsystem configured in nvmet",
            subsys.is_some(),
            match subsys {
                Some(_) => nqn.to_string(),
                None => format!("{nqn} not present (reconcile pending?)"),
            },
        ),
        crit(
            "Namespace enabled on the right device",
            ns.is_some_and(|n| n.enabled && n.device_path == export.device_path),
            match ns {
                None => "namespace 1 missing".to_owned(),
                Some(n) if n.device_path != export.device_path => {
                    format!("wrong device {:?}", n.device_path)
                }
                Some(n) if !n.enabled => "namespace disabled".to_owned(),
                Some(_) => export.device_path.clone(),
            },
        ),
        crit(
            "Linked to an RDMA port",
            !rdma_ports.is_empty(),
            match listen {
                Some(p) => format!("{}:{}", p.traddr, p.trsvcid),
                None => "subsystem not linked to any rdma-trtype port".to_owned(),
            },
        ),
    ];
    crits.extend(rdma_device_criteria(rdma, capable_disabled));
    crits.push({
        let (ok, detail) = match listen {
            Some(p) => {
                let served = addr_served_by_rdma(&p.traddr, rdma);
                let detail = if served {
                    format!("RDMA backs {}", p.traddr)
                } else {
                    format!("no RDMA device backs {}", p.traddr)
                };
                (served, detail)
            }
            None => (false, "no RDMA listen address".to_owned()),
        };
        crit("Listen address served by RDMA", ok, detail)
    });
    crits
}

/// Ordered RDMA-readiness checklist for an iSCSI export (iSER), mirroring
/// `iscsi_dot`.
pub fn iscsi_diagnostics(
    export: &IscsiExport,
    actual: &ActualLio,
    rdma: &[RdmaDev],
    capable_disabled: &[String],
) -> Vec<Criterion> {
    let iqn = export.iqn();
    let backstore = actual.backstores.iter().find(|b| b.name == export.name);
    let target = actual.targets.iter().find(|t| t.iqn == iqn.as_str());
    let iser_portals: Vec<&Portal> = target
        .map(|t| t.portals.iter().filter(|p| p.iser).collect())
        .unwrap_or_default();
    let portal = iser_portals.first();
    let lun_mapped = target.is_some_and(|t| t.luns.iter().any(|l| l == &export.name));

    let mut crits = vec![
        crit(
            "RDMA (iSER) requested for this export",
            export.want_rdma,
            if export.want_rdma {
                "transport flag set"
            } else {
                "export does not request RDMA"
            },
        ),
        crit(
            "Backstore configured on the right device",
            backstore.is_some_and(|b| b.enabled && b.udev_path == export.device_path),
            match backstore {
                None => "backstore not present (reconcile pending?)".to_owned(),
                Some(b) if b.udev_path != export.device_path => {
                    format!("wrong device {:?}", b.udev_path)
                }
                Some(b) if !b.enabled => "backstore disabled".to_owned(),
                Some(_) => export.device_path.clone(),
            },
        ),
        crit(
            "Target portal group enabled",
            target.is_some_and(|t| t.enabled),
            match target {
                None => "iSCSI target missing".to_owned(),
                Some(t) if !t.enabled => "TPG disabled".to_owned(),
                Some(_) => iqn.to_string(),
            },
        ),
        crit(
            "LUN mapped",
            lun_mapped,
            if lun_mapped {
                format!("lun → {}", export.name)
            } else {
                "backstore not mapped as a LUN".to_owned()
            },
        ),
        crit(
            "iSER portal exists",
            !iser_portals.is_empty(),
            match portal {
                Some(p) => p.addr_port.clone(),
                None => "no iSER-enabled portal".to_owned(),
            },
        ),
    ];
    crits.extend(rdma_device_criteria(rdma, capable_disabled));
    crits.push({
        let (ok, detail) = match portal {
            Some(p) => {
                let served = addr_served_by_rdma(p.addr(), rdma);
                let detail = if served {
                    format!("RDMA backs {}", p.addr())
                } else {
                    format!("no RDMA device backs {}", p.addr())
                };
                (served, detail)
            }
            None => (false, "no iSER portal address".to_owned()),
        };
        crit("Portal address served by RDMA", ok, detail)
    });
    crits
}

/// Ordered RDMA-readiness checklist for an NFS export, decomposing the same
/// state `nfs_dot` consults into per-condition pass/fail rows.
pub fn nfs_diagnostics(
    export: &NfsExport,
    actual: &ActualNfs,
    rdma: &[RdmaDev],
    capable_disabled: &[String],
    listen: IpAddr,
) -> Vec<Criterion> {
    let exported = actual.exported(&export.path);
    let mut crits = vec![crit(
        "Path exported by nfsd",
        exported,
        if exported {
            export.path.clone()
        } else {
            "not in the export table (reconcile pending?)".to_owned()
        },
    )];
    crits.extend(rdma_device_criteria(rdma, capable_disabled));
    crits.push(crit(
        "nfsd RDMA listener active",
        actual.rdma_port.is_some(),
        match actual.rdma_port {
            Some(p) => format!("rdma {p} in /proc/fs/nfsd/portlist"),
            None => "no rdma line in portlist — serving TCP only".to_owned(),
        },
    ));
    crits.push({
        let served = addr_served_by_rdma(&listen.to_string(), rdma);
        crit(
            "Listen address served by RDMA",
            served,
            if served {
                format!("RDMA backs {listen}")
            } else {
                format!("no RDMA device backs {listen}")
            },
        )
    });
    crits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actual::nvmet::{Namespace, Port, Subsys};
    use rstest::rstest;
    use std::net::IpAddr;

    const NQN: &str = "nqn.2026-06.io.greendot:vm1";
    const DEV: &str = "/dev/zvol/tank/vm1";

    fn export(want_rdma: bool, want_tcp: bool, last_error: Option<&str>) -> NvmeExport {
        NvmeExport {
            id: 1,
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

    fn iscsi_export(want_rdma: bool, want_tcp: bool, last_error: Option<&str>) -> IscsiExport {
        IscsiExport {
            id: 1,
            name: "vm1".into(),
            device_path: DEV.into(),
            enabled: true,
            want_rdma,
            want_tcp,
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
            netdev: Some("eth0".into()),
            active: true,
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
        #[case] export: NvmeExport,
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

    use crate::actual::lio::{ActualLio, Backstore, Portal, Target};

    const IQN: &str = "iqn.2026-06.io.greendot:vm1";

    fn lio(
        backstore_dev: Option<&str>,
        tpg_enabled: bool,
        lun_mapped: bool,
        portals: Vec<Portal>,
    ) -> ActualLio {
        ActualLio {
            backstores: backstore_dev
                .map(|dev| {
                    vec![Backstore {
                        name: "vm1".into(),
                        udev_path: dev.into(),
                        enabled: true,
                    }]
                })
                .unwrap_or_default(),
            targets: vec![Target {
                iqn: IQN.into(),
                enabled: tpg_enabled,
                demo_mode: false,
                luns: if lun_mapped {
                    vec!["vm1".into()]
                } else {
                    vec![]
                },
                portals,
                acls: vec![],
            }],
        }
    }

    fn portal(addr_port: &str, iser: bool) -> Portal {
        Portal {
            addr_port: addr_port.into(),
            iser,
        }
    }

    #[rstest]
    #[case::green_iser(
        iscsi_export(true, true, None),
        lio(Some(DEV), true, true, vec![portal("10.0.0.5:3260", true)]),
        vec![rdma_dev("10.0.0.5")],
        DotState::Green, "iser"
    )]
    #[case::yellow_plain_tcp(
        iscsi_export(false, true, None),
        lio(Some(DEV), true, true, vec![portal("10.0.0.5:3260", false)]),
        vec![],
        DotState::Yellow, "not requested"
    )]
    #[case::yellow_iser_unbacked(
        iscsi_export(true, true, None),
        lio(Some(DEV), true, true, vec![portal("10.0.0.5:3260", true), portal("10.0.0.5:3261", false)]),
        vec![],
        DotState::Yellow, "no RDMA device"
    )]
    #[case::red_no_backstore(
        iscsi_export(true, true, None),
        lio(None, true, true, vec![portal("10.0.0.5:3260", true)]),
        vec![rdma_dev("10.0.0.5")],
        DotState::Red, "backstore"
    )]
    #[case::red_tpg_disabled(
        iscsi_export(true, true, None),
        lio(Some(DEV), false, true, vec![portal("10.0.0.5:3260", true)]),
        vec![rdma_dev("10.0.0.5")],
        DotState::Red, "disabled"
    )]
    #[case::red_lun_unmapped(
        iscsi_export(true, true, None),
        lio(Some(DEV), true, false, vec![portal("10.0.0.5:3260", true)]),
        vec![rdma_dev("10.0.0.5")],
        DotState::Red, "LUN"
    )]
    #[case::red_no_portals(
        iscsi_export(true, true, None),
        lio(Some(DEV), true, true, vec![]),
        vec![rdma_dev("10.0.0.5")],
        DotState::Red, "portal"
    )]
    fn iscsi_dot_truth_table(
        #[case] export: IscsiExport,
        #[case] actual: ActualLio,
        #[case] rdma: Vec<RdmaDev>,
        #[case] want_state: DotState,
        #[case] reason_contains: &str,
    ) {
        let dot = iscsi_dot(&export, &actual, &rdma);
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

    // External dots report only the observed transport — no desired state, so the
    // nqn/target need not be greendot's; the helpers match purely on identity.
    #[rstest]
    #[case::green_rdma(
        vec![port(1, "rdma", "10.0.0.5", true), port(2, "tcp", "10.0.0.5", true)],
        vec![rdma_dev("10.0.0.5")], DotState::Green, "rdma"
    )]
    #[case::yellow_tcp_only(vec![port(2, "tcp", "10.0.0.5", true)], vec![], DotState::Yellow, "tcp only")]
    #[case::yellow_rdma_unbacked(
        vec![port(1, "rdma", "10.0.0.5", true)], vec![], DotState::Yellow, "no RDMA device"
    )]
    #[case::red_no_ports(vec![], vec![], DotState::Red, "no port")]
    fn external_nvme_dot_truth_table(
        #[case] ports: Vec<Port>,
        #[case] rdma: Vec<RdmaDev>,
        #[case] want_state: DotState,
        #[case] reason_contains: &str,
    ) {
        let actual = ActualNvmet {
            subsystems: vec![],
            ports,
        };
        let dot = external_nvme_dot(NQN, &actual, &rdma);
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

    fn ext_target(portals: Vec<Portal>) -> Target {
        Target {
            iqn: "iqn.2000-01.com.foreign:lun1".into(),
            enabled: true,
            demo_mode: false,
            luns: vec![],
            portals,
            acls: vec![],
        }
    }

    #[rstest]
    #[case::green_iser(vec![portal("10.0.0.5:3260", true)], vec![rdma_dev("10.0.0.5")], DotState::Green, "iser")]
    #[case::yellow_plain_tcp(vec![portal("10.0.0.5:3260", false)], vec![], DotState::Yellow, "plain")]
    #[case::yellow_iser_unbacked(vec![portal("10.0.0.5:3260", true)], vec![], DotState::Yellow, "no RDMA device")]
    #[case::red_no_portals(vec![], vec![], DotState::Red, "portal")]
    fn external_iscsi_dot_truth_table(
        #[case] portals: Vec<Portal>,
        #[case] rdma: Vec<RdmaDev>,
        #[case] want_state: DotState,
        #[case] reason_contains: &str,
    ) {
        let dot = external_iscsi_dot(&ext_target(portals), &rdma);
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

    fn find<'a>(crits: &'a [Criterion], label: &str) -> &'a Criterion {
        crits
            .iter()
            .find(|c| c.label.contains(label))
            .unwrap_or_else(|| panic!("no criterion mentioning {label:?} in {crits:#?}"))
    }

    #[test]
    fn nvme_diagnostics_pinpoints_the_broken_link() {
        let dev = vec![rdma_dev("10.0.0.5")];
        let good = ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "10.0.0.5", true)],
        };
        // Healthy: every criterion passes and the verdict names the address.
        let crits = nvme_diagnostics(&export(true, false, None), &good, &dev, &[]);
        assert!(crits.iter().all(|c| c.ok), "{crits:#?}");
        assert!(
            find(&crits, "Listen address served")
                .detail
                .contains("10.0.0.5")
        );

        // Each fault flips exactly the criterion it owns; upstream rows stay green.
        assert!(
            !find(
                &nvme_diagnostics(&export(false, true, None), &good, &dev, &[]),
                "RDMA requested"
            )
            .ok
        );
        let no_subsys = nvme_diagnostics(
            &export(true, false, None),
            &ActualNvmet::default(),
            &dev,
            &[],
        );
        assert!(!find(&no_subsys, "Subsystem configured").ok);
        let no_dev = nvme_diagnostics(&export(true, false, None), &good, &[], &[]);
        assert!(find(&no_dev, "Subsystem configured").ok);
        assert!(!find(&no_dev, "RDMA device present").ok);
        assert!(!find(&no_dev, "Listen address served").ok);

        // No RDMA device but a RoCE-capable-disabled NIC: the verdict names it
        // and points at Settings instead of a bare "none".
        let disabled = nvme_diagnostics(&export(true, false, None), &good, &[], &["ens16".into()]);
        let present = find(&disabled, "RDMA device present");
        assert!(!present.ok);
        assert!(
            present.detail.contains("ens16") && present.detail.contains("Settings"),
            "{}",
            present.detail
        );

        // Wildcard listen is served whenever any device carries an address.
        let wild = ActualNvmet {
            subsystems: vec![subsys(true, DEV)],
            ports: vec![port(1, "rdma", "0.0.0.0", true)],
        };
        assert!(
            find(
                &nvme_diagnostics(&export(true, false, None), &wild, &dev, &[]),
                "Listen address served"
            )
            .ok
        );
    }

    #[test]
    fn iscsi_diagnostics_pinpoints_the_broken_link() {
        let dev = vec![rdma_dev("10.0.0.5")];
        let exp = iscsi_export(true, false, None);
        let good = lio(Some(DEV), true, true, vec![portal("10.0.0.5:3260", true)]);
        let crits = iscsi_diagnostics(&exp, &good, &dev, &[]);
        assert!(crits.iter().all(|c| c.ok), "{crits:#?}");

        // A plain (non-iSER) portal fails the iSER-portal row.
        let no_iser = lio(Some(DEV), true, true, vec![portal("10.0.0.5:3260", false)]);
        assert!(
            !find(
                &iscsi_diagnostics(&exp, &no_iser, &dev, &[]),
                "iSER portal exists"
            )
            .ok
        );

        // No RDMA device → device chain and the portal verdict fail together.
        let no_dev = iscsi_diagnostics(&exp, &good, &[], &[]);
        assert!(!find(&no_dev, "RDMA device present").ok);
        assert!(!find(&no_dev, "Portal address served").ok);
    }

    use crate::actual::nfs::{ActualNfs, NfsExportEntry};
    use crate::state::NfsExport;

    fn nfs_export(last_error: Option<&str>) -> NfsExport {
        NfsExport {
            id: 1,
            path: "/tank/share".into(),
            enabled: true,
            clients: vec![],
            last_error: last_error.map(Into::into),
        }
    }

    fn actual_nfs(exported: bool, rdma_port: Option<u16>) -> ActualNfs {
        let exports = if exported {
            vec![NfsExportEntry {
                path: "/tank/share".into(),
                clients: vec!["*".into()],
            }]
        } else {
            vec![]
        };
        ActualNfs {
            exports,
            rdma_port,
            managed: Default::default(),
        }
    }

    #[rstest]
    // Green: exported, RDMA listener active, a device backs the listen address.
    #[case::green(nfs_export(None), actual_nfs(true, Some(20049)), vec![rdma_dev("10.0.0.5")], DotState::Green, "nfsordma")]
    // Yellow: exported but only TCP (no RDMA listener).
    #[case::yellow_tcp(nfs_export(None), actual_nfs(true, None), vec![rdma_dev("10.0.0.5")], DotState::Yellow, "tcp only")]
    // Yellow: RDMA listener active but no RDMA device.
    #[case::yellow_no_dev(nfs_export(None), actual_nfs(true, Some(20049)), vec![], DotState::Yellow, "no RDMA device")]
    // Red: not in the export table yet.
    #[case::red_not_exported(nfs_export(None), actual_nfs(false, Some(20049)), vec![rdma_dev("10.0.0.5")], DotState::Red, "not exported")]
    // Red: a recorded reconcile error wins.
    #[case::red_error(nfs_export(Some("exportfs failed")), actual_nfs(true, Some(20049)), vec![rdma_dev("10.0.0.5")], DotState::Red, "exportfs failed")]
    fn nfs_dot_truth_table(
        #[case] export: NfsExport,
        #[case] actual: ActualNfs,
        #[case] rdma: Vec<RdmaDev>,
        #[case] want_state: DotState,
        #[case] reason_contains: &str,
    ) {
        // Wildcard listen: an RDMA device with any address backs it.
        let listen: IpAddr = "0.0.0.0".parse().unwrap();
        let dot = nfs_dot(&export, &actual, &rdma, listen);
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

    #[test]
    fn nfs_diagnostics_and_external_dot() {
        let listen: IpAddr = "0.0.0.0".parse().unwrap();
        let dev = vec![rdma_dev("10.0.0.5")];
        // Healthy: every criterion passes.
        let crits = nfs_diagnostics(
            &nfs_export(None),
            &actual_nfs(true, Some(20049)),
            &dev,
            &[],
            listen,
        );
        assert!(crits.iter().all(|c| c.ok), "{crits:#?}");
        // TCP-only flips exactly the listener row.
        let tcp = nfs_diagnostics(
            &nfs_export(None),
            &actual_nfs(true, None),
            &dev,
            &[],
            listen,
        );
        assert!(!find(&tcp, "RDMA listener active").ok);
        assert!(find(&tcp, "Path exported").ok);
        // External dot reports the observed transport without desired state.
        assert_eq!(
            external_nfs_dot(&actual_nfs(true, Some(20049)), &dev, listen).state,
            DotState::Green
        );
        assert_eq!(
            external_nfs_dot(&actual_nfs(true, None), &dev, listen).state,
            DotState::Yellow
        );
    }
}
