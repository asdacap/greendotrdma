//! Desired state (SQLite) → actual state (configfs) reconciliation.
//!
//! `plan()` is a pure function emitting helper requests; every helper op is
//! idempotent, so the plan can always be replayed. Subsystems we manage are
//! recognized by [`OUR_NQN_PREFIX`]; anything else in configfs is left alone.

use crate::actual::lio::ActualLio;
use crate::actual::nvmet::ActualNvmet;
use crate::state::{Export, ExportKind, OUR_IQN_PREFIX, OUR_NQN_PREFIX};
use greendot_proto::{BackstoreName, DevicePath, Iqn, KernelModule, Nqn, Request, Transport};
use std::net::IpAddr;

/// Fixed nvmet port ids, one per transport.
pub const PORT_RDMA: u16 = 1;
pub const PORT_TCP: u16 = 2;
pub const PORT_LOOP: u16 = 3;

pub struct PortConfig {
    pub listen_addr: IpAddr,
    pub trsvcid: u16,
}

/// (port id, transport, kernel module) for every transport an export can want.
fn wanted_transports(e: &Export) -> Vec<(u16, Transport, KernelModule)> {
    [
        (
            e.want_rdma,
            PORT_RDMA,
            Transport::Rdma,
            KernelModule::NvmetRdma,
        ),
        (e.want_tcp, PORT_TCP, Transport::Tcp, KernelModule::NvmetTcp),
        (
            e.want_loop,
            PORT_LOOP,
            Transport::Loop,
            KernelModule::NvmetLoop,
        ),
    ]
    .into_iter()
    .filter(|(want, ..)| *want)
    .map(|(_, id, t, m)| (id, t, m))
    .collect()
}

pub fn plan(exports: &[Export], actual: &ActualNvmet, cfg: &PortConfig) -> Vec<Request> {
    let desired: Vec<&Export> = exports
        .iter()
        .filter(|e| e.kind == ExportKind::Nvme && e.enabled)
        .collect();
    let mut requests = Vec::new();

    // 1. Kernel modules and ports for the union of wanted transports.
    let mut transports: Vec<(u16, Transport, KernelModule)> = Vec::new();
    for e in &desired {
        for t in wanted_transports(e) {
            if !transports.contains(&t) {
                transports.push(t);
            }
        }
    }
    transports.sort_by_key(|(id, ..)| *id);
    if !transports.is_empty() {
        requests.push(Request::EnsureModules {
            modules: transports.iter().map(|(.., m)| *m).collect(),
        });
    }
    for (id, trtype, _) in &transports {
        let existing = actual.ports.iter().find(|p| p.id == *id);
        let matches = existing.is_some_and(|p| {
            p.trtype == trtype.as_str()
                && (*trtype == Transport::Loop
                    || (p.traddr == cfg.listen_addr.to_string()
                        && p.trsvcid == cfg.trsvcid.to_string()))
        });
        if matches {
            continue;
        }
        if existing.is_some() {
            requests.push(Request::NvmetPortDelete { id: *id });
        }
        requests.push(Request::NvmetPortCreate {
            id: *id,
            trtype: *trtype,
            traddr: cfg.listen_addr,
            trsvcid: cfg.trsvcid,
        });
    }

    // 2. Per-export subsystem state (idempotent replays) and link/host diffs.
    for e in &desired {
        let nqn = e.nqn();
        let Ok(device_path) = DevicePath::new(&e.device_path) else {
            tracing::error!(
                export = e.name,
                device = e.device_path,
                "invalid device path in store"
            );
            continue;
        };
        requests.push(Request::NvmetSubsysCreate {
            nqn: nqn.clone(),
            allow_any_host: e.allow_any_host,
        });
        requests.push(Request::NvmetNamespaceSet {
            nqn: nqn.clone(),
            nsid: 1,
            device_path,
            enable: true,
        });

        let subsys = actual.subsystems.iter().find(|s| s.nqn == nqn.as_str());
        let current_hosts: &[String] = subsys
            .map(|s| s.allowed_hosts.as_slice())
            .unwrap_or_default();
        if !e.allow_any_host {
            for host in &e.initiators {
                if !current_hosts.contains(host)
                    && let Ok(host_nqn) = Nqn::new(host.clone())
                {
                    requests.push(Request::NvmetHostAllow {
                        nqn: nqn.clone(),
                        host_nqn,
                    });
                }
            }
        }
        for host in current_hosts {
            if (e.allow_any_host || !e.initiators.contains(host))
                && let Ok(host_nqn) = Nqn::new(host.clone())
            {
                requests.push(Request::NvmetHostRemove {
                    nqn: nqn.clone(),
                    host_nqn,
                });
            }
        }

        let wanted_ports: Vec<u16> = wanted_transports(e).iter().map(|(id, ..)| *id).collect();
        for port in &actual.ports {
            if port.subsystems.iter().any(|s| s == nqn.as_str()) && !wanted_ports.contains(&port.id)
            {
                requests.push(Request::NvmetPortUnlink {
                    port: port.id,
                    nqn: nqn.clone(),
                });
            }
        }
        for id in wanted_ports {
            let already = actual
                .ports
                .iter()
                .any(|p| p.id == id && p.subsystems.iter().any(|s| s == nqn.as_str()))
                // a port being (re)created above can't have stale links
                && !requests.iter().any(|r| matches!(r, Request::NvmetPortCreate { id: pid, .. } if *pid == id));
            if !already {
                requests.push(Request::NvmetPortLink {
                    port: id,
                    nqn: nqn.clone(),
                });
            }
        }
    }

    // 3. Tear down subsystems under our prefix that no enabled export wants.
    for subsys in &actual.subsystems {
        if !subsys.nqn.starts_with(OUR_NQN_PREFIX)
            || desired.iter().any(|e| e.nqn().as_str() == subsys.nqn)
        {
            continue;
        }
        let Ok(nqn) = Nqn::new(subsys.nqn.clone()) else {
            continue;
        };
        for port in &actual.ports {
            if port.subsystems.iter().any(|s| s == &subsys.nqn) {
                requests.push(Request::NvmetPortUnlink {
                    port: port.id,
                    nqn: nqn.clone(),
                });
            }
        }
        requests.push(Request::NvmetSubsysDelete { nqn });
    }

    requests
}

/// iSCSI desired state → helper requests. Same contract as `plan()`.
pub fn plan_iscsi(exports: &[Export], actual: &ActualLio, cfg: &PortConfig) -> Vec<Request> {
    let desired: Vec<&Export> = exports
        .iter()
        .filter(|e| e.kind == ExportKind::Iscsi && e.enabled)
        .collect();
    let mut requests = Vec::new();

    if !desired.is_empty() {
        let mut modules = vec![KernelModule::Iscsi];
        if desired.iter().any(|e| e.want_rdma) {
            modules.push(KernelModule::Iser);
        }
        requests.push(Request::EnsureModules { modules });
    }

    for e in &desired {
        let iqn = e.iqn();
        let (Ok(device_path), Ok(backstore)) =
            (DevicePath::new(&e.device_path), BackstoreName::new(&e.name))
        else {
            tracing::error!(
                export = e.name,
                "invalid device path or backstore name in store"
            );
            continue;
        };
        requests.push(Request::LioBackstoreCreate {
            name: backstore.clone(),
            device_path,
        });
        requests.push(Request::LioTargetCreate { iqn: iqn.clone() });
        requests.push(Request::LioLunMap {
            iqn: iqn.clone(),
            lun: 0,
            backstore,
        });

        // Desired portals: iSER on 3260 when RDMA is wanted; plain TCP on
        // 3260, or on 3261 when it must coexist with the iSER portal.
        let mut want: Vec<(u16, bool)> = Vec::new();
        if e.want_rdma {
            want.push((3260, true));
        }
        if e.want_tcp {
            want.push((if e.want_rdma { 3261 } else { 3260 }, false));
        }
        let target = actual.targets.iter().find(|t| t.iqn == iqn.as_str());
        let current = target.map(|t| t.portals.as_slice()).unwrap_or_default();
        let addr = cfg.listen_addr;
        let dirname = |port: u16| match addr {
            IpAddr::V4(v4) => format!("{v4}:{port}"),
            IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        };
        for portal in current {
            let keep = want
                .iter()
                .any(|(port, iser)| portal.addr_port == dirname(*port) && portal.iser == *iser);
            if !keep {
                // addr may have changed; parse what we can, skip junk
                if let (addr_str, Some(port)) = (
                    portal.addr().to_owned(),
                    portal
                        .addr_port
                        .rsplit_once(':')
                        .and_then(|(_, p)| p.parse::<u16>().ok()),
                ) && let Ok(addr) = addr_str.parse()
                {
                    requests.push(Request::LioPortalDelete {
                        iqn: iqn.clone(),
                        addr,
                        port,
                    });
                }
            }
        }
        for (port, iser) in &want {
            if !current
                .iter()
                .any(|p| p.addr_port == dirname(*port) && p.iser == *iser)
            {
                requests.push(Request::LioPortalSet {
                    iqn: iqn.clone(),
                    addr,
                    port: *port,
                    iser: *iser,
                });
            }
        }

        let current_acls: &[String] = target.map(|t| t.acls.as_slice()).unwrap_or_default();
        if !e.allow_any_host {
            for initiator in &e.initiators {
                if !current_acls.contains(initiator)
                    && let Ok(initiator) = Iqn::new(initiator.clone())
                {
                    requests.push(Request::LioAclAdd {
                        iqn: iqn.clone(),
                        initiator,
                    });
                }
            }
        }
        for acl in current_acls {
            if (e.allow_any_host || !e.initiators.contains(acl))
                && let Ok(initiator) = Iqn::new(acl.clone())
            {
                requests.push(Request::LioAclRemove {
                    iqn: iqn.clone(),
                    initiator,
                });
            }
        }

        requests.push(Request::LioTpgSet {
            iqn,
            enabled: true,
            demo_mode: e.allow_any_host,
            auth: None,
        });
    }

    // Tear down our targets (and their same-named backstores) that no
    // enabled export wants. A stray backstore without a target lingers
    // until an export of the same name is recreated — acceptable.
    for target in &actual.targets {
        if !target.iqn.starts_with(OUR_IQN_PREFIX)
            || desired.iter().any(|e| e.iqn().as_str() == target.iqn)
        {
            continue;
        }
        let Ok(iqn) = Iqn::new(target.iqn.clone()) else {
            continue;
        };
        requests.push(Request::LioTargetDelete { iqn });
        if let Some(name) = target.iqn.strip_prefix(OUR_IQN_PREFIX)
            && let Ok(backstore) = BackstoreName::new(name)
            && actual.backstores.iter().any(|b| b.name == name)
        {
            requests.push(Request::LioBackstoreDelete { name: backstore });
        }
    }

    requests
}

/// Which export a failed request should be blamed on (its NQN/IQN); None
/// means the failure is global (modules, ports).
fn request_key(req: &Request) -> Option<String> {
    let nqn = match req {
        Request::NvmetSubsysCreate { nqn, .. }
        | Request::NvmetSubsysDelete { nqn }
        | Request::NvmetNamespaceSet { nqn, .. }
        | Request::NvmetNamespaceDelete { nqn, .. }
        | Request::NvmetPortLink { nqn, .. }
        | Request::NvmetPortUnlink { nqn, .. }
        | Request::NvmetHostAllow { nqn, .. }
        | Request::NvmetHostRemove { nqn, .. } => Some(nqn.as_str()),
        _ => None,
    };
    let iqn = match req {
        Request::LioTargetCreate { iqn }
        | Request::LioTargetDelete { iqn }
        | Request::LioLunMap { iqn, .. }
        | Request::LioPortalSet { iqn, .. }
        | Request::LioPortalDelete { iqn, .. }
        | Request::LioAclAdd { iqn, .. }
        | Request::LioAclRemove { iqn, .. }
        | Request::LioTpgSet { iqn, .. } => Some(iqn.as_str()),
        // Backstores are named after the export; blame via the IQN prefix.
        Request::LioBackstoreCreate { name, .. } | Request::LioBackstoreDelete { name } => {
            return Some(format!("{OUR_IQN_PREFIX}{name}"));
        }
        _ => None,
    };
    nqn.or(iqn).map(ToOwned::to_owned)
}

pub const RECONCILE_ERROR_KEY: &str = "reconcile_error";

/// Plans against current state and replays through the helper, recording
/// per-export errors in the store. Callers serialize via AppState's lock.
pub async fn run(
    db: &crate::state::Db,
    helper: &crate::helper_client::HelperClient,
    nvmet_root: &std::path::Path,
    lio_root: &std::path::Path,
    cfg: &PortConfig,
) -> anyhow::Result<()> {
    use std::collections::HashMap;

    let exports = db.list_exports()?;
    let mut requests = plan(&exports, &crate::actual::nvmet::read(nvmet_root), cfg);
    requests.extend(plan_iscsi(
        &exports,
        &crate::actual::lio::read(lio_root),
        cfg,
    ));

    let mut errors: HashMap<String, String> = HashMap::new();
    let mut global_error = None;
    for req in requests {
        let blame = request_key(&req);
        let failure = match helper.call(req).await {
            Ok(greendot_proto::Response::Err { message, .. }) => Some(message),
            Err(e) => Some(format!("helper unavailable: {e:#}")),
            Ok(_) => None,
        };
        if let Some(message) = failure {
            tracing::warn!(error = %message, "reconcile step failed");
            match blame {
                Some(nqn) => {
                    errors.entry(nqn).or_insert(message);
                }
                None => {
                    global_error.get_or_insert(message);
                }
            }
        }
    }
    for export in &exports {
        db.set_export_error(
            export.id,
            errors.get(&export.qualified_name()).map(String::as_str),
        )?;
    }
    db.set_setting(RECONCILE_ERROR_KEY, global_error.as_deref().unwrap_or(""))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actual::nvmet::{Namespace, Port, Subsys};
    use greendot_proto::{DevicePath, ExportName};

    const NQN: &str = "nqn.2026-06.io.greendot:vm1";
    const DEV: &str = "/dev/zvol/tank/vm1";
    const HOST: &str = "nqn.2014-08.org.nvmexpress:host1";

    fn cfg() -> PortConfig {
        PortConfig {
            listen_addr: "10.0.0.5".parse().unwrap(),
            trsvcid: 4420,
        }
    }

    fn export() -> Export {
        Export {
            id: 1,
            kind: ExportKind::Nvme,
            name: "vm1".into(),
            device_path: DEV.into(),
            enabled: true,
            want_rdma: true,
            want_tcp: true,
            want_loop: false,
            allow_any_host: false,
            initiators: vec![HOST.into()],
            last_error: None,
        }
    }

    fn nqn(s: &str) -> Nqn {
        Nqn::new(s).unwrap()
    }

    fn rdma_port(linked: bool) -> Port {
        Port {
            id: PORT_RDMA,
            trtype: "rdma".into(),
            traddr: "10.0.0.5".into(),
            trsvcid: "4420".into(),
            subsystems: if linked { vec![NQN.into()] } else { vec![] },
        }
    }

    fn tcp_port(linked: bool) -> Port {
        Port {
            id: PORT_TCP,
            trtype: "tcp".into(),
            traddr: "10.0.0.5".into(),
            trsvcid: "4420".into(),
            subsystems: if linked { vec![NQN.into()] } else { vec![] },
        }
    }

    fn actual_subsys() -> Subsys {
        Subsys {
            nqn: NQN.into(),
            allow_any_host: false,
            allowed_hosts: vec![HOST.into()],
            namespaces: vec![Namespace {
                nsid: 1,
                device_path: DEV.into(),
                enabled: true,
            }],
        }
    }

    #[test]
    fn iscsi_fresh_creation_drift_and_teardown() {
        use crate::actual::lio::{ActualLio, Backstore, Portal, Target};
        let iqn_s = "iqn.2026-06.io.greendot:vm1";
        let iqn = |s: &str| Iqn::new(s).unwrap();
        let mut e = export();
        e.kind = ExportKind::Iscsi;
        e.initiators = vec!["iqn.1993-08.org.debian:01:abc".into()];
        let addr: IpAddr = "10.0.0.5".parse().unwrap();

        // Fresh: full creation, iSER on 3260, TCP coexisting on 3261.
        let requests = plan_iscsi(&[e.clone()], &ActualLio::default(), &cfg());
        assert_eq!(
            requests,
            vec![
                Request::EnsureModules {
                    modules: vec![KernelModule::Iscsi, KernelModule::Iser]
                },
                Request::LioBackstoreCreate {
                    name: BackstoreName::new("vm1").unwrap(),
                    device_path: DevicePath::new(DEV).unwrap(),
                },
                Request::LioTargetCreate { iqn: iqn(iqn_s) },
                Request::LioLunMap {
                    iqn: iqn(iqn_s),
                    lun: 0,
                    backstore: BackstoreName::new("vm1").unwrap()
                },
                Request::LioPortalSet {
                    iqn: iqn(iqn_s),
                    addr,
                    port: 3260,
                    iser: true
                },
                Request::LioPortalSet {
                    iqn: iqn(iqn_s),
                    addr,
                    port: 3261,
                    iser: false
                },
                Request::LioAclAdd {
                    iqn: iqn(iqn_s),
                    initiator: iqn("iqn.1993-08.org.debian:01:abc")
                },
                Request::LioTpgSet {
                    iqn: iqn(iqn_s),
                    enabled: true,
                    demo_mode: false,
                    auth: None
                },
            ]
        );

        // Converged except a stale portal and a stray target of ours.
        let actual = ActualLio {
            backstores: vec![Backstore {
                name: "vm1".into(),
                udev_path: DEV.into(),
                enabled: true,
            }],
            targets: vec![
                Target {
                    iqn: iqn_s.into(),
                    enabled: true,
                    demo_mode: false,
                    luns: vec!["vm1".into()],
                    portals: vec![
                        Portal {
                            addr_port: "10.0.0.5:3260".into(),
                            iser: true,
                        },
                        Portal {
                            addr_port: "10.0.0.5:3261".into(),
                            iser: false,
                        },
                        Portal {
                            addr_port: "192.168.9.9:3260".into(),
                            iser: false,
                        }, // stale
                    ],
                    acls: vec!["iqn.1993-08.org.debian:01:abc".into()],
                },
                Target {
                    iqn: "iqn.2026-06.io.greendot:gone".into(),
                    enabled: true,
                    demo_mode: true,
                    luns: vec![],
                    portals: vec![],
                    acls: vec![],
                },
            ],
        };
        let requests = plan_iscsi(&[e], &actual, &cfg());
        assert_eq!(
            requests,
            vec![
                Request::EnsureModules {
                    modules: vec![KernelModule::Iscsi, KernelModule::Iser]
                },
                Request::LioBackstoreCreate {
                    name: BackstoreName::new("vm1").unwrap(),
                    device_path: DevicePath::new(DEV).unwrap(),
                },
                Request::LioTargetCreate { iqn: iqn(iqn_s) },
                Request::LioLunMap {
                    iqn: iqn(iqn_s),
                    lun: 0,
                    backstore: BackstoreName::new("vm1").unwrap()
                },
                Request::LioPortalDelete {
                    iqn: iqn(iqn_s),
                    addr: "192.168.9.9".parse().unwrap(),
                    port: 3260
                },
                Request::LioTpgSet {
                    iqn: iqn(iqn_s),
                    enabled: true,
                    demo_mode: false,
                    auth: None
                },
                Request::LioTargetDelete {
                    iqn: iqn("iqn.2026-06.io.greendot:gone")
                },
            ]
        );
    }

    #[test]
    fn fresh_system_gets_full_creation_sequence() {
        let _ = ExportName::new("vm1").unwrap(); // name validity is what makes the NQN derivable
        let requests = plan(&[export()], &ActualNvmet::default(), &cfg());
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            requests,
            vec![
                Request::EnsureModules {
                    modules: vec![KernelModule::NvmetRdma, KernelModule::NvmetTcp]
                },
                Request::NvmetPortCreate {
                    id: PORT_RDMA,
                    trtype: Transport::Rdma,
                    traddr: addr,
                    trsvcid: 4420
                },
                Request::NvmetPortCreate {
                    id: PORT_TCP,
                    trtype: Transport::Tcp,
                    traddr: addr,
                    trsvcid: 4420
                },
                Request::NvmetSubsysCreate {
                    nqn: nqn(NQN),
                    allow_any_host: false
                },
                Request::NvmetNamespaceSet {
                    nqn: nqn(NQN),
                    nsid: 1,
                    device_path: DevicePath::new(DEV).unwrap(),
                    enable: true,
                },
                Request::NvmetHostAllow {
                    nqn: nqn(NQN),
                    host_nqn: nqn(HOST)
                },
                Request::NvmetPortLink {
                    port: PORT_RDMA,
                    nqn: nqn(NQN)
                },
                Request::NvmetPortLink {
                    port: PORT_TCP,
                    nqn: nqn(NQN)
                },
            ]
        );
    }

    #[test]
    fn converged_system_only_replays_idempotent_subsys_state() {
        let actual = ActualNvmet {
            subsystems: vec![actual_subsys()],
            ports: vec![rdma_port(true), tcp_port(true)],
        };
        let requests = plan(&[export()], &actual, &cfg());
        assert_eq!(
            requests,
            vec![
                Request::EnsureModules {
                    modules: vec![KernelModule::NvmetRdma, KernelModule::NvmetTcp]
                },
                Request::NvmetSubsysCreate {
                    nqn: nqn(NQN),
                    allow_any_host: false
                },
                Request::NvmetNamespaceSet {
                    nqn: nqn(NQN),
                    nsid: 1,
                    device_path: DevicePath::new(DEV).unwrap(),
                    enable: true,
                },
            ]
        );
    }

    #[test]
    fn drift_is_corrected_and_foreign_subsystems_are_untouched() {
        // Host list drift, an unwanted loop link, and a stray subsystem of
        // ours; a foreign subsystem must survive.
        let mut e = export();
        e.want_tcp = false;
        let stray = "nqn.2026-06.io.greendot:deleted";
        let foreign = "nqn.2000-01.com.example:manual";
        let actual = ActualNvmet {
            subsystems: vec![
                Subsys {
                    allowed_hosts: vec!["nqn.2014-08.org.nvmexpress:oldhost".into()],
                    ..actual_subsys()
                },
                Subsys {
                    nqn: stray.into(),
                    allow_any_host: true,
                    allowed_hosts: vec![],
                    namespaces: vec![],
                },
                Subsys {
                    nqn: foreign.into(),
                    allow_any_host: true,
                    allowed_hosts: vec![],
                    namespaces: vec![],
                },
            ],
            ports: vec![
                rdma_port(true),
                Port {
                    subsystems: vec![NQN.into(), stray.into(), foreign.into()],
                    ..tcp_port(false)
                },
            ],
        };
        let requests = plan(&[e], &actual, &cfg());
        assert_eq!(
            requests,
            vec![
                Request::EnsureModules {
                    modules: vec![KernelModule::NvmetRdma]
                },
                Request::NvmetSubsysCreate {
                    nqn: nqn(NQN),
                    allow_any_host: false
                },
                Request::NvmetNamespaceSet {
                    nqn: nqn(NQN),
                    nsid: 1,
                    device_path: DevicePath::new(DEV).unwrap(),
                    enable: true,
                },
                Request::NvmetHostAllow {
                    nqn: nqn(NQN),
                    host_nqn: nqn(HOST)
                },
                Request::NvmetHostRemove {
                    nqn: nqn(NQN),
                    host_nqn: nqn("nqn.2014-08.org.nvmexpress:oldhost"),
                },
                Request::NvmetPortUnlink {
                    port: PORT_TCP,
                    nqn: nqn(NQN)
                },
                Request::NvmetPortUnlink {
                    port: PORT_TCP,
                    nqn: nqn(stray)
                },
                Request::NvmetSubsysDelete { nqn: nqn(stray) },
            ]
        );
    }

    #[test]
    fn disabled_exports_and_port_attr_changes_are_torn_down_and_rebuilt() {
        let mut e = export();
        e.enabled = false;
        // Port 1 exists with a stale address; no enabled export wants RDMA
        // anymore, so only the teardown of the disabled export and no port
        // recreation for transports nobody wants.
        let actual = ActualNvmet {
            subsystems: vec![actual_subsys()],
            ports: vec![Port {
                traddr: "192.168.9.9".into(),
                ..rdma_port(true)
            }],
        };
        let requests = plan(&[e], &actual, &cfg());
        assert_eq!(
            requests,
            vec![
                Request::NvmetPortUnlink {
                    port: PORT_RDMA,
                    nqn: nqn(NQN)
                },
                Request::NvmetSubsysDelete { nqn: nqn(NQN) },
            ]
        );

        // With an enabled export wanting RDMA, the stale port is recreated.
        let actual = ActualNvmet {
            subsystems: vec![actual_subsys()],
            ports: vec![Port {
                traddr: "192.168.9.9".into(),
                subsystems: vec![],
                ..rdma_port(false)
            }],
        };
        let mut e = export();
        e.want_tcp = false;
        let requests = plan(&[e], &actual, &cfg());
        let addr: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            requests,
            vec![
                Request::EnsureModules {
                    modules: vec![KernelModule::NvmetRdma]
                },
                Request::NvmetPortDelete { id: PORT_RDMA },
                Request::NvmetPortCreate {
                    id: PORT_RDMA,
                    trtype: Transport::Rdma,
                    traddr: addr,
                    trsvcid: 4420
                },
                Request::NvmetSubsysCreate {
                    nqn: nqn(NQN),
                    allow_any_host: false
                },
                Request::NvmetNamespaceSet {
                    nqn: nqn(NQN),
                    nsid: 1,
                    device_path: DevicePath::new(DEV).unwrap(),
                    enable: true,
                },
                Request::NvmetPortLink {
                    port: PORT_RDMA,
                    nqn: nqn(NQN)
                },
            ]
        );
    }
}
