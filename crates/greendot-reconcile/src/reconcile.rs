//! Desired-state reconciliation: renders the full NVMe-oF/iSCSI/NFS desired
//! state from the export list, plus the `*_satisfied` drift predicates and the
//! per-area kernel-module lists.
//!
//! Everything here is a pure render/compare — the applies run inline in
//! greendotctl (the privileged caller: the daemon on `Request::Reconcile`, or
//! the root-only standalone `greendotctl reconcile`). Shared with greendot-web's
//! drift pre-check (`routes::block_export::reconcile_state`), so the web and
//! greendotctl render the same live input identically.

use crate::actual::lio::ActualLio;
use crate::actual::nfs::ActualNfs;
use crate::actual::nvmet::ActualNvmet;
use crate::state::{IscsiExport, NfsExport, NvmeExport, OUR_IQN_PREFIX, OUR_NQN_PREFIX};
use greendot_proto::{
    KernelModule, LioBackstoreSpec, LioDesired, LioLunSpec, LioPortalSpec, LioTargetSpec,
    NfsClient, NfsClientSpec, NfsDesired, NfsExportPath, NfsExportSpec, Nqn, NvmetDesired,
    NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, Transport,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// greendot's NFS `fsid`s are offset into a reserved high range so they don't
/// collide with foreign numeric `fsid=`s in `/etc/exports`.
const NFS_FSID_BASE: u32 = 0x6700_0000;

pub const RECONCILE_ERROR_KEY: &str = "reconcile_error";

/// Setting holding the id of the most recent reconcile task, so the export
/// banner and dots can link to it (`/tasks/{id}`). Empty when none has run.
pub const RECONCILE_TASK_KEY: &str = "reconcile_task_id";

const TRSVCID: u16 = 4420;

/// The IPs an export should listen on: its pinned interfaces resolved to their
/// current IPs, or `default` when it pins none (the unchanged behavior). A
/// selector that resolves to no current IP — link down, no DHCP lease yet, or an
/// unknown scheme — contributes nothing, so the export simply isn't served there
/// until an IP appears.
pub fn listen_addrs(
    interfaces: &[String],
    default: IpAddr,
    pci_addrs: &HashMap<String, Vec<IpAddr>>,
) -> Vec<IpAddr> {
    if interfaces.is_empty() {
        return vec![default];
    }
    let mut addrs: Vec<IpAddr> = interfaces
        .iter()
        .filter_map(|s| crate::state::parse_listen_iface(s))
        .filter_map(|pci| pci_addrs.get(&pci.to_string()))
        .flatten()
        .copied()
        .collect();
    addrs.sort();
    addrs.dedup();
    addrs
}

/// Renders the desired nvmet state from the enabled NVMe-oF exports. Each export
/// listens on its pinned interfaces' current IPs (resolved via `pci_addrs`), or
/// `default_listen` when it pins none.
pub fn render_nvmet(
    nvme: &[NvmeExport],
    default_listen: IpAddr,
    pci_addrs: &HashMap<String, Vec<IpAddr>>,
) -> NvmetDesired {
    let enabled = || {
        nvme.iter()
            .filter(|e| e.enabled && greendot_proto::DevicePath::new(&e.device_path).is_ok())
    };
    let subsystems: Vec<NvmetSubsysSpec> = enabled()
        .filter_map(|e| {
            Some(NvmetSubsysSpec {
                nqn: e.nqn(),
                allow_any_host: e.allow_any_host,
                allowed_hosts: e
                    .initiators
                    .iter()
                    .filter_map(|i| Nqn::new(i.clone()).ok())
                    .collect(),
                namespaces: vec![NvmetNsSpec {
                    nsid: 1,
                    device_path: greendot_proto::DevicePath::new(&e.device_path).ok()?,
                }],
            })
        })
        .collect();

    // A single nvmet port carries one (trtype, traddr) and links many subsystems,
    // so group exports' NQNs by the address each lands on. Loop has no address and
    // stays one group.
    let mut net: BTreeMap<(Transport, IpAddr), Vec<Nqn>> = BTreeMap::new();
    let mut loop_subs: Vec<Nqn> = Vec::new();
    for e in enabled() {
        let addrs = listen_addrs(&e.interfaces, default_listen, pci_addrs);
        for (want, trtype) in [(e.want_rdma, Transport::Rdma), (e.want_tcp, Transport::Tcp)] {
            if want {
                for a in &addrs {
                    net.entry((trtype, *a)).or_default().push(e.nqn());
                }
            }
        }
        if e.want_loop {
            loop_subs.push(e.nqn());
        }
    }

    // Deterministic port ids from the sorted groups: the web drift pre-check and
    // the CLI apply render the same live input independently, so the ids must
    // agree. The loop port (if any) comes last.
    let mut ports: Vec<NvmetPortSpec> = net
        .into_iter()
        .map(|((trtype, traddr), subsystems)| NvmetPortSpec {
            id: 0,
            trtype,
            traddr,
            trsvcid: TRSVCID,
            subsystems,
        })
        .collect();
    if !loop_subs.is_empty() {
        ports.push(NvmetPortSpec {
            id: 0,
            trtype: Transport::Loop,
            traddr: default_listen, // ignored for loop — no address is bound
            trsvcid: TRSVCID,
            subsystems: loop_subs,
        });
    }
    for (i, p) in ports.iter_mut().enumerate() {
        p.id = i as u16 + 1;
    }
    NvmetDesired { subsystems, ports }
}

/// Renders the desired LIO state from the enabled iSCSI exports. Each target's
/// portals listen on the export's pinned interfaces' current IPs (resolved via
/// `pci_addrs`), or `default_listen` when it pins none.
pub fn render_lio(
    iscsi: &[IscsiExport],
    default_listen: IpAddr,
    pci_addrs: &HashMap<String, Vec<IpAddr>>,
) -> LioDesired {
    let mut backstores = Vec::new();
    let mut targets = Vec::new();
    for e in iscsi.iter().filter(|e| e.enabled) {
        let (Ok(name), Ok(device_path)) = (
            greendot_proto::BackstoreName::new(&e.name),
            greendot_proto::DevicePath::new(&e.device_path),
        ) else {
            continue;
        };
        backstores.push(LioBackstoreSpec {
            name: name.clone(),
            device_path,
        });
        // Portals are per-target (not shared), so one iSER (3260) and/or TCP
        // (3261, else 3260) portal per resolved address.
        let mut portals = Vec::new();
        for addr in listen_addrs(&e.interfaces, default_listen, pci_addrs) {
            if e.want_rdma {
                portals.push(LioPortalSpec {
                    addr,
                    port: 3260,
                    iser: true,
                });
            }
            if e.want_tcp {
                portals.push(LioPortalSpec {
                    addr,
                    port: if e.want_rdma { 3261 } else { 3260 },
                    iser: false,
                });
            }
        }
        targets.push(LioTargetSpec {
            iqn: e.iqn(),
            enabled: true,
            demo_mode: e.allow_any_host,
            luns: vec![LioLunSpec {
                lun: 0,
                backstore: name,
            }],
            portals,
            acls: if e.allow_any_host {
                Vec::new()
            } else {
                e.initiators
                    .iter()
                    .filter_map(|i| greendot_proto::Iqn::new(i.clone()).ok())
                    .collect()
            },
        });
    }
    LioDesired {
        backstores,
        targets,
    }
}

/// Renders the desired NFS state from the enabled exports. Entries whose path
/// or every client fails validation are skipped (like `render_nvmet`).
pub fn render_nfs(nfs_exports: &[NfsExport], rdma_port: u16) -> NfsDesired {
    let exports = nfs_exports
        .iter()
        .filter(|e| e.enabled)
        .filter_map(|e| {
            let path = NfsExportPath::new(&e.path).ok()?;
            let clients: Vec<NfsClientSpec> = e
                .clients
                .iter()
                .filter_map(|c| {
                    Some(NfsClientSpec {
                        client: NfsClient::new(&c.client).ok()?,
                        rw: c.rw,
                    })
                })
                .collect();
            // An export with no valid client can't be served — drop it.
            (!clients.is_empty()).then_some(NfsExportSpec {
                path,
                fsid: NFS_FSID_BASE | (e.id as u32),
                clients,
            })
        })
        .collect();
    NfsDesired { exports, rdma_port }
}

/// Whether actual NFS state realizes the desired state. Scoped to greendot's
/// own exports (the managed file is the baseline, like the OUR_ prefix for
/// nvmet): what we last applied must equal what's desired (catches adds *and*
/// removes), each desired path must be live in the export table, and the RDMA
/// listener must be active whenever we export anything. Foreign exports never
/// force a re-apply.
pub fn nfs_satisfied(d: &NfsDesired, a: &ActualNfs) -> bool {
    let want: BTreeSet<(String, String, bool)> = d
        .exports
        .iter()
        .flat_map(|e| {
            e.clients
                .iter()
                .map(move |c| (e.path.to_string(), c.client.to_string(), c.rw))
        })
        .collect();
    want == a.managed
        && d.exports.iter().all(|e| a.exported(e.path.as_str()))
        && (d.exports.is_empty() || a.rdma_port.is_some())
}

/// The NFS-over-RDMA module to load when any NFS export is enabled.
pub fn nfs_modules(nfs_exports: &[NfsExport]) -> Vec<KernelModule> {
    if nfs_exports.iter().any(|e| e.enabled) {
        vec![KernelModule::Rpcrdma]
    } else {
        Vec::new()
    }
}

fn set<T: Ord, I: IntoIterator<Item = T>>(items: I) -> BTreeSet<T> {
    items.into_iter().collect()
}

/// Whether actual nvmet configfs already realizes the desired state (only our
/// prefix is considered; foreign subsystems are ignored).
pub fn nvmet_satisfied(d: &NvmetDesired, a: &ActualNvmet) -> bool {
    let want: BTreeSet<String> = set(d.subsystems.iter().map(|s| s.nqn.to_string()));
    let have: BTreeSet<String> = set(a
        .subsystems
        .iter()
        .filter(|s| s.nqn.starts_with(OUR_NQN_PREFIX))
        .map(|s| s.nqn.clone()));
    if want != have {
        return false;
    }
    for ds in &d.subsystems {
        let Some(as_) = a.subsystems.iter().find(|s| s.nqn == ds.nqn.as_str()) else {
            return false;
        };
        if as_.allow_any_host != ds.allow_any_host {
            return false;
        }
        if set(ds.allowed_hosts.iter().map(|h| h.to_string()))
            != set(as_.allowed_hosts.iter().cloned())
        {
            return false;
        }
        let (Some(an), Some(dn)) = (
            as_.namespaces.iter().find(|n| n.nsid == 1),
            ds.namespaces.iter().find(|n| n.nsid == 1),
        ) else {
            return false;
        };
        if !an.enabled || an.device_path != dn.device_path.as_str() {
            return false;
        }
    }
    // Ports: managed links per port id must match exactly.
    let ids: BTreeSet<u16> = d
        .ports
        .iter()
        .map(|p| p.id)
        .chain(a.ports.iter().map(|p| p.id))
        .collect();
    for id in ids {
        let dp = d.ports.iter().find(|p| p.id == id);
        let ap = a.ports.iter().find(|p| p.id == id);
        let want_links: BTreeSet<String> = dp
            .map(|p| set(p.subsystems.iter().map(|n| n.to_string())))
            .unwrap_or_default();
        let have_links: BTreeSet<String> = ap
            .map(|p| {
                set(p
                    .subsystems
                    .iter()
                    .filter(|n| n.starts_with(OUR_NQN_PREFIX))
                    .cloned())
            })
            .unwrap_or_default();
        if want_links != have_links {
            return false;
        }
        if let (Some(dp), Some(ap)) = (dp, ap) {
            if ap.trtype != dp.trtype.as_str() {
                return false;
            }
            if dp.trtype != Transport::Loop && ap.traddr != dp.traddr.to_string() {
                return false;
            }
        }
    }
    true
}

/// Whether actual LIO configfs already realizes the desired state (managed
/// targets, by our IQN prefix).
pub fn lio_satisfied(d: &LioDesired, a: &ActualLio) -> bool {
    let want: BTreeSet<String> = set(d.targets.iter().map(|t| t.iqn.to_string()));
    let have: BTreeSet<String> = set(a
        .targets
        .iter()
        .filter(|t| t.iqn.starts_with(OUR_IQN_PREFIX))
        .map(|t| t.iqn.clone()));
    if want != have {
        return false;
    }
    for db in &d.backstores {
        let Some(ab) = a.backstores.iter().find(|b| b.name == db.name.as_str()) else {
            return false;
        };
        if !ab.enabled || ab.udev_path != db.device_path.as_str() {
            return false;
        }
    }
    for dt in &d.targets {
        let Some(at) = a.targets.iter().find(|t| t.iqn == dt.iqn.as_str()) else {
            return false;
        };
        if at.enabled != dt.enabled || at.demo_mode != dt.demo_mode {
            return false;
        }
        if set(dt.luns.iter().map(|l| l.backstore.to_string())) != set(at.luns.iter().cloned()) {
            return false;
        }
        let want_portals: BTreeSet<(String, bool)> = set(dt
            .portals
            .iter()
            .map(|p| (fmt_addr(p.addr, p.port), p.iser)));
        let have_portals: BTreeSet<(String, bool)> =
            set(at.portals.iter().map(|p| (p.addr_port.clone(), p.iser)));
        if want_portals != have_portals {
            return false;
        }
        let want_acls: BTreeSet<String> = if dt.demo_mode {
            BTreeSet::new()
        } else {
            set(dt.acls.iter().map(|a| a.to_string()))
        };
        if want_acls != set(at.acls.iter().cloned()) {
            return false;
        }
    }
    true
}

fn fmt_addr(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// The nvmet transport modules to load for the enabled NVMe-oF exports.
pub fn nvme_modules(nvme: &[NvmeExport]) -> Vec<KernelModule> {
    let mut m = Vec::new();
    let any = |f: fn(&NvmeExport) -> bool| nvme.iter().filter(|e| e.enabled).any(f);
    if any(|e| e.want_rdma) {
        m.push(KernelModule::NvmetRdma);
    }
    if any(|e| e.want_tcp) {
        m.push(KernelModule::NvmetTcp);
    }
    if any(|e| e.want_loop) {
        m.push(KernelModule::NvmetLoop);
    }
    m
}

/// The LIO modules to load for the enabled iSCSI exports (iSER only when any
/// requests RDMA).
pub fn iscsi_modules(iscsi: &[IscsiExport]) -> Vec<KernelModule> {
    let mut m = Vec::new();
    let enabled: Vec<&IscsiExport> = iscsi.iter().filter(|e| e.enabled).collect();
    if !enabled.is_empty() {
        m.push(KernelModule::Iscsi);
        if enabled.iter().any(|e| e.want_rdma) {
            m.push(KernelModule::Iser);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actual::lio::{Backstore, Portal, Target};
    use crate::actual::nvmet::{Namespace, Port, Subsys};
    use greendot_proto::NFS_RDMA_PORT;

    const DEV: &str = "/dev/zvol/tank/vm1";

    fn nvme_export() -> NvmeExport {
        NvmeExport {
            id: 1,
            name: "vm1".into(),
            device_path: DEV.into(),
            enabled: true,
            want_rdma: true,
            want_tcp: true,
            want_loop: false,
            allow_any_host: false,
            initiators: vec!["nqn.2014-08.org.nvmexpress:host1".into()],
            interfaces: vec![],
            last_error: None,
        }
    }

    #[test]
    fn renders_nvmet_subsystems_and_ports() {
        let d = render_nvmet(
            &[nvme_export()],
            "10.0.0.5".parse().unwrap(),
            &HashMap::new(),
        );
        assert_eq!(d.subsystems.len(), 1);
        assert_eq!(d.subsystems[0].nqn.as_str(), "nqn.2026-06.io.greendot:vm1");
        assert_eq!(d.subsystems[0].allowed_hosts.len(), 1);
        // rdma (port 1) + tcp (port 2), both linking the subsystem; no loop.
        let ids: Vec<u16> = d.ports.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![1, 2]);
        assert_eq!(d.ports[0].trtype, Transport::Rdma);
        assert_eq!(d.ports[1].trtype, Transport::Tcp);
        assert!(
            d.ports
                .iter()
                .all(|p| p.subsystems.len() == 1 && p.traddr.to_string() == "10.0.0.5")
        );
    }

    #[test]
    fn nvmet_satisfied_detects_match_and_drift() {
        let listen: IpAddr = "10.0.0.5".parse().unwrap();
        let d = render_nvmet(&[nvme_export()], listen, &HashMap::new());
        let actual = ActualNvmet {
            subsystems: vec![Subsys {
                nqn: "nqn.2026-06.io.greendot:vm1".into(),
                allow_any_host: false,
                allowed_hosts: vec!["nqn.2014-08.org.nvmexpress:host1".into()],
                namespaces: vec![Namespace {
                    nsid: 1,
                    device_path: DEV.into(),
                    enabled: true,
                }],
            }],
            ports: vec![
                Port {
                    id: 1,
                    trtype: "rdma".into(),
                    traddr: "10.0.0.5".into(),
                    trsvcid: "4420".into(),
                    subsystems: vec!["nqn.2026-06.io.greendot:vm1".into()],
                },
                Port {
                    id: 2,
                    trtype: "tcp".into(),
                    traddr: "10.0.0.5".into(),
                    trsvcid: "4420".into(),
                    subsystems: vec!["nqn.2026-06.io.greendot:vm1".into()],
                },
            ],
        };
        assert!(
            nvmet_satisfied(&d, &actual),
            "exact match should be satisfied"
        );
        // Empty actual (post-reboot) is not satisfied.
        assert!(!nvmet_satisfied(&d, &ActualNvmet::default()));
        // Wrong device path is drift.
        let mut drift = actual.clone();
        drift.subsystems[0].namespaces[0].device_path = "/dev/zvol/tank/other".into();
        assert!(!nvmet_satisfied(&d, &drift));
        // A foreign subsystem does not force a re-apply.
        let mut foreign = actual.clone();
        foreign.subsystems.push(Subsys {
            nqn: "nqn.2000-01.com.example:manual".into(),
            allow_any_host: true,
            allowed_hosts: vec![],
            namespaces: vec![],
        });
        assert!(nvmet_satisfied(&d, &foreign));
    }

    /// Two physical ports with known live IPs, for the interface-pinning tests.
    fn pci_addrs() -> HashMap<String, Vec<IpAddr>> {
        HashMap::from([
            ("0000:00:10.0".to_owned(), vec!["10.0.0.1".parse().unwrap()]),
            ("0000:00:11.0".to_owned(), vec!["10.0.0.2".parse().unwrap()]),
        ])
    }

    #[test]
    fn listen_addrs_resolves_pins_or_falls_back_to_default() {
        let default: IpAddr = "0.0.0.0".parse().unwrap();
        let pci = pci_addrs();
        // No pins → the default (unchanged behavior).
        assert_eq!(listen_addrs(&[], default, &pci), vec![default]);
        // One pin → its current IP.
        assert_eq!(
            listen_addrs(&["pci:0000:00:10.0".into()], default, &pci),
            vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
        // Unknown scheme / unresolvable port / malformed all contribute nothing.
        assert!(
            listen_addrs(
                &[
                    "mac:00:11:22:33:44:55".into(),
                    "pci:0000:00:99.0".into(),
                    "garbage".into(),
                ],
                default,
                &pci,
            )
            .is_empty()
        );
    }

    #[test]
    fn renders_per_interface_nvmet_ports() {
        let default: IpAddr = "0.0.0.0".parse().unwrap();
        let pci = pci_addrs();
        let pin = |id: i64, name: &str, ifaces: &[&str]| NvmeExport {
            id,
            name: name.into(),
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
            want_rdma: true,
            want_tcp: false,
            ..nvme_export()
        };

        // One pinned interface → a single RDMA port at the resolved IP, not 0.0.0.0.
        let d = render_nvmet(&[pin(1, "a", &["pci:0000:00:10.0"])], default, &pci);
        assert_eq!(d.ports.len(), 1);
        assert_eq!(d.ports[0].trtype, Transport::Rdma);
        assert_eq!(d.ports[0].traddr.to_string(), "10.0.0.1");

        // Two exports on the same (transport, IP) share one port; the subsystem
        // remains, even for the export whose pin can't be resolved (no port).
        let shared = render_nvmet(
            &[
                pin(1, "a", &["pci:0000:00:10.0"]),
                pin(2, "b", &["pci:0000:00:10.0"]),
            ],
            default,
            &pci,
        );
        assert_eq!(shared.ports.len(), 1);
        assert_eq!(shared.ports[0].subsystems.len(), 2);

        // One export pinning both ports → one RDMA port per resolved IP.
        let multi = render_nvmet(
            &[pin(1, "a", &["pci:0000:00:10.0", "pci:0000:00:11.0"])],
            default,
            &pci,
        );
        let addrs: BTreeSet<String> = multi.ports.iter().map(|p| p.traddr.to_string()).collect();
        assert_eq!(
            addrs,
            BTreeSet::from(["10.0.0.1".into(), "10.0.0.2".into()])
        );

        // An unresolvable pin yields no port but keeps the subsystem (honest "not
        // served" rather than silently falling back to the default address).
        let unresolved = render_nvmet(&[pin(1, "a", &["pci:0000:00:99.0"])], default, &pci);
        assert!(unresolved.ports.is_empty());
        assert_eq!(unresolved.subsystems.len(), 1);
    }

    #[test]
    fn renders_per_interface_lio_portals() {
        let default: IpAddr = "0.0.0.0".parse().unwrap();
        let e = IscsiExport {
            interfaces: vec!["pci:0000:00:10.0".into()],
            want_rdma: true,
            want_tcp: true,
            ..iscsi_export()
        };
        let d = render_lio(&[e], default, &pci_addrs());
        let portals: BTreeSet<(String, bool)> = d.targets[0]
            .portals
            .iter()
            .map(|p| (fmt_addr(p.addr, p.port), p.iser))
            .collect();
        assert_eq!(
            portals,
            BTreeSet::from([
                ("10.0.0.1:3260".to_owned(), true),
                ("10.0.0.1:3261".to_owned(), false),
            ])
        );
    }

    fn iscsi_export() -> IscsiExport {
        IscsiExport {
            id: 1,
            name: "tape".into(),
            device_path: DEV.into(),
            enabled: true,
            want_rdma: true,
            want_tcp: true,
            allow_any_host: false,
            // iSCSI initiators are IQNs, not NQNs.
            initiators: vec!["iqn.1993-08.org.debian:01:abc".into()],
            interfaces: vec![],
            last_error: None,
        }
    }

    #[test]
    fn renders_and_satisfies_lio() {
        let listen: IpAddr = "10.0.0.5".parse().unwrap();
        let d = render_lio(&[iscsi_export()], listen, &HashMap::new());
        assert_eq!(d.targets[0].iqn.as_str(), "iqn.2026-06.io.greendot:tape");
        // rdma => iser on 3260, tcp => plain on 3261
        assert_eq!(d.targets[0].portals.len(), 2);

        let actual = ActualLio {
            backstores: vec![Backstore {
                name: "tape".into(),
                udev_path: DEV.into(),
                enabled: true,
            }],
            targets: vec![Target {
                iqn: "iqn.2026-06.io.greendot:tape".into(),
                enabled: true,
                demo_mode: false,
                luns: vec!["tape".into()],
                portals: vec![
                    Portal {
                        addr_port: "10.0.0.5:3260".into(),
                        iser: true,
                    },
                    Portal {
                        addr_port: "10.0.0.5:3261".into(),
                        iser: false,
                    },
                ],
                acls: vec!["iqn.1993-08.org.debian:01:abc".into()],
            }],
        };
        assert!(lio_satisfied(&d, &actual));
        assert!(!lio_satisfied(&d, &ActualLio::default()));
        let mut drift = actual.clone();
        drift.targets[0].portals.pop();
        assert!(!lio_satisfied(&d, &drift));
    }

    #[test]
    fn modules_follow_enabled_transports() {
        assert_eq!(
            nvme_modules(&[nvme_export()]),
            vec![KernelModule::NvmetRdma, KernelModule::NvmetTcp]
        );
        assert_eq!(
            iscsi_modules(&[iscsi_export()]),
            vec![KernelModule::Iscsi, KernelModule::Iser]
        );
        assert!(nvme_modules(&[]).is_empty());
        assert!(iscsi_modules(&[]).is_empty());
    }

    #[test]
    fn renders_and_satisfies_nfs() {
        use crate::actual::nfs::{ActualNfs, NfsExportEntry};
        use crate::state::{NfsClientEntry, NfsExport};

        let exp = NfsExport {
            id: 1,
            path: "/tank/share".into(),
            enabled: true,
            clients: vec![NfsClientEntry {
                client: "192.168.101.0/24".into(),
                rw: true,
            }],
            last_error: None,
        };
        let d = render_nfs(std::slice::from_ref(&exp), NFS_RDMA_PORT);
        assert_eq!(d.exports.len(), 1);
        assert_eq!(d.exports[0].path.as_str(), "/tank/share");
        assert_eq!(d.exports[0].fsid, NFS_FSID_BASE | 1);
        assert_eq!(d.rdma_port, NFS_RDMA_PORT);

        let entry = |path: &str, clients: &[&str]| NfsExportEntry {
            path: path.into(),
            clients: clients.iter().map(|c| c.to_string()).collect(),
        };
        let mgd = |specs: &[(&str, &str, bool)]| {
            specs
                .iter()
                .map(|(p, c, rw)| (p.to_string(), c.to_string(), *rw))
                .collect::<std::collections::BTreeSet<_>>()
        };
        let good = ActualNfs {
            exports: vec![entry("/tank/share", &["192.168.101.0/24"])],
            rdma_port: Some(NFS_RDMA_PORT),
            managed: mgd(&[("/tank/share", "192.168.101.0/24", true)]),
        };
        assert!(nfs_satisfied(&d, &good), "managed==desired, live, rdma on");
        // Post-reboot before apply: nothing managed yet → re-apply.
        assert!(!nfs_satisfied(
            &d,
            &ActualNfs {
                managed: mgd(&[]),
                ..good.clone()
            }
        ));
        // Same client but read-only (option drift) → re-apply.
        assert!(!nfs_satisfied(
            &d,
            &ActualNfs {
                managed: mgd(&[("/tank/share", "192.168.101.0/24", false)]),
                ..good.clone()
            }
        ));
        // TCP-only (RDMA listener missing) → re-apply to assert it.
        assert!(!nfs_satisfied(
            &d,
            &ActualNfs {
                rdma_port: None,
                ..good.clone()
            }
        ));
        // Path dropped from the live table → re-apply.
        assert!(!nfs_satisfied(
            &d,
            &ActualNfs {
                exports: vec![],
                ..good.clone()
            }
        ));
        // A foreign export present does not force a re-apply.
        let with_foreign = ActualNfs {
            exports: vec![
                entry("/tank/share", &["192.168.101.0/24"]),
                entry("/srv/foreign", &["*"]),
            ],
            ..good.clone()
        };
        assert!(nfs_satisfied(&d, &with_foreign));

        // Empty desired is satisfied only when greendot manages nothing.
        let empty = render_nfs(&[], NFS_RDMA_PORT);
        assert!(nfs_satisfied(&empty, &ActualNfs::default()));
        assert!(!nfs_satisfied(
            &empty,
            &ActualNfs {
                managed: mgd(&[("/old", "*", false)]),
                ..ActualNfs::default()
            }
        ));

        // Disabled exports render nothing and request no module.
        let disabled = NfsExport {
            enabled: false,
            ..exp
        };
        assert!(
            render_nfs(std::slice::from_ref(&disabled), NFS_RDMA_PORT)
                .exports
                .is_empty()
        );
        assert!(nfs_modules(&[disabled]).is_empty());
        let enabled = NfsExport {
            id: 2,
            path: "/x".into(),
            enabled: true,
            clients: vec![],
            last_error: None,
        };
        assert_eq!(nfs_modules(&[enabled]), vec![KernelModule::Rpcrdma]);
    }
}
