//! Desired-state reconciliation. Renders the full NVMe-oF/iSCSI desired state
//! from the export list, and — only when actual configfs no longer realizes it
//! — applies it via the helper: NVMe-oF is written to configfs directly, iSCSI
//! through a `targetctl` restore task.
//!
//! The apply itself runs out-of-process: `greendot-cli reconcile` calls
//! [`cli_run`], which streams its progress to stdout/stderr. The web service
//! wraps that command in a recorded task (see `routes::exports::reconcile_state`),
//! so the render/satisfied predicates here are shared by the web's drift
//! pre-check and the CLI.

use crate::actual::lio::ActualLio;
use crate::actual::nfs::ActualNfs;
use crate::actual::nvmet::ActualNvmet;
use crate::config::Config;
use crate::helper_client::HelperClient;
use crate::state::{Export, ExportKind, NfsExport, OUR_IQN_PREFIX, OUR_NQN_PREFIX};
use greendot_proto::{
    KernelModule, LioBackstoreSpec, LioDesired, LioLunSpec, LioPortalSpec, LioTargetSpec,
    NFS_RDMA_PORT, NfsClient, NfsClientSpec, NfsDesired, NfsExportPath, NfsExportSpec,
    NvmetDesired, NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, Request, Transport,
};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// greendot's NFS `fsid`s are offset into a reserved high range so they don't
/// collide with foreign numeric `fsid=`s in `/etc/exports`.
const NFS_FSID_BASE: u32 = 0x6700_0000;

pub const RECONCILE_ERROR_KEY: &str = "reconcile_error";

const PORT_RDMA: u16 = 1;
const PORT_TCP: u16 = 2;
const PORT_LOOP: u16 = 3;
const TRSVCID: u16 = 4420;

fn enabled(exports: &[Export], kind: ExportKind) -> impl Iterator<Item = &Export> {
    exports.iter().filter(move |e| e.enabled && e.kind == kind)
}

/// Predicate over an export (which transport it wants).
type Wants = fn(&Export) -> bool;

/// Renders the desired nvmet state from the enabled NVMe-oF exports.
pub fn render_nvmet(exports: &[Export], listen: IpAddr) -> NvmetDesired {
    let subsystems: Vec<NvmetSubsysSpec> = enabled(exports, ExportKind::Nvme)
        .filter_map(|e| {
            Some(NvmetSubsysSpec {
                nqn: e.nqn(),
                allow_any_host: e.allow_any_host,
                allowed_hosts: e
                    .initiators
                    .iter()
                    .filter_map(|i| greendot_proto::Nqn::new(i.clone()).ok())
                    .collect(),
                namespaces: vec![NvmetNsSpec {
                    nsid: 1,
                    device_path: greendot_proto::DevicePath::new(&e.device_path).ok()?,
                }],
            })
        })
        .collect();

    let mut ports = Vec::new();
    let wants: [(u16, Transport, Wants); 3] = [
        (PORT_RDMA, Transport::Rdma, |e| e.want_rdma),
        (PORT_TCP, Transport::Tcp, |e| e.want_tcp),
        (PORT_LOOP, Transport::Loop, |e| e.want_loop),
    ];
    for (id, trtype, want) in wants {
        let subs: Vec<_> = enabled(exports, ExportKind::Nvme)
            .filter(|e| want(e) && greendot_proto::DevicePath::new(&e.device_path).is_ok())
            .map(|e| e.nqn())
            .collect();
        if !subs.is_empty() {
            ports.push(NvmetPortSpec {
                id,
                trtype,
                traddr: listen,
                trsvcid: TRSVCID,
                subsystems: subs,
            });
        }
    }
    NvmetDesired { subsystems, ports }
}

/// Renders the desired LIO state from the enabled iSCSI exports.
pub fn render_lio(exports: &[Export], listen: IpAddr) -> LioDesired {
    let mut backstores = Vec::new();
    let mut targets = Vec::new();
    for e in enabled(exports, ExportKind::Iscsi) {
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
        let mut portals = Vec::new();
        if e.want_rdma {
            portals.push(LioPortalSpec {
                addr: listen,
                port: 3260,
                iser: true,
            });
        }
        if e.want_tcp {
            portals.push(LioPortalSpec {
                addr: listen,
                port: if e.want_rdma { 3261 } else { 3260 },
                iser: false,
            });
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

fn modules_for(exports: &[Export]) -> Vec<KernelModule> {
    let mut m = Vec::new();
    let nvme = |f: fn(&Export) -> bool| enabled(exports, ExportKind::Nvme).any(f);
    if nvme(|e| e.want_rdma) {
        m.push(KernelModule::NvmetRdma);
    }
    if nvme(|e| e.want_tcp) {
        m.push(KernelModule::NvmetTcp);
    }
    if nvme(|e| e.want_loop) {
        m.push(KernelModule::NvmetLoop);
    }
    if enabled(exports, ExportKind::Iscsi).next().is_some() {
        m.push(KernelModule::Iscsi);
        if enabled(exports, ExportKind::Iscsi).any(|e| e.want_rdma) {
            m.push(KernelModule::Iser);
        }
    }
    m
}

/// Reconciles desired → actual for `greendot-cli reconcile`: renders the
/// desired state, and on drift applies it via the helper, streaming each step's
/// output to stdout/stderr. Read-only on the config TOML — the web service
/// records the run as a task and writes back the outcome. Returns `true` when
/// everything reconciled (including the no-op steady state), `false` if any
/// apply failed.
pub async fn cli_run(cfg: &Config) -> anyhow::Result<bool> {
    let desired = crate::state::read_desired(&cfg.state_path)?;
    let exports = desired.exports;
    let helper = HelperClient::new(cfg.helper_socket.clone());

    let nfs_exports = desired.nfs_exports;
    let nvmet_desired = render_nvmet(&exports, desired.listen);
    let lio_desired = render_lio(&exports, desired.listen);
    let nfs_desired = render_nfs(&nfs_exports, NFS_RDMA_PORT);
    let nvmet_ok = nvmet_satisfied(&nvmet_desired, &crate::actual::nvmet::read(&cfg.nvmet_root));
    let lio_ok = lio_satisfied(&lio_desired, &crate::actual::lio::read(&cfg.lio_root));
    let nfs_ok = nfs_satisfied(&nfs_desired, &crate::actual::nfs::read(&helper).await);
    if nvmet_ok && lio_ok && nfs_ok {
        println!("already reconciled; nothing to do");
        return Ok(true);
    }

    let mut ok = true;
    let mut modules = modules_for(&exports);
    modules.extend(nfs_modules(&nfs_exports));
    if !modules.is_empty() {
        ok &= run_step(
            &helper,
            Request::EnsureModules { modules },
            "Load kernel modules",
        )
        .await;
    }
    if !nvmet_ok {
        let req = Request::NvmetApply {
            desired: nvmet_desired,
        };
        ok &= run_step(&helper, req, "Apply NVMe-oF configuration").await;
    }
    if !lio_ok {
        let req = Request::LioApply {
            desired: lio_desired,
        };
        ok &= run_step(&helper, req, "Apply iSCSI configuration").await;
    }
    if !nfs_ok {
        let req = Request::NfsApply {
            desired: nfs_desired,
        };
        ok &= run_step(&helper, req, "Apply NFS configuration").await;
    }
    Ok(ok)
}

/// Runs one apply request through the helper, echoing its streamed output to
/// the CLI's own stdout/stderr (which the web records as the task's output).
async fn run_step(helper: &HelperClient, req: Request, label: &str) -> bool {
    println!("== {label} ==");
    let out = helper.collect(req).await;
    print!("{}", out.stdout);
    eprint!("{}", out.stderr);
    if !out.ok {
        eprintln!(
            "{label} failed: {}",
            out.error.as_deref().unwrap_or("unknown error")
        );
    }
    out.ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actual::lio::{Backstore, Portal, Target};
    use crate::actual::nvmet::{Namespace, Port, Subsys};

    const DEV: &str = "/dev/zvol/tank/vm1";

    fn nvme_export() -> Export {
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
            initiators: vec!["nqn.2014-08.org.nvmexpress:host1".into()],
            last_error: None,
        }
    }

    #[test]
    fn renders_nvmet_subsystems_and_ports() {
        let d = render_nvmet(&[nvme_export()], "10.0.0.5".parse().unwrap());
        assert_eq!(d.subsystems.len(), 1);
        assert_eq!(d.subsystems[0].nqn.as_str(), "nqn.2026-06.io.greendot:vm1");
        assert_eq!(d.subsystems[0].allowed_hosts.len(), 1);
        // rdma (port 1) + tcp (port 2), both linking the subsystem; no loop.
        let ids: Vec<u16> = d.ports.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![PORT_RDMA, PORT_TCP]);
        assert!(
            d.ports
                .iter()
                .all(|p| p.subsystems.len() == 1 && p.traddr.to_string() == "10.0.0.5")
        );
    }

    #[test]
    fn nvmet_satisfied_detects_match_and_drift() {
        let listen: IpAddr = "10.0.0.5".parse().unwrap();
        let d = render_nvmet(&[nvme_export()], listen);
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

    fn iscsi_export() -> Export {
        Export {
            kind: ExportKind::Iscsi,
            name: "tape".into(),
            // iSCSI initiators are IQNs, not NQNs.
            initiators: vec!["iqn.1993-08.org.debian:01:abc".into()],
            ..nvme_export()
        }
    }

    #[test]
    fn renders_and_satisfies_lio() {
        let listen: IpAddr = "10.0.0.5".parse().unwrap();
        let d = render_lio(&[iscsi_export()], listen);
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
            modules_for(&[nvme_export()]),
            vec![KernelModule::NvmetRdma, KernelModule::NvmetTcp]
        );
        assert_eq!(
            modules_for(&[iscsi_export()]),
            vec![KernelModule::Iscsi, KernelModule::Iser]
        );
        assert!(modules_for(&[]).is_empty());
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
