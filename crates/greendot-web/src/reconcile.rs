//! Desired-state reconciliation. Renders the full NVMe-oF/iSCSI desired state
//! from the export list, and — only when actual configfs no longer realizes it
//! — applies it via the helper: NVMe-oF is written to configfs directly, iSCSI
//! through a `targetctl` restore task. Each apply is therefore a recorded task;
//! steady-state reconciles emit nothing.

use crate::actual::lio::ActualLio;
use crate::actual::nvmet::ActualNvmet;
use crate::routes::AppState;
use crate::state::{Export, ExportKind, OUR_IQN_PREFIX, OUR_NQN_PREFIX};
use crate::task_runner;
use greendot_proto::{
    KernelModule, LioBackstoreSpec, LioDesired, LioLunSpec, LioPortalSpec, LioTargetSpec,
    NvmetDesired, NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, Request, Transport,
};
use std::collections::BTreeSet;
use std::net::IpAddr;

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

/// Reconciles desired → actual, applying via tasks only on drift. Serialized
/// by the caller's `reconcile_lock`.
pub async fn run(state: &AppState) -> anyhow::Result<()> {
    let listen: IpAddr = state
        .db
        .get_setting("listen_addr")?
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    let exports = state.db.list_exports()?;

    let nvmet_desired = render_nvmet(&exports, listen);
    let lio_desired = render_lio(&exports, listen);
    let nvmet_ok = nvmet_satisfied(
        &nvmet_desired,
        &crate::actual::nvmet::read(&state.nvmet_root),
    );
    let lio_ok = lio_satisfied(&lio_desired, &crate::actual::lio::read(&state.lio_root));
    if nvmet_ok && lio_ok {
        return Ok(()); // already realized — emit no task
    }

    let modules = modules_for(&exports);
    if !modules.is_empty() {
        task_runner::run(
            state,
            Request::EnsureModules { modules },
            "modules",
            "Load kernel modules",
        )
        .await?;
    }

    let mut nvmet_err = None;
    if !nvmet_ok {
        let out = task_runner::run(
            state,
            Request::NvmetApply {
                desired: nvmet_desired,
            },
            "nvmet-apply",
            "Apply NVMe-oF configuration",
        )
        .await?;
        nvmet_err = (!out.ok).then(|| out.error.unwrap_or_else(|| "nvmet apply failed".into()));
    }
    let mut lio_err = None;
    if !lio_ok {
        let out = task_runner::run(
            state,
            Request::LioApply {
                desired: lio_desired,
            },
            "lio-apply",
            "Apply iSCSI configuration",
        )
        .await?;
        lio_err = (!out.ok).then(|| out.error.unwrap_or_else(|| "targetcli failed".into()));
    }

    // Surface apply failures on the relevant exports' dots and the banner.
    for e in exports.iter().filter(|e| e.enabled) {
        let err = match e.kind {
            ExportKind::Nvme => nvmet_err.as_deref(),
            ExportKind::Iscsi => lio_err.as_deref(),
        };
        state.db.set_export_error(e.id, err)?;
    }
    let banner = nvmet_err.or(lio_err).unwrap_or_default();
    state.db.set_setting(RECONCILE_ERROR_KEY, &banner)?;
    Ok(())
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
}
