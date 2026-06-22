use super::{AppState, page};
use crate::actual::nic::{self, NicRdmaKind, NicStatus};
use crate::actual::rdma;
use crate::auth::CurrentUser;
use crate::routes::exports::reconcile_state;
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use greendot_proto::{KernelModule, NetdevName, PciAddress, Request};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/settings", get(settings_page))
        .route("/settings/nic/{netdev}", get(nic_detail_page))
        .route("/settings/reconcile", post(reconcile_now))
        .route("/settings/listen", post(set_listen))
        .route("/settings/rxe", post(enable_rxe))
        .route("/settings/roce", post(set_roce))
        .route("/settings/install", post(install_deps))
}

pub struct RdmaRow {
    pub name: String,
    pub netdev: String,
    pub state: &'static str,
    pub addrs: String,
}

/// One row of the per-NIC RDMA-capability table.
pub struct NicRow {
    pub netdev: String,
    pub rdma: String,
    pub addrs: String,
    pub status: &'static str,
    pub dot: &'static str,
    /// `Some(pci)` → render an "Enable RoCE" button targeting that PCI address.
    pub roce_pci: Option<String>,
    /// True → render an "Enable Soft-RoCE" button for this netdev.
    pub soft_roce: bool,
}

/// Map a classified NIC to a table row, dropping interfaces that aren't RDMA
/// candidates (virtual interfaces, IB-only netdevs). Shared with the dashboard.
pub(crate) fn nic_row(s: NicStatus) -> Option<NicRow> {
    let (status, dot, roce_pci, soft_roce) = match &s.kind {
        NicRdmaKind::Active => ("RDMA active", "dot-green", None, false),
        NicRdmaKind::Inactive => ("RDMA device down", "dot-yellow", None, false),
        NicRdmaKind::CapableDisabled { pci } => (
            "RoCE-capable (Mellanox), disabled",
            "dot-red",
            Some(pci.clone()),
            false,
        ),
        NicRdmaKind::SoftRoceable => ("no RDMA", "dot-gray", None, true),
        NicRdmaKind::Unsupported => return None,
    };
    Some(NicRow {
        rdma: s.rdma.unwrap_or_else(|| "—".into()),
        addrs: s
            .addrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        status,
        dot,
        roce_pci,
        soft_roce,
        netdev: s.netdev,
    })
}

pub struct DepRow {
    pub cli: &'static str,
    pub package: String,
    pub present: bool,
}

pub struct SettingsView {
    pub listen_addr: String,
    pub rdma_devs: Vec<RdmaRow>,
    pub nics: Vec<NicRow>,
    pub deps: Vec<DepRow>,
    /// Missing packages apt can install here — the one-click "Install missing".
    pub installable_packages: String,
    /// Missing packages with no apt candidate — must be installed manually.
    pub manual_packages: String,
    /// Detected OS label (for display).
    pub os_pretty: String,
    /// Whether the one-click installer can drive this OS (Debian/Ubuntu).
    pub install_supported: bool,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

/// True if `cli` is found on PATH (unprivileged check).
fn cli_present(cli: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(cli).is_file()))
        .unwrap_or(false)
}

/// Split missing packages into those apt can install on this host (first) and
/// those with no apt candidate, which must be installed manually (second).
fn partition_missing(
    missing: Vec<String>,
    available: &std::collections::HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    missing.into_iter().partition(|p| available.contains(p))
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    user: CurrentUser,
    view: SettingsView,
}

#[derive(Template)]
#[template(path = "_settings.html")]
struct SettingsPartial {
    view: SettingsView,
}

async fn gather(
    state: &AppState,
    flash: Option<String>,
    form_error: Option<String>,
) -> SettingsView {
    let devs = rdma::devices();
    let nics: Vec<NicRow> = nic::interfaces().into_iter().filter_map(nic_row).collect();
    let deps: Vec<DepRow> = greendot_proto::REQUIRED_CLIS
        .iter()
        .map(|&cli| DepRow {
            cli,
            package: greendot_proto::package_for_cli(cli)
                .unwrap_or("")
                .to_string(),
            present: cli_present(cli),
        })
        .collect();
    let mut missing: Vec<String> = deps
        .iter()
        .filter(|d| !d.present && !d.package.is_empty())
        .map(|d| d.package.clone())
        .collect();
    missing.sort();
    missing.dedup();
    let os = greendot_proto::detect();
    let install_supported = matches!(os.family, greendot_proto::PkgFamily::Debian);
    // Only packages apt can actually install belong in the one-click button; the
    // rest (e.g. nvmetcli, which Ubuntu 26.04 dropped) get a manual-install hint.
    // On non-apt distros there is nothing the in-app installer can supply.
    let available = if install_supported {
        crate::actual::apt::available(&missing).await
    } else {
        std::collections::HashSet::new()
    };
    let (installable, manual) = partition_missing(missing, &available);
    SettingsView {
        install_supported,
        os_pretty: os.pretty,
        installable_packages: installable.join(" "),
        manual_packages: manual.join(" "),
        deps,
        listen_addr: state
            .db
            .get_setting("listen_addr")
            .ok()
            .flatten()
            .unwrap_or_else(|| "0.0.0.0".into()),
        rdma_devs: devs
            .into_iter()
            .map(|d| RdmaRow {
                name: d.name,
                netdev: d.netdev.unwrap_or_else(|| "?".into()),
                state: if d.active { "active" } else { "down" },
                addrs: d
                    .addrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            })
            .collect(),
        nics,
        flash,
        form_error,
    }
}

async fn settings_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(SettingsTemplate {
        user,
        view: gather(&state, None, None).await,
    })
}

// ---- Per-NIC page (Enable RoCE / Soft-RoCE) ----

pub struct NicDetailView {
    /// `None` when no such RDMA-candidate interface exists on this host.
    pub nic: Option<NicRow>,
    pub netdev: String,
    pub flash: Option<String>,
    pub form_error: Option<String>,
}

#[derive(Template)]
#[template(path = "nic_detail.html")]
struct NicDetailTemplate {
    user: CurrentUser,
    view: NicDetailView,
}

#[derive(Template)]
#[template(path = "_nic_detail.html")]
struct NicDetailPartial {
    view: NicDetailView,
}

fn gather_nic_detail(
    netdev: &str,
    flash: Option<String>,
    form_error: Option<String>,
) -> NicDetailView {
    NicDetailView {
        nic: nic::interfaces()
            .into_iter()
            .filter_map(nic_row)
            .find(|n| n.netdev == netdev),
        netdev: netdev.to_owned(),
        flash,
        form_error,
    }
}

async fn nic_detail_page(
    Extension(user): Extension<CurrentUser>,
    Path(netdev): Path<String>,
) -> Response {
    page(NicDetailTemplate {
        user,
        view: gather_nic_detail(&netdev, None, None),
    })
}

async fn reconcile_now(State(state): State<Arc<AppState>>) -> Response {
    let (flash, error) = match reconcile_state(&state).await {
        Ok(()) => (Some("reconciled".into()), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(SettingsPartial {
        view: gather(&state, flash, error).await,
    })
}

#[derive(Deserialize)]
struct ListenForm {
    listen_addr: String,
}

async fn set_listen(State(state): State<Arc<AppState>>, Form(form): Form<ListenForm>) -> Response {
    let addr = form.listen_addr.trim();
    if addr.parse::<std::net::IpAddr>().is_err() {
        return page(SettingsPartial {
            view: gather(&state, None, Some(format!("invalid IP address {addr:?}"))).await,
        });
    }
    let result = match state.db.set_setting("listen_addr", addr) {
        Ok(()) => reconcile_state(&state).await,
        Err(e) => Err(e),
    };
    let (flash, error) = match result {
        Ok(()) => (
            Some(format!("listen address set to {addr}; exports reconciled")),
            None,
        ),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    page(SettingsPartial {
        view: gather(&state, flash, error).await,
    })
}

#[derive(Deserialize)]
struct RxeForm {
    netdev: String,
}

async fn enable_rxe(State(state): State<Arc<AppState>>, Form(form): Form<RxeForm>) -> Response {
    let Ok(netdev) = NetdevName::new(form.netdev.trim()) else {
        return page(NicDetailPartial {
            view: gather_nic_detail(
                &form.netdev,
                None,
                Some(format!("invalid interface name {:?}", form.netdev)),
            ),
        });
    };
    let steps = [
        (
            "modules",
            "load rxe module",
            Request::EnsureModules {
                modules: vec![KernelModule::Rxe],
            },
        ),
        (
            "rxe-link",
            &format!("add Soft-RoCE on {netdev}"),
            Request::RxeLinkAdd {
                netdev: netdev.clone(),
            },
        ),
    ];
    for (kind, title, req) in steps {
        match crate::task_runner::run(&state, req, kind, title).await {
            Ok(o) if o.ok => {}
            Ok(o) => {
                let msg = o.error.unwrap_or_else(|| "task failed".into());
                return page(NicDetailPartial {
                    view: gather_nic_detail(netdev.as_str(), None, Some(msg)),
                });
            }
            Err(e) => {
                return page(NicDetailPartial {
                    view: gather_nic_detail(netdev.as_str(), None, Some(format!("{e:#}"))),
                });
            }
        }
    }
    let _ = reconcile_state(&state).await;
    page(NicDetailPartial {
        view: gather_nic_detail(
            netdev.as_str(),
            Some(format!("Soft-RoCE enabled on {netdev}")),
            None,
        ),
    })
}

#[derive(Deserialize)]
struct RoceForm {
    pci: String,
    netdev: String,
}

/// Turn on hardware RoCE for a Mellanox NIC: confirm `enable_roce` is actually
/// present and off (a VF may be PF-gated and can't self-enable), then set the
/// param and reload the device. The reload briefly drops the NIC.
async fn set_roce(State(state): State<Arc<AppState>>, Form(form): Form<RoceForm>) -> Response {
    let netdev = form.netdev.as_str();
    let Ok(pci) = PciAddress::new(form.pci.trim()) else {
        return page(NicDetailPartial {
            view: gather_nic_detail(
                netdev,
                None,
                Some(format!("invalid PCI address {:?}", form.pci)),
            ),
        });
    };
    // Confirm enable_roce is present and currently false before reloading.
    let probe = state
        .helper
        .collect(Request::DevlinkParams { pci: pci.clone() })
        .await;
    match nic::enable_roce_from_json(&probe.stdout) {
        Some(false) => {}
        Some(true) => {
            return page(NicDetailPartial {
                view: gather_nic_detail(
                    netdev,
                    Some(format!("RoCE is already enabled on {pci}")),
                    None,
                ),
            });
        }
        None => {
            let why = if probe.ok {
                format!(
                    "{pci} has no settable enable_roce parameter — on an SR-IOV VF, enable RoCE on the host/PF"
                )
            } else {
                probe
                    .error
                    .unwrap_or_else(|| format!("could not read devlink params for {pci}"))
            };
            return page(NicDetailPartial {
                view: gather_nic_detail(netdev, None, Some(why)),
            });
        }
    }
    let steps = [
        (
            "roce-param",
            format!("enable RoCE on {pci}"),
            Request::RoceEnableParam { pci: pci.clone() },
        ),
        (
            "devlink-reload",
            format!("reload {pci}"),
            Request::DevlinkReload { pci: pci.clone() },
        ),
    ];
    for (kind, title, req) in steps {
        match crate::task_runner::run(&state, req, kind, &title).await {
            Ok(o) if o.ok => {}
            Ok(o) => {
                let msg = o.error.unwrap_or_else(|| "task failed".into());
                return page(NicDetailPartial {
                    view: gather_nic_detail(netdev, None, Some(msg)),
                });
            }
            Err(e) => {
                return page(NicDetailPartial {
                    view: gather_nic_detail(netdev, None, Some(format!("{e:#}"))),
                });
            }
        }
    }
    let _ = reconcile_state(&state).await;
    page(NicDetailPartial {
        view: gather_nic_detail(
            netdev,
            Some(format!(
                "RoCE enabled on {pci}; reconnect if your session dropped"
            )),
            None,
        ),
    })
}

#[derive(Deserialize)]
struct InstallForm {
    /// Space-separated package names (from the dependency panel).
    packages: String,
}

async fn install_deps(
    State(state): State<Arc<AppState>>,
    Form(form): Form<InstallForm>,
) -> Response {
    let packages: Vec<greendot_proto::PackageName> = form
        .packages
        .split_whitespace()
        .filter_map(|p| greendot_proto::PackageName::new(p).ok())
        .collect();
    if packages.is_empty() {
        return page(SettingsPartial {
            view: gather(&state, None, Some("no valid packages to install".into())).await,
        });
    }
    let names = packages
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let req = Request::InstallPackages { packages };
    let (flash, error) =
        match crate::task_runner::run(&state, req, "install", &format!("install {names}")).await {
            Ok(o) => o.message(&format!("installed {names}")),
            Err(e) => (None, Some(format!("{e:#}"))),
        };
    page(SettingsPartial {
        view: gather(&state, flash, error).await,
    })
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use std::collections::HashSet;

    #[test]
    fn partition_missing_splits_installable_from_manual() {
        // nvmetcli has no apt candidate (e.g. Ubuntu 26.04); the rest do.
        let missing = ["nvmetcli", "targetcli-fb", "nvme-cli"]
            .map(String::from)
            .to_vec();
        let available: HashSet<String> = ["targetcli-fb", "nvme-cli"].map(String::from).into();
        let (installable, manual) = super::partition_missing(missing, &available);
        assert_eq!(installable, ["targetcli-fb", "nvme-cli"]);
        assert_eq!(manual, ["nvmetcli"]);
    }

    #[tokio::test]
    async fn settings_page_listen_addr_and_rxe_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        let req = auth(HttpRequest::get("/settings").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Listen address"), "{body}");
        assert!(body.contains("Network interfaces"), "{body}");

        // The per-NIC page renders (a graceful not-found is fine in the test env).
        let req = auth(
            HttpRequest::get("/settings/nic/eth0")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);

        // Valid listen address persists; invalid is rejected.
        let (_, _, body) = send(
            &app,
            auth(form_post("/settings/listen", "listen_addr=10.0.0.5")),
        )
        .await;
        assert!(body.contains("listen address set to 10.0.0.5"), "{body}");
        let (_, _, body) = send(
            &app,
            auth(form_post("/settings/listen", "listen_addr=junk")),
        )
        .await;
        assert!(body.contains("invalid IP address"), "{body}");

        // Soft-RoCE enable round-trips through the fake helper.
        let (_, _, body) = send(&app, auth(form_post("/settings/rxe", "netdev=eth0"))).await;
        assert!(body.contains("Soft-RoCE enabled on eth0"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/settings/rxe", "netdev=bad%2Fname"))).await;
        assert!(body.contains("invalid interface name"), "{body}");

        // Enable-RoCE: the fake helper reports enable_roce=false, so set+reload
        // run and report success; a malformed PCI address is rejected. The form
        // carries the netdev so the NIC's detail page can be re-gathered.
        let (_, _, body) = send(
            &app,
            auth(form_post("/settings/roce", "pci=0000:00:10.0&netdev=eth0")),
        )
        .await;
        assert!(body.contains("RoCE enabled on 0000:00:10.0"), "{body}");
        let (_, _, body) = send(
            &app,
            auth(form_post("/settings/roce", "pci=junk&netdev=eth0")),
        )
        .await;
        assert!(body.contains("invalid PCI address"), "{body}");
    }
}
