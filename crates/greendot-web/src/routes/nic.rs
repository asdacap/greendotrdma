//! The NIC pages: a list of network interfaces and a per-NIC detail page with
//! its network configuration, traffic/temperature graphs, RDMA status, and the
//! RoCE / Soft-RoCE enable actions — plus the read-only RDMA-readiness Diagnose
//! page. All vendor knowledge stays in the helper; the web renders opaque data.

use super::{AppState, page};
use crate::actual::nic::{self, NicNetwork, NicRdmaKind, NicStatus};
use crate::auth::CurrentUser;
use crate::dot::{Criterion, nic_diagnostics};
use crate::metrics::{ChartUnit, chart_svg, mirror_chart_svg};
use crate::routes::block_export::reconcile_state;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use greendot_proto::{NetdevName, ops};
use serde::Deserialize;
use std::sync::Arc;

/// The smallest MTU we consider a jumbo frame. RDMA storage wants jumbo frames
/// (or larger) to cut per-packet overhead; anything below this earns a warning.
const JUMBO_MTU: u32 = 9000;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/nic", get(nic_page))
        .route("/nic/{netdev}", get(nic_detail_page))
        .route("/nic/{netdev}/diagnose", get(nic_diagnose_page))
        .route("/nic/{netdev}/roce", post(set_roce))
        .route("/nic/{netdev}/rxe", post(enable_rxe))
        .route("/nic/{netdev}/mtu", post(set_mtu))
}

/// One row of the per-NIC RDMA-capability table.
pub struct NicRow {
    pub netdev: String,
    pub rdma: String,
    pub addrs: String,
    pub status: String,
    pub dot: &'static str,
    /// True → render an "Enable RoCE" button posting this NIC's `netdev` (the
    /// helper detects the vendor and runs the enable).
    pub roce: bool,
    /// True → render an "Enable Soft-RoCE" button for this netdev.
    pub soft_roce: bool,
    /// True → offer the per-NIC Diagnose page (the NIC isn't actively serving
    /// RDMA, so there is something to explain).
    pub diagnose: bool,
}

/// Map a classified NIC to a table row, dropping interfaces that aren't RDMA
/// candidates (virtual interfaces, IB-only netdevs). Shared with the dashboard.
pub(crate) fn nic_row(s: NicStatus) -> Option<NicRow> {
    let (status, dot, roce, soft_roce): (String, &'static str, bool, bool) = match &s.kind {
        NicRdmaKind::Active => ("RDMA active".into(), "dot-green", false, false),
        NicRdmaKind::Inactive => ("RDMA device down".into(), "dot-yellow", false, false),
        NicRdmaKind::CapableDisabled { vendor } => (
            format!("RoCE-capable ({vendor}), disabled"),
            "dot-red",
            true,
            false,
        ),
        NicRdmaKind::SoftRoceable => ("no RDMA".into(), "dot-gray", false, true),
        NicRdmaKind::Unsupported => return None,
    };
    // Anything that isn't actively serving RDMA has something to diagnose.
    let diagnose = !matches!(s.kind, NicRdmaKind::Active);
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
        roce,
        soft_roce,
        diagnose,
        netdev: s.netdev,
    })
}

// ---- NIC list page ----

/// One row of the NIC list: the RDMA-capability row plus a DHCP + link-state
/// column from the network-config read.
pub struct NicListRow {
    pub netdev: String,
    pub dot: &'static str,
    pub rdma: String,
    pub addrs: String,
    pub status: String,
    /// "yes" / "no" / "—" (unknown).
    pub dhcp: String,
    /// Operational state (e.g. `UP`/`DOWN`) or "—" when unknown.
    pub link: String,
}

pub struct NicListView {
    pub rows: Vec<NicListRow>,
}

#[derive(Template)]
#[template(path = "nic.html")]
struct NicTemplate {
    user: CurrentUser,
    view: NicListView,
}

async fn gather_list(state: &AppState) -> NicListView {
    let nets = nic::networks(&state.helper).await;
    let rows = nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter_map(nic_row)
        .map(|r| {
            let net = nets.get(&r.netdev);
            NicListRow {
                dhcp: net
                    .map(|n| if n.dhcp { "yes" } else { "no" }.to_owned())
                    .unwrap_or_else(|| "—".into()),
                link: net
                    .map(|n| n.operstate.clone())
                    .unwrap_or_else(|| "—".into()),
                netdev: r.netdev,
                dot: r.dot,
                rdma: r.rdma,
                addrs: r.addrs,
                status: r.status,
            }
        })
        .collect();
    NicListView { rows }
}

async fn nic_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    page(NicTemplate {
        user,
        view: gather_list(&state).await,
    })
}

// ---- Per-NIC detail page (network config, graphs, Enable RoCE / Soft-RoCE) ----

pub struct NicDetailView {
    /// `None` when no such RDMA-candidate interface exists on this host.
    pub nic: Option<NicRow>,
    /// The interface's network configuration, when the helper could read it.
    pub net: Option<NicNetwork>,
    pub netdev: String,
    /// Live Ethernet (netdev) traffic chart (received up / transmitted down).
    pub traffic_svg: String,
    /// The associated RDMA device's RoCE traffic (rx up / tx down). `None` when
    /// the NIC has no RDMA device or that device has no samples yet.
    pub roce_svg: Option<String>,
    /// Rendered only when the NIC exposes a temperature sensor.
    pub temp_svg: Option<String>,
    pub flash: Option<String>,
    /// The just-dispatched task to link from the flash notice (`/tasks/{id}`).
    pub task_id: Option<i64>,
    pub form_error: Option<String>,
    /// Set when the NIC's MTU is known and below a jumbo frame — a warning the
    /// detail page renders next to the MTU form.
    pub mtu_warning: Option<String>,
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

async fn gather_nic_detail(
    state: &AppState,
    netdev: &str,
    flash: Option<String>,
    form_error: Option<String>,
    task_id: Option<i64>,
) -> NicDetailView {
    let nic = nic::interfaces(&state.helper)
        .await
        .into_iter()
        .filter_map(nic_row)
        .find(|n| n.netdev == netdev);
    let net = nic::networks(&state.helper).await.remove(netdev);
    let mtu_warning = net
        .as_ref()
        .and_then(|n| n.mtu)
        .filter(|m| *m < JUMBO_MTU)
        .map(|m| {
            format!(
                "MTU {m} is below a jumbo frame ({JUMBO_MTU}). RDMA storage benefits \
             from jumbo frames or larger — set it on every host and switch on the path."
            )
        });
    let series = |suffix: &str| state.metrics.ring_series(&format!("nic:{netdev}:{suffix}"));
    let temp = series("temp_c");
    // RoCE traffic lives under the associated RDMA device (rdma:<dev>), separate
    // from the kernel netdev counters above; skip it when there's no device.
    let roce_svg = nic
        .as_ref()
        .map(|n| n.rdma.as_str())
        .filter(|dev| *dev != "—")
        .and_then(|dev| {
            let rx = state.metrics.ring_series(&format!("rdma:{dev}:rx_bps"));
            let tx = state.metrics.ring_series(&format!("rdma:{dev}:tx_bps"));
            (!rx.is_empty() || !tx.is_empty())
                .then(|| mirror_chart_svg(&rx, &tx, "Rx", "Tx", 600, 120, ChartUnit::Bytes))
        });
    NicDetailView {
        traffic_svg: mirror_chart_svg(
            &series("rx_bps"),
            &series("tx_bps"),
            "Rx",
            "Tx",
            600,
            120,
            ChartUnit::Bytes,
        ),
        roce_svg,
        temp_svg: (!temp.is_empty()).then(|| chart_svg(&temp, 600, 120, ChartUnit::Celsius)),
        nic,
        net,
        netdev: netdev.to_owned(),
        flash,
        task_id,
        form_error,
        mtu_warning,
    }
}

async fn nic_detail_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(netdev): Path<String>,
) -> Response {
    page(NicDetailTemplate {
        user,
        view: gather_nic_detail(&state, &netdev, None, None, None).await,
    })
}

// ---- Per-NIC Diagnose page (read-only RDMA-readiness checklist) ----

pub struct NicDiagnoseView {
    pub netdev: String,
    /// Short status line for the header (empty when the NIC isn't found).
    pub status: String,
    pub dot_class: &'static str,
    pub criteria: Vec<Criterion>,
    pub not_found: bool,
}

#[derive(Template)]
#[template(path = "nic_diagnose.html")]
struct NicDiagnoseTemplate {
    user: CurrentUser,
    view: NicDiagnoseView,
}

/// Build the diagnose view for `netdev`: the vendor-neutral structural checklist
/// plus whatever opaque advisory the helper supplied for this NIC.
async fn gather_nic_diagnose(
    helper: &crate::helper_client::HelperClient,
    netdev: &str,
) -> NicDiagnoseView {
    let Some(status) = nic::interfaces(helper)
        .await
        .into_iter()
        .find(|n| n.netdev == netdev)
    else {
        return NicDiagnoseView {
            netdev: netdev.to_owned(),
            status: String::new(),
            dot_class: "dot-gray",
            criteria: vec![],
            not_found: true,
        };
    };
    let advice = nic::rdma_advice(helper).await;
    let criteria = nic_diagnostics(&status, advice.get(netdev));
    // The header dot/label reuses the same per-row mapping as the table.
    let (status_text, dot_class) = nic_row(status.clone())
        .map(|r| (r.status, r.dot))
        .unwrap_or((String::new(), "dot-gray"));
    NicDiagnoseView {
        netdev: netdev.to_owned(),
        status: status_text,
        dot_class,
        criteria,
        not_found: false,
    }
}

async fn nic_diagnose_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Path(netdev): Path<String>,
) -> Response {
    page(NicDiagnoseTemplate {
        user,
        view: gather_nic_diagnose(&state.helper, &netdev).await,
    })
}

// ---- RoCE / Soft-RoCE enable actions ----

async fn enable_rxe(State(state): State<Arc<AppState>>, Path(netdev): Path<String>) -> Response {
    let Ok(netdev) = NetdevName::new(netdev.trim()) else {
        return page(NicDetailPartial {
            view: gather_nic_detail(
                &state,
                &netdev,
                None,
                Some(format!("invalid interface name {netdev:?}")),
                None,
            )
            .await,
        });
    };
    // One RxeAdd task: the helper loads the rxe module and adds the link in
    // order. The follow-up reconcile (a separate, idempotent intent) is chained
    // on the task's success from a background wait.
    let title = format!("enable Soft-RoCE on {netdev}");
    let id = match crate::task_runner::begin(&state, "rxe-add", &title) {
        Ok(id) => id,
        Err(e) => {
            return page(NicDetailPartial {
                view: gather_nic_detail(
                    &state,
                    netdev.as_str(),
                    None,
                    Some(format!("{e:#}")),
                    None,
                )
                .await,
            });
        }
    };
    let st = state.clone();
    let nd = netdev.clone();
    tokio::spawn(async move {
        let rx = st.helper.rxe_add(ops::RxeAdd { netdev: nd });
        let added = crate::task_runner::drive(&st, id, rx)
            .await
            .map(|o| o.ok)
            .unwrap_or(false);
        st.tasks.unregister(id);
        if added {
            let _ = reconcile_state(&st).await;
        }
    });
    page(NicDetailPartial {
        view: gather_nic_detail(
            &state,
            netdev.as_str(),
            Some(format!("started {title}")),
            None,
            Some(id),
        )
        .await,
    })
}

/// Turn on hardware RoCE for a NIC. The helper detects the vendor, confirms its
/// enable parameter is present and off (a VF may be PF-gated and can't
/// self-enable), then sets it and reloads the device — all as one task. The
/// reload briefly drops the NIC (which can drop the caller's own session), so it
/// runs non-blocking; exports re-realize over the now-RoCE NIC on the next
/// reconcile pass. The web names only the interface.
async fn set_roce(State(state): State<Arc<AppState>>, Path(netdev): Path<String>) -> Response {
    let Ok(netdev) = NetdevName::new(netdev.trim()) else {
        return page(NicDetailPartial {
            view: gather_nic_detail(
                &state,
                &netdev,
                None,
                Some(format!("invalid interface name {netdev:?}")),
                None,
            )
            .await,
        });
    };
    let title = format!("enable RoCE on {netdev}");
    let view = match crate::task_runner::start(
        &state,
        state.helper.enable_roce(ops::EnableRoce {
            netdev: netdev.clone(),
        }),
        "roce",
        &title,
    ) {
        Ok(id) => {
            gather_nic_detail(
                &state,
                netdev.as_str(),
                Some(format!(
                    "started {title}; reconnect if your session dropped"
                )),
                None,
                Some(id),
            )
            .await
        }
        Err(e) => {
            gather_nic_detail(&state, netdev.as_str(), None, Some(format!("{e:#}")), None).await
        }
    };
    page(NicDetailPartial { view })
}

// ---- Set MTU ----

#[derive(Deserialize)]
struct SetMtuForm {
    mtu: String,
}

/// Change a NIC's MTU. Unlike RoCE this doesn't reload the device — `ip link set
/// mtu` takes effect at once and doesn't drop the link — so it runs as a plain
/// task and the page stays put. The web only names the interface and the value;
/// the range check and the `ip` invocation live in the daemon.
async fn set_mtu(
    State(state): State<Arc<AppState>>,
    Path(netdev): Path<String>,
    Form(form): Form<SetMtuForm>,
) -> Response {
    let err = |msg: String| async {
        page(NicDetailPartial {
            view: gather_nic_detail(&state, &netdev, None, Some(msg), None).await,
        })
    };
    let Ok(name) = NetdevName::new(netdev.trim()) else {
        return err(format!("invalid interface name {netdev:?}")).await;
    };
    let Ok(mtu) = form.mtu.trim().parse::<u32>() else {
        return err(format!("invalid MTU {:?}", form.mtu)).await;
    };
    let title = format!("set MTU {mtu} on {name}");
    let view = match crate::task_runner::start(
        &state,
        state.helper.set_mtu(ops::SetMtu {
            netdev: name.clone(),
            mtu,
        }),
        "set-mtu",
        &title,
    ) {
        Ok(id) => {
            gather_nic_detail(
                &state,
                name.as_str(),
                Some(format!("started {title}")),
                None,
                Some(id),
            )
            .await
        }
        Err(e) => {
            gather_nic_detail(&state, name.as_str(), None, Some(format!("{e:#}")), None).await
        }
    };
    page(NicDetailPartial { view })
}

#[cfg(test)]
mod tests {
    use crate::routes::testutil::{form_post, login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

    #[tokio::test]
    async fn nic_list_detail_diagnose_and_roce_flow() {
        let app = test_app();
        let (cookie, csrf) = login(&app).await;
        let auth = |mut req: HttpRequest<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert("x-greendot-csrf", csrf.parse().unwrap());
            req
        };

        // The list page renders its NIC table.
        let req = auth(HttpRequest::get("/nic").body(Body::empty()).unwrap());
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Network interfaces"), "{body}");

        // The per-NIC page renders (a graceful not-found is fine in the test env).
        let req = auth(HttpRequest::get("/nic/eth0").body(Body::empty()).unwrap());
        let (status, _, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);

        // The Diagnose page renders its checklist / back link; a clearly
        // nonexistent interface takes the graceful not-found path.
        let req = auth(
            HttpRequest::get("/nic/eth0/diagnose")
                .body(Body::empty())
                .unwrap(),
        );
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Diagnose"), "{body}");
        assert!(body.contains("Back to NICs"), "{body}");
        let req = auth(
            HttpRequest::get("/nic/zzz999/diagnose")
                .body(Body::empty())
                .unwrap(),
        );
        let (_, _, body) = send(&app, req).await;
        assert!(body.contains("not found"), "{body}");

        // Soft-RoCE and RoCE enable round-trip through the fake helper; a
        // too-long (invalid) interface name is rejected before the helper runs.
        let (_, _, body) = send(&app, auth(form_post("/nic/eth0/rxe", ""))).await;
        assert!(body.contains("started enable Soft-RoCE on eth0"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/nic/eth0/roce", ""))).await;
        assert!(body.contains("started enable RoCE on eth0"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/nic/abcdefghijklmnop/roce", ""))).await;
        assert!(body.contains("invalid interface name"), "{body}");

        // Set MTU: a jumbo value dispatches the task; a non-numeric value and a
        // too-long interface name are both rejected before the helper runs.
        let (_, _, body) = send(&app, auth(form_post("/nic/eth0/mtu", "mtu=9000"))).await;
        assert!(body.contains("started set MTU 9000 on eth0"), "{body}");
        let (_, _, body) = send(&app, auth(form_post("/nic/eth0/mtu", "mtu=abc"))).await;
        assert!(body.contains("invalid MTU"), "{body}");
        let (_, _, body) = send(
            &app,
            auth(form_post("/nic/abcdefghijklmnop/mtu", "mtu=9000")),
        )
        .await;
        assert!(body.contains("invalid interface name"), "{body}");
    }
}
