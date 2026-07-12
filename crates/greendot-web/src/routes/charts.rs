use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::dot::DotState;
use crate::metrics::{ChartUnit, PromSample, chart_svg, render_prometheus};
use crate::{actual, dot};
use askama::Template;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/charts", get(charts_page))
}

pub struct ChartCard {
    pub title: String,
    pub svg: String,
}

/// One resource-type section (Disks / RDMA links / Pools) of the page.
pub struct ChartGroup {
    pub heading: &'static str,
    pub cards: Vec<ChartCard>,
}

/// A time-range link; `href` preserves the active metric filter.
pub struct RangeLink {
    pub label: &'static str,
    pub active: bool,
    pub href: String,
}

/// A metric-type filter chip; clicking toggles it in/out of the URL.
pub struct MetricChip {
    pub label: &'static str,
    pub active: bool,
    pub href: String,
}

pub struct ChartsView {
    pub live: bool,
    pub ranges: Vec<RangeLink>,
    pub chips: Vec<MetricChip>,
    pub groups: Vec<ChartGroup>,
    /// The current URL, so the live htmx poll re-requests the same filtered view.
    pub refresh_url: String,
}

/// Coarse metric class the user can filter by. Several series suffixes map to
/// one kind (rx/tx → Network).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MetricKind {
    Read,
    Write,
    Temp,
    Network,
    Util,
}

const CHIP_ORDER: [MetricKind; 5] = [
    MetricKind::Read,
    MetricKind::Write,
    MetricKind::Temp,
    MetricKind::Network,
    MetricKind::Util,
];

/// Sections in display order: (series category, heading).
const CATEGORIES: [(&str, &str); 3] =
    [("disk", "Disks"), ("rdma", "RDMA links"), ("pool", "Pools")];

impl MetricKind {
    fn slug(self) -> &'static str {
        match self {
            MetricKind::Read => "read",
            MetricKind::Write => "write",
            MetricKind::Temp => "temp",
            MetricKind::Network => "network",
            MetricKind::Util => "util",
        }
    }

    fn label(self) -> &'static str {
        match self {
            MetricKind::Read => "Read",
            MetricKind::Write => "Write",
            MetricKind::Temp => "Temperature",
            MetricKind::Network => "Network",
            MetricKind::Util => "Utilization",
        }
    }

    fn from_slug(s: &str) -> Option<MetricKind> {
        CHIP_ORDER.into_iter().find(|k| k.slug() == s)
    }

    /// Classifies a series' metric suffix (`read_bps`, `temp_c`, …).
    fn of_suffix(suffix: &str) -> Option<MetricKind> {
        match suffix {
            "read_bps" => Some(MetricKind::Read),
            "write_bps" => Some(MetricKind::Write),
            "temp_c" => Some(MetricKind::Temp),
            "rx_bps" | "tx_bps" => Some(MetricKind::Network),
            "used_percent" => Some(MetricKind::Util),
            _ => None,
        }
    }
}

/// Card-title suffix and per-category display order for a series suffix.
fn suffix_label(suffix: &str) -> (&'static str, u8) {
    match suffix {
        "read_bps" => ("read", 0),
        "rx_bps" => ("rx", 0),
        "write_bps" => ("write", 1),
        "tx_bps" => ("tx", 1),
        "temp_c" => ("temperature", 2),
        "used_percent" => ("used %", 2),
        _ => ("?", 9),
    }
}

/// `/charts` URL for the given range and active filter set, in canonical order.
fn charts_url(range: &str, kinds: &[MetricKind]) -> String {
    let mut parts = Vec::new();
    if range != "live" {
        parts.push(format!("range={range}"));
    }
    let slugs: Vec<&str> = CHIP_ORDER
        .iter()
        .filter(|k| kinds.contains(k))
        .map(|k| k.slug())
        .collect();
    if !slugs.is_empty() {
        parts.push(format!("metric={}", slugs.join(",")));
    }
    if parts.is_empty() {
        "/charts".to_owned()
    } else {
        format!("/charts?{}", parts.join("&"))
    }
}

#[derive(Template)]
#[template(path = "charts.html")]
struct ChartsTemplate {
    user: CurrentUser,
    view: ChartsView,
}

#[derive(Deserialize)]
pub struct RangeQuery {
    #[serde(default)]
    range: String,
    #[serde(default)]
    metric: String,
}

async fn charts_page(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<RangeQuery>,
) -> Response {
    let now = chrono::Utc::now().timestamp();
    let (range, since) = match query.range.as_str() {
        "1h" => ("1h", Some(now - 3600)),
        "24h" => ("24h", Some(now - 86400)),
        "7d" => ("7d", Some(now - 7 * 86400)),
        "90d" => ("90d", Some(now - 90 * 86400)),
        _ => ("live", None),
    };
    let active: Vec<MetricKind> = query
        .metric
        .split(',')
        .filter_map(MetricKind::from_slug)
        .collect();

    let names = state.metrics.series_names();
    let groups = CATEGORIES
        .into_iter()
        .filter_map(|(cat, heading)| {
            // (target, suffix) for series in this category passing the filter.
            let mut entries: Vec<(&str, &str)> = names
                .iter()
                .filter_map(|s| match s.split(':').collect::<Vec<_>>()[..] {
                    [c, target, suffix] if c == cat => {
                        let kind = MetricKind::of_suffix(suffix)?;
                        (active.is_empty() || active.contains(&kind)).then_some((target, suffix))
                    }
                    _ => None,
                })
                .collect();
            entries.sort_by(|a, b| {
                a.0.cmp(b.0)
                    .then(suffix_label(a.1).1.cmp(&suffix_label(b.1).1))
            });
            let cards: Vec<ChartCard> = entries
                .into_iter()
                .map(|(target, suffix)| {
                    let series = format!("{cat}:{target}:{suffix}");
                    let points = match since {
                        None => state.metrics.ring_series(&series),
                        Some(since) => state
                            .metrics
                            .history(&series, since, now)
                            .unwrap_or_default(),
                    };
                    ChartCard {
                        svg: chart_svg(&points, 600, 120, ChartUnit::for_series(&series)),
                        title: format!("{target} · {}", suffix_label(suffix).0),
                    }
                })
                .collect();
            (!cards.is_empty()).then_some(ChartGroup { heading, cards })
        })
        .collect();

    let ranges = ["live", "1h", "24h", "7d", "90d"]
        .into_iter()
        .map(|r| RangeLink {
            label: r,
            active: r == range,
            href: charts_url(r, &active),
        })
        .collect();
    // "All" clears the filter; each metric chip toggles itself.
    let chips = std::iter::once(MetricChip {
        label: "All",
        active: active.is_empty(),
        href: charts_url(range, &[]),
    })
    .chain(CHIP_ORDER.into_iter().map(|k| {
        let on = active.contains(&k);
        let mut next: Vec<MetricKind> = active.iter().copied().filter(|&x| x != k).collect();
        if !on {
            next.push(k);
        }
        MetricChip {
            label: k.label(),
            active: on,
            href: charts_url(range, &next),
        }
    }))
    .collect();

    page(ChartsTemplate {
        user,
        view: ChartsView {
            live: range == "live",
            ranges,
            chips,
            groups,
            refresh_url: charts_url(range, &active),
        },
    })
}

/// Prometheus exposition; mounted without auth (read-only appliance metrics).
pub async fn prometheus(State(state): State<Arc<AppState>>) -> Response {
    let mut samples = Vec::new();
    for (key, value) in state.metrics.latest_raw() {
        // keys look like "disk:sda:read_bps" / "rdma:rxe0:rx_bps" / "pool:tank:read_bps"
        let parts: Vec<&str> = key.split(':').collect();
        let (name, label, target) = match parts.as_slice() {
            ["disk", dev, "read_bps"] => ("greendot_disk_read_bytes_total", "device", dev),
            ["disk", dev, "write_bps"] => ("greendot_disk_written_bytes_total", "device", dev),
            ["rdma", dev, "rx_bps"] => ("greendot_rdma_received_bytes_total", "device", dev),
            ["rdma", dev, "tx_bps"] => ("greendot_rdma_transmitted_bytes_total", "device", dev),
            ["pool", pool, "read_bps"] => ("greendot_pool_read_bytes_total", "pool", pool),
            ["pool", pool, "write_bps"] => ("greendot_pool_written_bytes_total", "pool", pool),
            _ => continue,
        };
        samples.push(PromSample {
            name,
            labels: vec![(label, (*target).to_owned())],
            value: value as f64,
        });
    }
    if let Ok(Some(pools)) = actual::zfs::pools().await {
        for pool in pools {
            for (name, value) in [
                ("greendot_pool_size_bytes", pool.size as f64),
                ("greendot_pool_allocated_bytes", pool.alloc as f64),
                (
                    "greendot_pool_online",
                    f64::from(u8::from(pool.health == "ONLINE")),
                ),
            ] {
                samples.push(PromSample {
                    name,
                    labels: vec![("pool", pool.name.clone())],
                    value,
                });
            }
        }
    }
    {
        let nvmet = actual::nvmet::read(&state.helper).await;
        let lio = actual::lio::read(&state.helper).await;
        let rdma = actual::rdma::devices(&state.helper).await;
        let status_value = |d: dot::Dot| match d.state {
            DotState::Green => 2.0,
            DotState::Yellow => 1.0,
            DotState::Red => 0.0,
        };
        let mut push = |name: String, value: f64| {
            samples.push(PromSample {
                name: "greendot_export_status",
                labels: vec![("export", name)],
                value,
            });
        };
        if let Ok(exports) = state.db.list_nvme_exports() {
            for e in exports.iter().filter(|e| e.enabled) {
                push(
                    e.name.clone(),
                    status_value(dot::nvme_dot(e, &nvmet, &rdma)),
                );
            }
        }
        if let Ok(exports) = state.db.list_iscsi_exports() {
            for e in exports.iter().filter(|e| e.enabled) {
                push(e.name.clone(), status_value(dot::iscsi_dot(e, &lio, &rdma)));
            }
        }
    }
    samples.sort_by(|a, b| (a.name, &a.labels).cmp(&(b.name, &b.labels)));
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_prometheus(&samples),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{CHIP_ORDER, MetricKind, charts_url};
    use crate::routes::testutil::{login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};
    use rstest::rstest;

    #[tokio::test]
    async fn charts_page_and_unauthenticated_prometheus_endpoint() {
        let app = test_app();

        // /metrics needs no session.
        let req = HttpRequest::get("/metrics").body(Body::empty()).unwrap();
        let (status, headers, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/plain")
        );

        // /charts is protected and renders for each range and with a filter.
        let (cookie, _) = login(&app).await;
        for query in ["", "?range=1h", "?range=7d", "?metric=read,write"] {
            let req = HttpRequest::get(format!("/charts{query}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "{query}");
            assert!(body.contains("Charts"), "{query}: {body}");
            // The metric filter chips always render.
            assert!(body.contains(r#"class="chip"#), "{query}: {body}");
        }
    }

    #[rstest]
    #[case::read("disk:sda:read_bps", Some(MetricKind::Read))]
    #[case::write("pool:tank:write_bps", Some(MetricKind::Write))]
    #[case::temp("disk:nvme0n1:temp_c", Some(MetricKind::Temp))]
    #[case::rx("rdma:rxe0:rx_bps", Some(MetricKind::Network))]
    #[case::tx("rdma:rxe0:tx_bps", Some(MetricKind::Network))]
    #[case::util("pool:tank:used_percent", Some(MetricKind::Util))]
    #[case::unknown("pool:tank:mystery", None)]
    fn suffix_classifies_into_a_filter_kind(
        #[case] series: &str,
        #[case] want: Option<MetricKind>,
    ) {
        let suffix = series.rsplit(':').next().unwrap();
        assert_eq!(MetricKind::of_suffix(suffix), want);
    }

    #[test]
    fn urls_carry_range_and_filter_and_chips_round_trip() {
        // Live + no filter is the bare path; range and metric append in order.
        assert_eq!(charts_url("live", &[]), "/charts");
        assert_eq!(
            charts_url("1h", &[MetricKind::Read]),
            "/charts?range=1h&metric=read"
        );
        // Slugs are emitted in canonical CHIP_ORDER regardless of input order.
        assert_eq!(
            charts_url("live", &[MetricKind::Util, MetricKind::Read]),
            "/charts?metric=read,util"
        );
        // Every chip slug round-trips through from_slug.
        for k in CHIP_ORDER {
            assert_eq!(MetricKind::from_slug(k.slug()), Some(k));
        }
        assert_eq!(MetricKind::from_slug("nope"), None);
    }
}
