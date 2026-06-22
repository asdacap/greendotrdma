use super::{AppState, page};
use crate::auth::CurrentUser;
use crate::metrics::{PromSample, chart_svg, render_prometheus};
use crate::{actual, dot};
use askama::Template;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use greendot_proto::DotState;
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/charts", get(charts_page))
}

pub struct ChartCard {
    pub title: String,
    pub svg: String,
}

pub struct ChartsView {
    pub live: bool,
    /// (label, is the active range)
    pub ranges: Vec<(&'static str, bool)>,
    pub cards: Vec<ChartCard>,
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
    let cards = state
        .metrics
        .series_names()
        .into_iter()
        .map(|series| {
            let points = match since {
                None => state.metrics.ring_series(&series),
                Some(since) => state
                    .metrics
                    .history(&series, since, now)
                    .unwrap_or_default(),
            };
            ChartCard {
                svg: chart_svg(&points, 600, 120),
                title: series,
            }
        })
        .collect();
    let ranges = ["live", "1h", "24h", "7d", "90d"]
        .map(|r| (r, r == range))
        .to_vec();
    page(ChartsTemplate {
        user,
        view: ChartsView {
            live: range == "live",
            ranges,
            cards,
        },
    })
}

/// Prometheus exposition; mounted without auth (read-only appliance metrics).
pub async fn prometheus(State(state): State<Arc<AppState>>) -> Response {
    let mut samples = Vec::new();
    for (key, value) in state.metrics.latest_raw() {
        // keys look like "disk:sda:read_bps" / "rdma:rxe0:rx_bps"
        let parts: Vec<&str> = key.split(':').collect();
        let (name, device) = match parts.as_slice() {
            ["disk", dev, "read_bps"] => ("greendot_disk_read_bytes_total", dev),
            ["disk", dev, "write_bps"] => ("greendot_disk_written_bytes_total", dev),
            ["rdma", dev, "rx_bps"] => ("greendot_rdma_received_bytes_total", dev),
            ["rdma", dev, "tx_bps"] => ("greendot_rdma_transmitted_bytes_total", dev),
            _ => continue,
        };
        samples.push(PromSample {
            name,
            labels: vec![("device", (*device).to_owned())],
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
        let nvmet = actual::nvmet::read(&state.nvmet_root);
        let lio = actual::lio::read(&state.lio_root);
        let rdma = actual::rdma::devices();
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
    use crate::routes::testutil::{login, send, test_app};
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode, header};

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

        // /charts is protected and renders for each known range.
        let (cookie, _) = login(&app).await;
        for range in ["", "?range=1h", "?range=7d"] {
            let req = HttpRequest::get(format!("/charts{range}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "{range}");
            assert!(body.contains("Charts"), "{range}: {body}");
        }
    }
}
