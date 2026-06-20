//! The 5-second collector: /sys/block I/O counters and RDMA port traffic
//! counters into the metrics store, with 1-min/1-hour rollup flushes.

use super::Metrics;
use crate::routes::AppState;
use std::path::Path;

/// `/sys/block/<dev>/stat`: (read bytes, written bytes). Sector counts are
/// fields 2 and 6 (0-based), always in 512-byte units.
pub fn parse_block_stat(stat: &str) -> Option<(u64, u64)> {
    let fields: Vec<&str> = stat.split_whitespace().collect();
    let read: u64 = fields.get(2)?.parse().ok()?;
    let written: u64 = fields.get(6)?.parse().ok()?;
    Some((read * 512, written * 512))
}

/// RDMA port data counters are in 4-byte lane words.
pub fn rdma_counter_bytes(raw: &str) -> Option<u64> {
    raw.trim().parse::<u64>().ok().map(|words| words * 4)
}

fn read_dir_names(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn collect_block(metrics: &Metrics, root: &Path, ts: i64) {
    for dev in read_dir_names(root) {
        if dev.starts_with("ram") || dev.starts_with("sr") {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(root.join(&dev).join("stat")) else {
            continue;
        };
        if let Some((read, written)) = parse_block_stat(&stat) {
            metrics.push_counter(&format!("disk:{dev}:read_bps"), ts, read);
            metrics.push_counter(&format!("disk:{dev}:write_bps"), ts, written);
        }
    }
}

fn collect_rdma(metrics: &Metrics, root: &Path, ts: i64) {
    for dev in read_dir_names(root) {
        for port in read_dir_names(&root.join(&dev).join("ports")) {
            let counters = root.join(&dev).join("ports").join(&port).join("counters");
            for (file, dir) in [("port_rcv_data", "rx"), ("port_xmit_data", "tx")] {
                if let Ok(raw) = std::fs::read_to_string(counters.join(file))
                    && let Some(bytes) = rdma_counter_bytes(&raw)
                {
                    metrics.push_counter(&format!("rdma:{dev}:{dir}_bps"), ts, bytes);
                }
            }
        }
    }
}

async fn collect_pools(metrics: &Metrics, ts: i64) {
    if let Ok(Some(pools)) = crate::actual::zfs::pools().await {
        for pool in pools {
            let used = pool.alloc as f64 / pool.size.max(1) as f64 * 100.0;
            metrics.push(&format!("pool:{}:used_percent", pool.name), ts, used);
        }
    }
}

/// The background task. Pool stats and rollup flushes happen on minute
/// boundaries; hourly rollups on hour boundaries.
pub async fn collector(state: std::sync::Arc<AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut last_minute = 0;
    let mut last_hour = 0;
    loop {
        tick.tick().await;
        let ts = chrono::Utc::now().timestamp();
        collect_block(&state.metrics, Path::new("/sys/block"), ts);
        collect_rdma(&state.metrics, Path::new("/sys/class/infiniband"), ts);
        if ts / 60 != last_minute {
            last_minute = ts / 60;
            collect_pools(&state.metrics, ts).await;
            if let Err(e) = state.metrics.flush("samples_1m", ts) {
                tracing::error!(error = %e, "minute metrics flush failed");
            }
        }
        if ts / 3600 != last_hour {
            last_hour = ts / 3600;
            if let Err(e) = state.metrics.flush("samples_1h", ts) {
                tracing::error!(error = %e, "hourly metrics flush failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::real_stat(
        "53055 12109 4731234 13284 41571 53354 2839906 110806 0 64468 138755 0 0 0 0 5374 14664",
        Some((4731234 * 512, 2839906 * 512))
    )]
    #[case::short("1 2", None)]
    #[case::garbage("a b c d e f g h", None)]
    fn block_stat_parsing(#[case] stat: &str, #[case] expected: Option<(u64, u64)>) {
        assert_eq!(parse_block_stat(stat), expected);
    }

    #[test]
    fn rdma_counters_scale_by_lane_word_and_sysfs_walk_works() {
        assert_eq!(rdma_counter_bytes("250\n"), Some(1000));
        assert_eq!(rdma_counter_bytes("junk"), None);

        let tmp = std::env::temp_dir().join(format!("gd-metrics{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let counters = tmp.join("ib/rxe0/ports/1/counters");
        std::fs::create_dir_all(&counters).unwrap();
        std::fs::write(counters.join("port_rcv_data"), "100\n").unwrap();
        std::fs::write(counters.join("port_xmit_data"), "200\n").unwrap();
        let block = tmp.join("block/sda");
        std::fs::create_dir_all(&block).unwrap();
        std::fs::write(block.join("stat"), "0 0 100 0 0 0 200 0 0 0 0\n").unwrap();

        let metrics = Metrics::in_memory().unwrap();
        // Two passes so rates exist.
        collect_rdma(&metrics, &tmp.join("ib"), 100);
        collect_block(&metrics, &tmp.join("block"), 100);
        std::fs::write(counters.join("port_rcv_data"), "350\n").unwrap();
        std::fs::write(block.join("stat"), "0 0 1124 0 0 0 200 0 0 0 0\n").unwrap();
        collect_rdma(&metrics, &tmp.join("ib"), 105);
        collect_block(&metrics, &tmp.join("block"), 105);

        assert_eq!(metrics.ring_series("rdma:rxe0:rx_bps"), vec![(105, 200.0)]); // (350-100)*4/5
        assert_eq!(
            metrics.ring_series("disk:sda:read_bps"),
            vec![(105, (1024.0 * 512.0) / 5.0)]
        );
        assert_eq!(metrics.ring_series("disk:sda:write_bps"), vec![(105, 0.0)]);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
