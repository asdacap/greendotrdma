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

/// `/sys/class/hwmon/hwmonN/temp1_input` is milli-°C → °C.
pub fn parse_temp_millis(raw: &str) -> Option<f64> {
    raw.trim().parse::<i64>().ok().map(|m| m as f64 / 1000.0)
}

/// `nvme0n1`-style namespace name (controller digits + `n` + namespace digits;
/// no partition suffix). Used to find the block device behind an NVMe hwmon.
fn is_nvme_namespace(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("nvme") else {
        return false;
    };
    let mut parts = rest.splitn(2, 'n');
    let ctrl = parts.next().unwrap_or("");
    let ns = parts.next().unwrap_or("");
    !ctrl.is_empty()
        && ctrl.bytes().all(|b| b.is_ascii_digit())
        && !ns.is_empty()
        && ns.bytes().all(|b| b.is_ascii_digit())
}

/// The block device a hwmon entry measures: `drivetemp` (SATA/SAS) exposes it
/// under `device/block/<sdX>`; `nvme` exposes the namespace directly under
/// `device/<nvmeXnY>`. Pure sysfs walking — no device-vendor knowledge.
fn hwmon_block_device(hwmon_dir: &Path) -> Option<String> {
    let device = hwmon_dir.join("device");
    if let Some(name) = read_dir_names(&device.join("block")).into_iter().next() {
        return Some(name);
    }
    read_dir_names(&device)
        .into_iter()
        .find(|n| is_nvme_namespace(n))
}

/// Pushes a `disk:<dev>:temp_c` gauge for every `drivetemp`/`nvme` hwmon that
/// resolves to a block device. Hosts without `drivetemp` simply yield no SATA
/// temp series.
fn collect_drive_temp(metrics: &Metrics, hwmon_root: &Path, ts: i64) {
    for hw in read_dir_names(hwmon_root) {
        let dir = hwmon_root.join(&hw);
        let name = std::fs::read_to_string(dir.join("name")).unwrap_or_default();
        if !matches!(name.trim(), "drivetemp" | "nvme") {
            continue;
        }
        let Some(dev) = hwmon_block_device(&dir) else {
            continue;
        };
        if let Ok(raw) = std::fs::read_to_string(dir.join("temp1_input"))
            && let Some(celsius) = parse_temp_millis(&raw)
        {
            metrics.push(&format!("disk:{dev}:temp_c"), ts, celsius);
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
        collect_drive_temp(&state.metrics, Path::new("/sys/class/hwmon"), ts);
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

    #[rstest]
    #[case::celsius("38000\n", Some(38.0))]
    #[case::fractional("45250", Some(45.25))]
    #[case::garbage("warm", None)]
    fn temp_millis_parsing(#[case] raw: &str, #[case] expected: Option<f64>) {
        assert_eq!(parse_temp_millis(raw), expected);
    }

    #[test]
    fn drive_temp_resolves_drivetemp_and_nvme_block_devices() {
        let tmp = std::env::temp_dir().join(format!("gd-hwmon{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // SATA drive: drivetemp exposes the disk under device/block/sda.
        let sata = tmp.join("hwmon0");
        std::fs::create_dir_all(sata.join("device/block/sda")).unwrap();
        std::fs::write(sata.join("name"), "drivetemp\n").unwrap();
        std::fs::write(sata.join("temp1_input"), "38000\n").unwrap();
        // NVMe: namespace sits directly under device/nvme0n1.
        let nvme = tmp.join("hwmon1");
        std::fs::create_dir_all(nvme.join("device/nvme0n1")).unwrap();
        std::fs::write(nvme.join("name"), "nvme\n").unwrap();
        std::fs::write(nvme.join("temp1_input"), "45000\n").unwrap();
        // A non-disk sensor (CPU) is ignored.
        let cpu = tmp.join("hwmon2");
        std::fs::create_dir_all(&cpu).unwrap();
        std::fs::write(cpu.join("name"), "k10temp\n").unwrap();
        std::fs::write(cpu.join("temp1_input"), "55000\n").unwrap();

        let metrics = Metrics::in_memory().unwrap();
        collect_drive_temp(&metrics, &tmp, 100);
        assert_eq!(metrics.ring_series("disk:sda:temp_c"), vec![(100, 38.0)]);
        assert_eq!(
            metrics.ring_series("disk:nvme0n1:temp_c"),
            vec![(100, 45.0)]
        );
        assert!(
            metrics
                .series_names()
                .iter()
                .all(|s| !s.contains("k10temp"))
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
