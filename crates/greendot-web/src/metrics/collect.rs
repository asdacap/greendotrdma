//! The 5-second collector: /sys/block I/O counters, RDMA port traffic
//! counters, and per-ZFS-pool objset I/O counters into the metrics store,
//! with 1-min/1-hour rollup flushes.

use super::Metrics;
use crate::routes::AppState;
use std::path::Path;

/// The `/sys/block/<dev>/stat` fields we chart. All are monotonic counters
/// except `in_flight`, which is an instantaneous gauge.
pub struct BlockStat {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ios: u64,
    pub write_ios: u64,
    /// I/Os currently in progress — the live queue depth.
    pub in_flight: u64,
    /// Cumulative ms the device has been busy; its ms/s rate ×0.1 is %util.
    pub io_ticks: u64,
}

/// Parses `/sys/block/<dev>/stat`. Field order (0-based): read I/Os (0),
/// read sectors (2), write I/Os (4), write sectors (6), in-flight (8),
/// io_ticks ms (9); sectors are always 512-byte units.
pub fn parse_block_stat(stat: &str) -> Option<BlockStat> {
    let fields: Vec<&str> = stat.split_whitespace().collect();
    let field = |i: usize| fields.get(i)?.parse::<u64>().ok();
    Some(BlockStat {
        read_ios: field(0)?,
        read_bytes: field(2)? * 512,
        write_ios: field(4)?,
        write_bytes: field(6)? * 512,
        in_flight: field(8)?,
        io_ticks: field(9)?,
    })
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
        if let Some(s) = parse_block_stat(&stat) {
            metrics.push_counter(&format!("disk:{dev}:read_bps"), ts, s.read_bytes);
            metrics.push_counter(&format!("disk:{dev}:write_bps"), ts, s.write_bytes);
            metrics.push_counter(&format!("disk:{dev}:read_iops"), ts, s.read_ios);
            metrics.push_counter(&format!("disk:{dev}:write_iops"), ts, s.write_ios);
            // in_flight is a gauge; io_ticks (ms busy) → %util via ms/s ×0.1.
            metrics.push(&format!("disk:{dev}:queue_depth"), ts, s.in_flight as f64);
            metrics.push_counter_scaled(&format!("disk:{dev}:util_percent"), ts, s.io_ticks, 0.1);
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

/// One value from a kstat table: lines are `name type data` triples after a
/// two-line header.
fn kstat_field(kstat: &str, name: &str) -> Option<u64> {
    kstat.lines().find_map(|line| {
        let mut f = line.split_whitespace();
        if f.next() != Some(name) {
            return None;
        }
        f.nth(1)?.parse().ok()
    })
}

/// Sums the byte (`nread`/`nwritten`) and op (`reads`/`writes`) counters of
/// every `/proc/spl/kstat/zfs/<pool>/objset-*` dataset kstat into per-pool
/// `pool:<name>:read_bps`/`write_bps` and `read_iops`/`write_iops` counters. A
/// destroyed dataset makes a sum dip, which push_counter treats as a reset and
/// skips one sample.
fn collect_pool_io(metrics: &Metrics, root: &Path, ts: i64) {
    for pool in read_dir_names(root) {
        let dir = root.join(&pool);
        let (mut read, mut written, mut read_ops, mut write_ops, mut seen) =
            (0u64, 0u64, 0u64, 0u64, false);
        for objset in read_dir_names(&dir) {
            if !objset.starts_with("objset-") {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(dir.join(&objset))
                && let (Some(r), Some(w)) =
                    (kstat_field(&raw, "nread"), kstat_field(&raw, "nwritten"))
            {
                read += r;
                written += w;
                read_ops += kstat_field(&raw, "reads").unwrap_or(0);
                write_ops += kstat_field(&raw, "writes").unwrap_or(0);
                seen = true;
            }
        }
        if seen {
            metrics.push_counter(&format!("pool:{pool}:read_bps"), ts, read);
            metrics.push_counter(&format!("pool:{pool}:write_bps"), ts, written);
            metrics.push_counter(&format!("pool:{pool}:read_iops"), ts, read_ops);
            metrics.push_counter(&format!("pool:{pool}:write_iops"), ts, write_ops);
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

/// Per-physical-NIC ethernet byte counters from
/// `/sys/class/net/<dev>/statistics/{rx_bytes,tx_bytes}` into
/// `nic:<dev>:rx_bps`/`write_bps`. Only interfaces with a PCI `device` symlink
/// (physical NICs) are counted, so veth/bridge/loopback noise is skipped. Pure
/// sysfs walking — no vendor knowledge.
fn collect_nic_traffic(metrics: &Metrics, net_root: &Path, ts: i64) {
    for dev in read_dir_names(net_root) {
        let dir = net_root.join(&dev);
        if dev == "lo" || dir.join("device").symlink_metadata().is_err() {
            continue;
        }
        for (file, label) in [("rx_bytes", "rx"), ("tx_bytes", "tx")] {
            if let Ok(raw) = std::fs::read_to_string(dir.join("statistics").join(file))
                && let Ok(bytes) = raw.trim().parse::<u64>()
            {
                metrics.push_counter(&format!("nic:{dev}:{label}_bps"), ts, bytes);
            }
        }
    }
}

/// Best-effort per-NIC temperature: the first
/// `/sys/class/net/<dev>/device/hwmon/hwmon*/temp*_input` (milli-°C) into a
/// `nic:<dev>:temp_c` gauge. Many NICs expose a sensor via their PCI device's
/// hwmon; hosts/NICs without one simply yield no series. Vendor-neutral.
fn collect_nic_temp(metrics: &Metrics, net_root: &Path, ts: i64) {
    for dev in read_dir_names(net_root) {
        if dev == "lo" {
            continue;
        }
        let hwmon_root = net_root.join(&dev).join("device").join("hwmon");
        let Some(celsius) = read_dir_names(&hwmon_root).into_iter().find_map(|hw| {
            let hwdir = hwmon_root.join(&hw);
            read_dir_names(&hwdir)
                .into_iter()
                .filter(|f| f.starts_with("temp") && f.ends_with("_input"))
                .min()
                .and_then(|f| std::fs::read_to_string(hwdir.join(f)).ok())
                .and_then(|raw| parse_temp_millis(&raw))
        }) else {
            continue;
        };
        metrics.push(&format!("nic:{dev}:temp_c"), ts, celsius);
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
        collect_nic_traffic(&state.metrics, Path::new("/sys/class/net"), ts);
        collect_nic_temp(&state.metrics, Path::new("/sys/class/net"), ts);
        collect_pool_io(&state.metrics, Path::new("/proc/spl/kstat/zfs"), ts);
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

    #[test]
    fn block_stat_parses_charted_fields_and_rejects_bad_input() {
        let s = parse_block_stat(
            "53055 12109 4731234 13284 41571 53354 2839906 110806 0 64468 138755 0 0 0 0 5374 14664",
        )
        .unwrap();
        assert_eq!(
            (
                s.read_bytes,
                s.write_bytes,
                s.read_ios,
                s.write_ios,
                s.in_flight,
                s.io_ticks,
            ),
            (4731234 * 512, 2839906 * 512, 53055, 41571, 0, 64468)
        );
        // Too few fields, or a non-numeric field before io_ticks → nothing.
        assert!(parse_block_stat("1 2").is_none());
        assert!(parse_block_stat("a b c d e f g h i j").is_none());
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
        // Fields: read_ios(0) .. read_sectors(2) .. write_ios(4) .. write_sectors(6)
        // .. in_flight(8) io_ticks(9).
        std::fs::write(block.join("stat"), "10 0 100 0 5 0 200 0 3 1000 0\n").unwrap();

        let metrics = Metrics::in_memory().unwrap();
        // Two passes so rates exist.
        collect_rdma(&metrics, &tmp.join("ib"), 100);
        collect_block(&metrics, &tmp.join("block"), 100);
        std::fs::write(counters.join("port_rcv_data"), "350\n").unwrap();
        std::fs::write(block.join("stat"), "30 0 1124 0 15 0 200 0 7 1500 0\n").unwrap();
        collect_rdma(&metrics, &tmp.join("ib"), 105);
        collect_block(&metrics, &tmp.join("block"), 105);

        assert_eq!(metrics.ring_series("rdma:rxe0:rx_bps"), vec![(105, 200.0)]); // (350-100)*4/5
        assert_eq!(
            metrics.ring_series("disk:sda:read_bps"),
            vec![(105, (1024.0 * 512.0) / 5.0)]
        );
        assert_eq!(metrics.ring_series("disk:sda:write_bps"), vec![(105, 0.0)]);
        // read/write IOPS are op-count rates; in_flight is a per-pass gauge;
        // io_ticks (1000→1500 ms over 5s = 100 ms/s) ×0.1 = 10 %util.
        assert_eq!(metrics.ring_series("disk:sda:read_iops"), vec![(105, 4.0)]);
        assert_eq!(metrics.ring_series("disk:sda:write_iops"), vec![(105, 2.0)]);
        assert_eq!(
            metrics.ring_series("disk:sda:queue_depth"),
            vec![(100, 3.0), (105, 7.0)]
        );
        assert_eq!(
            metrics.ring_series("disk:sda:util_percent"),
            vec![(105, 10.0)]
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Real objset kstat shape: header, then `name type data` triples.
    fn objset(dataset: &str, nread: u64, nwritten: u64) -> String {
        format!(
            "36 1 0x01 7 2160 5342936343 5342936343\n\
             name                            type data\n\
             dataset_name                    7    {dataset}\n\
             writes                          4    10\n\
             nwritten                        4    {nwritten}\n\
             reads                           4    5\n\
             nread                           4    {nread}\n\
             nunlinks                        4    0\n"
        )
    }

    #[test]
    fn pool_io_sums_objsets_per_pool_and_skips_non_pool_entries() {
        let tmp = std::env::temp_dir().join(format!("gd-zpoolio{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let pool = tmp.join("tank");
        std::fs::create_dir_all(&pool).unwrap();
        std::fs::write(pool.join("objset-0x36"), objset("tank", 100, 200)).unwrap();
        std::fs::write(pool.join("objset-0x37"), objset("tank/vm1", 50, 25)).unwrap();
        // Non-objset pool entries and top-level plain files (arcstats) are ignored.
        std::fs::write(pool.join("state"), "ONLINE\n").unwrap();
        std::fs::write(tmp.join("arcstats"), "garbage\n").unwrap();

        let metrics = Metrics::in_memory().unwrap();
        // Two passes so rates exist: +250 read, +100 written over 5s.
        collect_pool_io(&metrics, &tmp, 100);
        std::fs::write(pool.join("objset-0x36"), objset("tank", 300, 300)).unwrap();
        std::fs::write(pool.join("objset-0x37"), objset("tank/vm1", 100, 25)).unwrap();
        collect_pool_io(&metrics, &tmp, 105);

        assert_eq!(metrics.ring_series("pool:tank:read_bps"), vec![(105, 50.0)]);
        assert_eq!(
            metrics.ring_series("pool:tank:write_bps"),
            vec![(105, 20.0)]
        );
        // Op counters are constant across passes in this fixture → 0/s rate,
        // but the series are still produced.
        assert_eq!(metrics.ring_series("pool:tank:read_iops"), vec![(105, 0.0)]);
        assert_eq!(
            metrics.ring_series("pool:tank:write_iops"),
            vec![(105, 0.0)]
        );
        assert_eq!(
            metrics.series_names(),
            vec![
                "pool:tank:read_bps",
                "pool:tank:read_iops",
                "pool:tank:write_bps",
                "pool:tank:write_iops",
            ],
            "no series from arcstats or the state file"
        );
        assert_eq!(kstat_field("name type data\nnread 4 junk\n", "nread"), None);
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
    fn nic_traffic_counts_physical_only_and_temp_reads_device_hwmon() {
        let tmp = std::env::temp_dir().join(format!("gd-nicmetrics{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // eth0: physical (has a `device` dir), with byte counters and a NIC temp
        // sensor under device/hwmon/hwmon5/temp1_input.
        let eth0 = tmp.join("eth0");
        std::fs::create_dir_all(eth0.join("statistics")).unwrap();
        std::fs::create_dir_all(eth0.join("device/hwmon/hwmon5")).unwrap();
        std::fs::write(eth0.join("statistics/rx_bytes"), "1000\n").unwrap();
        std::fs::write(eth0.join("statistics/tx_bytes"), "2000\n").unwrap();
        std::fs::write(eth0.join("device/hwmon/hwmon5/temp1_input"), "52000\n").unwrap();
        // br0: virtual (no `device`) — must produce no traffic series.
        let br0 = tmp.join("br0");
        std::fs::create_dir_all(br0.join("statistics")).unwrap();
        std::fs::write(br0.join("statistics/rx_bytes"), "500\n").unwrap();
        std::fs::write(br0.join("statistics/tx_bytes"), "500\n").unwrap();
        // lo: excluded.
        std::fs::create_dir_all(tmp.join("lo/statistics")).unwrap();

        let metrics = Metrics::in_memory().unwrap();
        // Two passes so counter rates exist: +2500 rx, +5000 tx over 5s.
        collect_nic_traffic(&metrics, &tmp, 100);
        collect_nic_temp(&metrics, &tmp, 100);
        std::fs::write(eth0.join("statistics/rx_bytes"), "3500\n").unwrap();
        std::fs::write(eth0.join("statistics/tx_bytes"), "7000\n").unwrap();
        collect_nic_traffic(&metrics, &tmp, 105);

        assert_eq!(metrics.ring_series("nic:eth0:rx_bps"), vec![(105, 500.0)]);
        assert_eq!(metrics.ring_series("nic:eth0:tx_bps"), vec![(105, 1000.0)]);
        assert_eq!(metrics.ring_series("nic:eth0:temp_c"), vec![(100, 52.0)]);
        assert!(
            metrics.series_names().iter().all(|s| !s.contains("br0")),
            "virtual interfaces produce no series"
        );
        std::fs::remove_dir_all(&tmp).unwrap();
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
