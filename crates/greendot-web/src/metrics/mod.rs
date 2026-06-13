//! Metrics: a 5s in-memory ring for live charts, SQLite history (1-min rows
//! for 7 days, 1-hour rows for 90 days), server-rendered SVG charts, and a
//! hand-rendered Prometheus /metrics endpoint.

pub mod collect;

use anyhow::Result;
use rusqlite::Connection;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Mutex, RwLock};

/// Live samples: ~10 minutes at one sample per 5s.
const RING_CAPACITY: usize = 120;
const WEEK: i64 = 7 * 86400;
const QUARTER: i64 = 90 * 86400;

pub struct Metrics {
    ring: RwLock<HashMap<String, VecDeque<(i64, f64)>>>,
    /// Last raw counter readings, for rate computation: key → (ts, value).
    raw: Mutex<HashMap<String, (i64, u64)>>,
    minute_acc: Mutex<HashMap<String, (f64, u32)>>,
    hour_acc: Mutex<HashMap<String, (f64, u32)>>,
    db: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS samples_1m (series TEXT NOT NULL, ts INTEGER NOT NULL, value REAL NOT NULL);
CREATE INDEX IF NOT EXISTS idx_samples_1m ON samples_1m(series, ts);
CREATE TABLE IF NOT EXISTS samples_1h (series TEXT NOT NULL, ts INTEGER NOT NULL, value REAL NOT NULL);
CREATE INDEX IF NOT EXISTS idx_samples_1h ON samples_1h(series, ts);
";

impl Metrics {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Metrics {
            ring: RwLock::new(HashMap::new()),
            raw: Mutex::new(HashMap::new()),
            minute_acc: Mutex::new(HashMap::new()),
            hour_acc: Mutex::new(HashMap::new()),
            db: Mutex::new(conn),
        })
    }

    /// Records a rate/gauge sample into the ring and the rollup accumulators.
    pub fn push(&self, series: &str, ts: i64, value: f64) {
        let mut ring = self.ring.write().unwrap();
        let buf = ring.entry(series.to_owned()).or_default();
        buf.push_back((ts, value));
        while buf.len() > RING_CAPACITY {
            buf.pop_front();
        }
        for acc in [&self.minute_acc, &self.hour_acc] {
            let mut acc = acc.lock().unwrap();
            let entry = acc.entry(series.to_owned()).or_insert((0.0, 0));
            entry.0 += value;
            entry.1 += 1;
        }
    }

    /// Turns a raw monotonic counter reading into a rate sample; the first
    /// reading (or a counter reset) yields nothing.
    pub fn push_counter(&self, series: &str, ts: i64, value: u64) {
        let prev = self
            .raw
            .lock()
            .unwrap()
            .insert(series.to_owned(), (ts, value));
        if let Some(rate) = rate(prev, (ts, value)) {
            self.push(series, ts, rate);
        }
    }

    pub fn ring_series(&self, series: &str) -> Vec<(i64, f64)> {
        self.ring
            .read()
            .unwrap()
            .get(series)
            .map(|b| b.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn series_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.ring.read().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    pub fn latest_raw(&self) -> HashMap<String, u64> {
        self.raw
            .lock()
            .unwrap()
            .iter()
            .map(|(k, (_, v))| (k.clone(), *v))
            .collect()
    }

    /// Flushes one accumulator into its rollup table and prunes old rows.
    pub fn flush(&self, table: &str, ts: i64) -> Result<()> {
        let acc = if table == "samples_1m" {
            &self.minute_acc
        } else {
            &self.hour_acc
        };
        let drained: Vec<(String, f64)> = acc
            .lock()
            .unwrap()
            .drain()
            .filter(|(_, (_, n))| *n > 0)
            .map(|(series, (sum, n))| (series, sum / f64::from(n)))
            .collect();
        let mut conn = self.db.lock().unwrap();
        let tx = conn.transaction()?;
        for (series, avg) in drained {
            tx.execute(
                &format!("INSERT INTO {table} (series, ts, value) VALUES (?1, ?2, ?3)"),
                rusqlite::params![series, ts, avg],
            )?;
        }
        let keep = if table == "samples_1m" { WEEK } else { QUARTER };
        tx.execute(&format!("DELETE FROM {table} WHERE ts < ?1"), [ts - keep])?;
        tx.commit()?;
        Ok(())
    }

    /// History from the rollup tables; picks 1-min rows for ranges within a
    /// week, 1-hour rows beyond.
    pub fn history(&self, series: &str, since: i64, now: i64) -> Result<Vec<(i64, f64)>> {
        let table = if now - since <= WEEK {
            "samples_1m"
        } else {
            "samples_1h"
        };
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(&format!(
            "SELECT ts, value FROM {table} WHERE series = ?1 AND ts >= ?2 ORDER BY ts"
        ))?;
        let rows = stmt
            .query_map(rusqlite::params![series, since], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
}

/// Counter delta → per-second rate; None on first sample, reset, or dt<=0.
pub fn rate(prev: Option<(i64, u64)>, current: (i64, u64)) -> Option<f64> {
    let (prev_ts, prev_value) = prev?;
    let (ts, value) = current;
    if ts <= prev_ts || value < prev_value {
        return None;
    }
    Some((value - prev_value) as f64 / (ts - prev_ts) as f64)
}

/// One Prometheus sample line.
pub struct PromSample {
    pub name: &'static str,
    pub labels: Vec<(&'static str, String)>,
    pub value: f64,
}

/// Prometheus text exposition (untyped; gauges and counters by name suffix).
pub fn render_prometheus(samples: &[PromSample]) -> String {
    let mut out = String::new();
    for s in samples {
        out.push_str(s.name);
        if !s.labels.is_empty() {
            let labels: Vec<String> = s
                .labels
                .iter()
                .map(|(k, v)| {
                    format!(
                        r#"{k}="{}""#,
                        v.replace('\\', r"\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                    )
                })
                .collect();
            out.push_str(&format!("{{{}}}", labels.join(",")));
        }
        out.push_str(&format!(" {}\n", s.value));
    }
    out
}

/// A simple line chart as inline SVG; pure string building, no JS.
pub fn chart_svg(points: &[(i64, f64)], width: u32, height: u32) -> String {
    if points.len() < 2 {
        return format!(
            r#"<svg class="chart" viewBox="0 0 {width} {height}"><text x="4" y="{}" class="chart-label">no data yet</text></svg>"#,
            height / 2
        );
    }
    let (t0, t1) = (points[0].0, points[points.len() - 1].0);
    let max = points
        .iter()
        .map(|(_, v)| *v)
        .fold(f64::MIN, f64::max)
        .max(1e-9);
    let span = (t1 - t0).max(1) as f64;
    let coords: Vec<String> = points
        .iter()
        .map(|(t, v)| {
            let x = (*t - t0) as f64 / span * f64::from(width);
            let y = f64::from(height) - (v / max * f64::from(height - 14)) - 2.0;
            format!("{x:.1},{y:.1}")
        })
        .collect();
    format!(
        r#"<svg class="chart" viewBox="0 0 {width} {height}"><polyline fill="none" points="{}"/><text x="4" y="12" class="chart-label">max {}</text></svg>"#,
        coords.join(" "),
        crate::fmt::human_bytes(max as u64),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::first_sample(None, (10, 1000), None)]
    #[case::steady(Some((10, 1000)), (15, 6000), Some(1000.0))]
    #[case::counter_reset(Some((10, 1000)), (15, 100), None)]
    #[case::same_timestamp(Some((10, 1000)), (10, 2000), None)]
    fn rate_computation(
        #[case] prev: Option<(i64, u64)>,
        #[case] current: (i64, u64),
        #[case] expected: Option<f64>,
    ) {
        assert_eq!(rate(prev, current), expected);
    }

    #[test]
    fn prometheus_rendering_with_label_escaping() {
        let samples = vec![
            PromSample {
                name: "greendot_pool_size_bytes",
                labels: vec![("pool", "tank".into())],
                value: 1024.0,
            },
            PromSample {
                name: "greendot_disk_read_bytes_total",
                labels: vec![("device", "weird\"name".into())],
                value: 5.0,
            },
            PromSample {
                name: "greendot_up",
                labels: vec![],
                value: 1.0,
            },
        ];
        let out = render_prometheus(&samples);
        assert_eq!(
            out,
            "greendot_pool_size_bytes{pool=\"tank\"} 1024\n\
             greendot_disk_read_bytes_total{device=\"weird\\\"name\"} 5\n\
             greendot_up 1\n"
        );
    }

    #[test]
    fn ring_rollups_history_and_chart() {
        let m = Metrics::in_memory().unwrap();
        // Counter samples 5s apart: 1000 B/s rate after the first.
        m.push_counter("disk:sda:read_bps", 100, 0);
        m.push_counter("disk:sda:read_bps", 105, 5000);
        m.push_counter("disk:sda:read_bps", 110, 10000);
        let ring = m.ring_series("disk:sda:read_bps");
        assert_eq!(ring, vec![(105, 1000.0), (110, 1000.0)]);
        assert_eq!(m.series_names(), vec!["disk:sda:read_bps"]);
        assert_eq!(m.latest_raw()["disk:sda:read_bps"], 10000);

        // Minute flush stores the average and history returns it.
        m.flush("samples_1m", 120).unwrap();
        assert_eq!(
            m.history("disk:sda:read_bps", 0, 120).unwrap(),
            vec![(120, 1000.0)]
        );
        // Accumulator drained: a second flush writes nothing new.
        m.flush("samples_1m", 180).unwrap();
        assert_eq!(m.history("disk:sda:read_bps", 0, 180).unwrap().len(), 1);
        // The hour accumulator is independent and still holds the samples.
        m.flush("samples_1h", 3600).unwrap();
        assert_eq!(
            m.history("disk:sda:read_bps", 0, WEEK + 3601).unwrap(),
            vec![(3600, 1000.0)],
            "long ranges read the hourly table"
        );

        let svg = chart_svg(&ring, 600, 120);
        assert!(svg.contains("<polyline"), "{svg}");
        assert!(svg.contains("max 1000 B"), "{svg}");
        assert!(chart_svg(&[], 600, 120).contains("no data yet"));
    }
}
