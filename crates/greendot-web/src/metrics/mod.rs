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

/// How a chart's peak value is labelled. Series are rates/sizes (bytes),
/// temperatures (°C), or saturation (%).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChartUnit {
    Bytes,
    Celsius,
    Percent,
}

impl ChartUnit {
    /// Picks the unit from a metrics series key (`disk:sda:read_bps`,
    /// `disk:sda:temp_c`, `pool:tank:used_percent`, …).
    pub fn for_series(series: &str) -> ChartUnit {
        if series.ends_with(":temp_c") {
            ChartUnit::Celsius
        } else if series.ends_with("_percent") {
            ChartUnit::Percent
        } else {
            ChartUnit::Bytes
        }
    }

    fn label(self, max: f64) -> String {
        match self {
            ChartUnit::Bytes => crate::fmt::human_bytes(max as u64),
            ChartUnit::Celsius => format!("{max:.0} °C"),
            ChartUnit::Percent => format!("{max:.0}%"),
        }
    }
}

/// A `HH:MM` (or `MM-DD` for spans over two days) label for a unix timestamp.
fn axis_time(ts: i64, span: i64) -> String {
    let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
    if span > 2 * 86400 {
        dt.format("%m-%d").to_string()
    } else {
        dt.format("%H:%M").to_string()
    }
}

/// A line chart as inline SVG with a vertical value scale (0 / mid / max) and a
/// horizontal time axis; pure string building, no JS.
pub fn chart_svg(points: &[(i64, f64)], width: u32, height: u32, unit: ChartUnit) -> String {
    if points.len() < 2 {
        return format!(
            r#"<svg class="chart" viewBox="0 0 {width} {height}"><text x="4" y="{}" class="chart-label">no data yet</text></svg>"#,
            height / 2
        );
    }
    // Inset a plot rect from the viewBox: left gutter for y-tick labels, bottom
    // gutter for the time axis.
    const PAD_L: f64 = 54.0;
    const PAD_R: f64 = 6.0;
    const PAD_T: f64 = 8.0;
    const PAD_B: f64 = 16.0;
    let (w, h) = (f64::from(width), f64::from(height));
    let (px0, px1) = (PAD_L, w - PAD_R);
    let py1 = h - PAD_B;
    let (plot_w, plot_h) = (px1 - px0, py1 - PAD_T);

    let (t0, t1) = (points[0].0, points[points.len() - 1].0);
    let max = points
        .iter()
        .map(|(_, v)| *v)
        .fold(f64::MIN, f64::max)
        .max(1e-9);
    let span = (t1 - t0).max(1);
    let coords: Vec<String> = points
        .iter()
        .map(|(t, v)| {
            let x = px0 + (*t - t0) as f64 / span as f64 * plot_w;
            let y = py1 - (v / max) * plot_h;
            format!("{x:.1},{y:.1}")
        })
        .collect();

    let mut svg = format!(r#"<svg class="chart" viewBox="0 0 {width} {height}">"#);
    // Y gridlines + right-aligned value ticks at 0, max/2, max.
    for frac in [0.0_f64, 0.5, 1.0] {
        let y = py1 - frac * plot_h;
        svg.push_str(&format!(
            r#"<line class="chart-grid" x1="{px0:.1}" y1="{y:.1}" x2="{px1:.1}" y2="{y:.1}"/><text class="chart-label chart-tick-y" x="{:.1}" y="{:.1}">{}</text>"#,
            px0 - 4.0,
            y + 3.0,
            unit.label(max * frac),
        ));
    }
    // X baseline with start/end time labels.
    svg.push_str(&format!(
        r#"<line class="chart-axis" x1="{px0:.1}" y1="{py1:.1}" x2="{px1:.1}" y2="{py1:.1}"/><text class="chart-label" x="{px0:.1}" y="{:.1}">{}</text><text class="chart-label" x="{px1:.1}" y="{:.1}" text-anchor="end">{}</text>"#,
        h - 4.0,
        axis_time(t0, span),
        h - 4.0,
        axis_time(t1, span),
    ));
    svg.push_str(&format!(
        r#"<polyline fill="none" points="{}"/></svg>"#,
        coords.join(" "),
    ));
    svg
}

/// A back-to-back ("mirror") chart: `up` is drawn upward from a central zero
/// baseline and `down` downward, both on one shared value scale so the two
/// directions are directly comparable. Folds a read/write (or rx/tx) pair into
/// a single chart; either series may be empty.
pub fn mirror_chart_svg(
    up: &[(i64, f64)],
    down: &[(i64, f64)],
    up_label: &str,
    down_label: &str,
    width: u32,
    height: u32,
    unit: ChartUnit,
) -> String {
    if up.len() < 2 && down.len() < 2 {
        return format!(
            r#"<svg class="chart" viewBox="0 0 {width} {height}"><text x="4" y="{}" class="chart-label">no data yet</text></svg>"#,
            height / 2
        );
    }
    const PAD_L: f64 = 54.0;
    const PAD_R: f64 = 6.0;
    const PAD_T: f64 = 8.0;
    const PAD_B: f64 = 16.0;
    let (w, h) = (f64::from(width), f64::from(height));
    let (px0, px1) = (PAD_L, w - PAD_R);
    let py1 = h - PAD_B;
    let plot_w = px1 - px0;
    // Zero sits on the centre line; each direction gets half the plot height.
    let mid = PAD_T + (py1 - PAD_T) / 2.0;
    let half_h = mid - PAD_T;

    // Shared time span and peak across both directions.
    let all = || up.iter().chain(down.iter());
    let t0 = all().map(|(t, _)| *t).min().unwrap();
    let t1 = all().map(|(t, _)| *t).max().unwrap();
    let span = (t1 - t0).max(1);
    let max = all().map(|(_, v)| *v).fold(f64::MIN, f64::max).max(1e-9);

    // Point string for one direction; `sign` is +1 (up) or -1 (down).
    let coords = |pts: &[(i64, f64)], sign: f64| -> String {
        pts.iter()
            .map(|(t, v)| {
                let x = px0 + (*t - t0) as f64 / span as f64 * plot_w;
                let y = mid - sign * (v / max) * half_h;
                format!("{x:.1},{y:.1}")
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    let mut svg = format!(r#"<svg class="chart" viewBox="0 0 {width} {height}">"#);
    // Value ticks: peak at top and bottom, zero on the centre axis.
    for (y, val, cls) in [
        (PAD_T, max, "chart-grid"),
        (mid, 0.0, "chart-axis"),
        (py1, max, "chart-grid"),
    ] {
        svg.push_str(&format!(
            r#"<line class="{cls}" x1="{px0:.1}" y1="{y:.1}" x2="{px1:.1}" y2="{y:.1}"/><text class="chart-label chart-tick-y" x="{:.1}" y="{:.1}">{}</text>"#,
            px0 - 4.0,
            y + 3.0,
            unit.label(val),
        ));
    }
    // Start/end time labels under the plot.
    svg.push_str(&format!(
        r#"<text class="chart-label" x="{px0:.1}" y="{:.1}">{}</text><text class="chart-label" x="{px1:.1}" y="{:.1}" text-anchor="end">{}</text>"#,
        h - 4.0,
        axis_time(t0, span),
        h - 4.0,
        axis_time(t1, span),
    ));
    if up.len() >= 2 {
        svg.push_str(&format!(
            r#"<polyline class="chart-up" fill="none" points="{}"/>"#,
            coords(up, 1.0),
        ));
    }
    if down.len() >= 2 {
        svg.push_str(&format!(
            r#"<polyline class="chart-down" fill="none" points="{}"/>"#,
            coords(down, -1.0),
        ));
    }
    // Direction legend, coloured to match each polyline.
    svg.push_str(&format!(
        r#"<text class="chart-up-label" x="{:.1}" y="{:.1}">▲ {up_label}</text><text class="chart-down-label" x="{:.1}" y="{:.1}">▼ {down_label}</text></svg>"#,
        px0 + 4.0,
        PAD_T + 10.0,
        px0 + 4.0,
        py1 - 4.0,
    ));
    svg
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

        let svg = chart_svg(&ring, 600, 120, ChartUnit::Bytes);
        assert!(svg.contains("<polyline"), "{svg}");
        // The value scale labels its top tick with the peak; axes are drawn.
        assert!(svg.contains(">1000 B</text>"), "{svg}");
        assert!(svg.contains("chart-grid"), "{svg}");
        assert!(svg.contains("chart-axis"), "{svg}");
        assert!(chart_svg(&[], 600, 120, ChartUnit::Bytes).contains("no data yet"));
        // Non-byte units label the peak tick appropriately.
        assert!(
            chart_svg(&[(0, 30.0), (5, 38.0)], 600, 120, ChartUnit::Celsius)
                .contains(">38 °C</text>")
        );
        assert_eq!(ChartUnit::for_series("disk:sda:temp_c"), ChartUnit::Celsius);
        assert_eq!(
            ChartUnit::for_series("pool:tank:used_percent"),
            ChartUnit::Percent
        );
        assert_eq!(ChartUnit::for_series("disk:sda:read_bps"), ChartUnit::Bytes);
    }

    #[test]
    fn mirror_chart_folds_two_directions_and_shares_a_scale() {
        // Write peaks higher than read: both halves scale to the shared 4000 peak.
        let read = [(0, 1000.0), (5, 2000.0)];
        let write = [(0, 4000.0), (5, 3000.0)];
        let svg = mirror_chart_svg(&read, &write, "Read", "Write", 600, 120, ChartUnit::Bytes);
        // One polyline per direction, each with its own class, plus the legend.
        assert!(svg.contains(r#"class="chart-up""#), "{svg}");
        assert!(svg.contains(r#"class="chart-down""#), "{svg}");
        assert!(svg.contains("▲ Read"), "{svg}");
        assert!(svg.contains("▼ Write"), "{svg}");
        // Shared peak tick (top and bottom) plus a zero centre axis.
        assert!(svg.contains(">3.9 KiB</text>"), "{svg}");
        assert!(svg.contains(">0 B</text>"), "{svg}");
        assert!(svg.contains("chart-axis"), "{svg}");
        // One empty direction still renders the other; two empty is "no data".
        assert!(
            mirror_chart_svg(&read, &[], "Read", "Write", 600, 120, ChartUnit::Bytes)
                .contains(r#"class="chart-up""#)
        );
        assert!(
            mirror_chart_svg(&[], &[], "Read", "Write", 600, 120, ChartUnit::Bytes)
                .contains("no data yet")
        );
    }
}
