//! SMART reads via `smartctl` (needs root). The full report is a plain task the
//! web collects verbatim; the batch health read runs `smartctl -Hj -A` per
//! device and streams one merged JSON line, like `hardware::report_capable_into`.

use crate::cmd::{TaskSpec, capture_into};
use crate::util::dev;
use greendot_proto::{BlockDev, SubStatus, SubTask};
use std::io::{self, Write};

/// `smartctl -x /dev/<device>` — the full human-readable dump (identity, health,
/// attributes, error/self-test logs). The web shows its output verbatim.
pub fn report(device: &BlockDev) -> TaskSpec {
    TaskSpec::new("smartctl", vec!["-x".into(), dev(device)])
}

/// `smartctl -H -A -j /dev/<device>`: health (`-H` → `smart_status.passed`) plus
/// attributes (`-A`, which carries `temperature.current`), as JSON (`-j`).
fn health_argv(device: &BlockDev) -> Vec<String> {
    vec!["-H".into(), "-A".into(), "-j".into(), dev(device)]
}

/// Parses one `smartctl -Hj -A` JSON document into (passed, temp °C). Both are
/// optional: a device without SMART, a USB bridge, or non-JSON output yields
/// `(None, None)` rather than an error — smartctl's nonzero exit bitmask (set on
/// many healthy drives) is deliberately ignored; only stdout is consulted.
pub fn parse_health(stdout: &str) -> (Option<bool>, Option<i32>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return (None, None);
    };
    let passed = v["smart_status"]["passed"].as_bool();
    let temp_c = v["temperature"]["current"]
        .as_i64()
        .and_then(|t| i32::try_from(t).ok());
    (passed, temp_c)
}

/// Streams per-device SMART health+temp as one JSON line — a privileged read the
/// web collects: `[{"device":"sda","passed":true,"temp_c":38}, …]`. Runs
/// `smartctl` once per device; a missing binary or unreadable device degrades
/// that entry to `passed:null,temp_c:null` (the web renders it gray).
pub fn report_health_into(devices: &[BlockDev], sub: &mut SubTask) -> io::Result<SubStatus> {
    let mut rows = Vec::with_capacity(devices.len());
    for device in devices {
        let spec = TaskSpec::new("smartctl", health_argv(device));
        let (passed, temp_c) = match capture_into(sub, &spec)? {
            // smartctl exits nonzero on healthy drives: parse stdout regardless.
            Ok(stdout) => parse_health(&stdout),
            Err(_) => (None, None),
        };
        rows.push(serde_json::json!({
            "device": device.as_str(),
            "passed": passed,
            "temp_c": temp_c,
        }));
    }
    write!(sub.stdout(), "{}", serde_json::Value::Array(rows))?;
    Ok(SubStatus::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn report_builds_smartctl_x() {
        let spec = report(&BlockDev::new("sda").unwrap());
        assert_eq!(spec.command, "smartctl");
        assert_eq!(spec.args, vec!["-x".to_string(), "/dev/sda".to_string()]);
        assert_eq!(spec.stdin, None);
    }

    #[test]
    fn health_argv_is_json_health_attributes() {
        assert_eq!(
            health_argv(&BlockDev::new("nvme0n1").unwrap()),
            vec!["-H", "-A", "-j", "/dev/nvme0n1"]
        );
    }

    #[rstest]
    #[case::healthy(
        r#"{"smart_status":{"passed":true},"temperature":{"current":38}}"#,
        (Some(true), Some(38))
    )]
    #[case::failing(
        r#"{"smart_status":{"passed":false},"temperature":{"current":61}}"#,
        (Some(false), Some(61))
    )]
    #[case::no_temp(r#"{"smart_status":{"passed":true}}"#, (Some(true), None))]
    #[case::no_status(r#"{"temperature":{"current":30}}"#, (None, Some(30)))]
    #[case::empty_object("{}", (None, None))]
    #[case::garbage("not json", (None, None))]
    fn health_parsing(#[case] json: &str, #[case] expected: (Option<bool>, Option<i32>)) {
        assert_eq!(parse_health(json), expected);
    }

    #[test]
    fn report_health_into_emits_one_json_array() {
        use crate::cmd::test::Collector;
        use greendot_proto::{Task, TaskEvent};
        // A device whose smartctl call fails (binary may be absent in CI) still
        // produces a row with null health — the array shape is what matters.
        let mut c = Collector::default();
        let status = {
            let mut task = Task::new(&mut c);
            let mut sub = task.begin_subtask("Read SMART health");
            let s = report_health_into(&[BlockDev::new("sda").unwrap()], &mut sub).unwrap();
            sub.complete(s);
            task.complete().unwrap();
            s
        };
        let stdout: String = c
            .events
            .iter()
            .filter_map(|e| match e {
                TaskEvent::Stdout { data } => Some(data.as_str()),
                _ => None,
            })
            .collect();
        let rows: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["device"], "sda");
        assert_eq!(status, SubStatus::Success);
        assert!(matches!(
            c.events.last().unwrap(),
            TaskEvent::Finished {
                status: SubStatus::Success,
                ..
            }
        ));
    }
}
