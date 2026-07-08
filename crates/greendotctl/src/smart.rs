//! SMART reads via `smartctl` (needs root). The full report is a plain task the
//! web collects verbatim; the batch health read runs `smartctl -Hj -A` per
//! device for the typed `SmartHealth` reply.

use crate::cmd::TaskSpec;
use crate::util::dev;
use greendot_proto::BlockDev;

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

/// One device's SMART health+temp for the typed `SmartHealth` reply. smartctl
/// exits nonzero on healthy drives, so stdout is parsed regardless; a missing
/// binary or unreadable device degrades to `(None, None)` (rendered gray).
pub fn health(device: &BlockDev) -> (Option<bool>, Option<i32>) {
    std::process::Command::new("smartctl")
        .args(health_argv(device))
        .output()
        .map(|o| parse_health(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or((None, None))
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

    /// smartctl is absent (or the device is) in CI: the typed health read
    /// degrades to unknown instead of failing.
    #[test]
    fn health_degrades_to_unknown_without_smartctl() {
        assert_eq!(health(&BlockDev::new("sda").unwrap()), (None, None));
    }
}
