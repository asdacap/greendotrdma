//! SMART data via the root helper (`smartctl` needs privileges). The batch
//! health read drives each device's status dot + temperature; the full report is
//! dumped verbatim. This module reads only the standardized `smart_status.passed`
//! and `temperature.current` fields — it carries no device-vendor knowledge.

use crate::helper_client::{self, HelperClient};
use greendot_proto::BlockDev;
use std::collections::HashMap;

/// Per-device SMART health and current temperature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmartHealth {
    /// `smart_status.passed`: `Some(true)` healthy, `Some(false)` failing,
    /// `None` when the device exposes no SMART.
    pub passed: Option<bool>,
    pub temp_c: Option<i32>,
}

/// The helper's batch SMART read as `device → health`. A transport failure,
/// missing smartctl, or empty result yields an empty map (every device then
/// reads as gray/unknown), the same graceful degradation as elsewhere.
pub async fn health(helper: &HelperClient, devices: &[BlockDev]) -> HashMap<String, SmartHealth> {
    if devices.is_empty() {
        return HashMap::new();
    }
    helper
        .smart_health(devices.to_vec())
        .await
        .devices
        .into_iter()
        .map(|d| {
            (
                d.device,
                SmartHealth {
                    passed: d.passed,
                    temp_c: d.temp_c,
                },
            )
        })
        .collect()
}

/// Dot class for a device's SMART status: green when SMART reports healthy, red
/// when failing, gray when there is no SMART data (or the read failed).
pub fn dot_class(health: Option<&SmartHealth>) -> &'static str {
    match health.and_then(|h| h.passed) {
        Some(true) => "dot-green",
        Some(false) => "dot-red",
        None => "dot-gray",
    }
}

/// Human temperature, e.g. `"38 °C"`, or `"—"` when unknown.
pub fn temp_display(health: Option<&SmartHealth>) -> String {
    match health.and_then(|h| h.temp_c) {
        Some(c) => format!("{c} °C"),
        None => "—".to_string(),
    }
}

/// The full `smartctl -x` dump for one device.
#[derive(Debug, Clone, Default)]
pub struct SmartReportOut {
    pub stdout: String,
    pub stderr: String,
    /// False only when smartctl itself isn't installed, so the page can show the
    /// dependency hint instead of an empty report.
    pub installed: bool,
}

/// True unless the helper reported smartctl missing. smartctl exits nonzero on
/// healthy drives, so the task's `ok` flag is not a usable signal — only a spawn
/// failure (the "is not installed" hint from `cmd::spawn_error`) matters.
fn report_installed(error: Option<&str>) -> bool {
    !error.is_some_and(|e| e.contains("is not installed"))
}

pub async fn report(helper: &HelperClient, device: &BlockDev) -> SmartReportOut {
    let out = helper_client::collect(helper.smart_report(greendot_proto::ops::SmartReport {
        device: device.clone(),
    }))
    .await;
    SmartReportOut {
        installed: report_installed(out.error.as_deref()),
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::healthy(Some(SmartHealth { passed: Some(true), temp_c: Some(38) }), "dot-green", "38 °C")]
    #[case::failing(Some(SmartHealth { passed: Some(false), temp_c: Some(61) }), "dot-red", "61 °C")]
    #[case::no_smart(Some(SmartHealth { passed: None, temp_c: None }), "dot-gray", "—")]
    #[case::absent(None, "dot-gray", "—")]
    fn dot_and_temp_mapping(
        #[case] health: Option<SmartHealth>,
        #[case] dot: &str,
        #[case] temp: &str,
    ) {
        assert_eq!(dot_class(health.as_ref()), dot);
        assert_eq!(temp_display(health.as_ref()), temp);
    }

    #[test]
    fn installed_detection() {
        assert!(report_installed(None), "no error → installed");
        assert!(
            report_installed(Some("smartctl exited with status 4")),
            "nonzero exit is not a missing binary"
        );
        assert!(!report_installed(Some(
            "smartctl is not installed — install the smartmontools package"
        )));
    }
}
