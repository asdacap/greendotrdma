//! LVM state via `vgs`/`lvs`/`pvs --reportformat json`. Unlike ZFS, LVM
//! reporting needs root, so these run through the helper ([`HelperClient::collect`])
//! rather than as a direct subprocess. The JSON parsers here are pure and tested.

use crate::helper_client::HelperClient;
use anyhow::{Context, Result};
use greendot_proto::{LvmReport, Request};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vg {
    pub name: String,
    pub size: u64,
    pub free: u64,
    pub pv_count: u64,
    pub lv_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pv {
    pub name: String,
    /// `None` when the PV isn't part of any VG.
    pub vg: Option<String>,
    pub size: u64,
    pub free: u64,
}

/// LV kind, derived from the first character of `lv_attr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LvKind {
    Linear,
    ThinPool,
    Thin,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Lv {
    pub vg: String,
    pub name: String,
    pub size: u64,
    pub kind: LvKind,
    /// The owning thin pool, for thin volumes.
    pub pool: Option<String>,
    /// Allocation %, for thin pools and thin volumes.
    pub data_percent: Option<f64>,
}

/// LVM JSON wraps rows as `{"report":[{"<key>":[ {…} ]}]}`. All values are
/// strings, even numbers.
#[derive(Deserialize)]
struct Report<T> {
    report: Vec<ReportGroup<T>>,
}

#[derive(Deserialize)]
struct ReportGroup<T> {
    #[serde(alias = "vg", alias = "lv", alias = "pv")]
    rows: Vec<T>,
}

#[derive(Deserialize)]
struct VgJson {
    vg_name: String,
    vg_size: String,
    vg_free: String,
    pv_count: String,
    lv_count: String,
}

#[derive(Deserialize)]
struct LvJson {
    vg_name: String,
    lv_name: String,
    lv_size: String,
    lv_attr: String,
    pool_lv: String,
    data_percent: String,
}

#[derive(Deserialize)]
struct PvJson {
    pv_name: String,
    vg_name: String,
    pv_size: String,
    pv_free: String,
}

/// Parses an integer byte/count field. `--units b --nosuffix` yields plain
/// integers; tolerate a trailing `.00` just in case.
fn num(field: &str) -> Result<u64> {
    let int = field.split('.').next().unwrap_or(field);
    int.parse()
        .with_context(|| format!("expected a number, got {field:?}"))
}

fn opt_str(field: String) -> Option<String> {
    Some(field).filter(|s| !s.is_empty())
}

fn opt_percent(field: &str) -> Result<Option<f64>> {
    if field.is_empty() {
        Ok(None)
    } else {
        Ok(Some(field.parse().with_context(|| {
            format!("expected a percentage, got {field:?}")
        })?))
    }
}

fn lv_kind(attr: &str) -> LvKind {
    match attr.chars().next() {
        Some('t') => LvKind::ThinPool,
        Some('V') => LvKind::Thin,
        _ => LvKind::Linear,
    }
}

fn rows<T>(out: &str) -> Result<Vec<T>>
where
    for<'de> T: Deserialize<'de>,
{
    let parsed: Report<T> = serde_json::from_str(out).context("parsing LVM JSON report")?;
    Ok(parsed.report.into_iter().flat_map(|g| g.rows).collect())
}

pub fn parse_vgs_json(out: &str) -> Result<Vec<Vg>> {
    rows::<VgJson>(out)?
        .into_iter()
        .map(|v| {
            Ok(Vg {
                name: v.vg_name,
                size: num(&v.vg_size)?,
                free: num(&v.vg_free)?,
                pv_count: num(&v.pv_count)?,
                lv_count: num(&v.lv_count)?,
            })
        })
        .collect()
}

pub fn parse_lvs_json(out: &str) -> Result<Vec<Lv>> {
    rows::<LvJson>(out)?
        .into_iter()
        .map(|l| {
            Ok(Lv {
                kind: lv_kind(&l.lv_attr),
                size: num(&l.lv_size)?,
                pool: opt_str(l.pool_lv),
                data_percent: opt_percent(&l.data_percent)?,
                vg: l.vg_name,
                name: l.lv_name,
            })
        })
        .collect()
}

pub fn parse_pvs_json(out: &str) -> Result<Vec<Pv>> {
    rows::<PvJson>(out)?
        .into_iter()
        .map(|p| {
            Ok(Pv {
                name: p.pv_name,
                vg: opt_str(p.vg_name),
                size: num(&p.pv_size)?,
                free: num(&p.pv_free)?,
            })
        })
        .collect()
}

/// Runs an LVM report through the helper. A missing binary (`is not installed`)
/// maps to `None`, the "LVM not installed" state, mirroring `zfs::run`.
async fn report(helper: &HelperClient, what: LvmReport) -> Result<Option<String>> {
    let out = helper.collect(Request::LvmReport { what }).await;
    if out
        .error
        .as_deref()
        .is_some_and(|e| e.contains("is not installed"))
    {
        return Ok(None);
    }
    anyhow::ensure!(
        out.ok,
        "lvm report failed: {}",
        out.error.unwrap_or_else(|| out.stderr.trim().to_string())
    );
    Ok(Some(out.stdout))
}

pub async fn volume_groups(helper: &HelperClient) -> Result<Option<Vec<Vg>>> {
    report(helper, LvmReport::Vgs)
        .await?
        .map(|out| parse_vgs_json(&out))
        .transpose()
}

pub async fn physical_volumes(helper: &HelperClient) -> Result<Option<Vec<Pv>>> {
    report(helper, LvmReport::Pvs)
        .await?
        .map(|out| parse_pvs_json(&out))
        .transpose()
}

pub async fn logical_volumes(helper: &HelperClient) -> Result<Option<Vec<Lv>>> {
    report(helper, LvmReport::Lvs)
        .await?
        .map(|out| parse_lvs_json(&out))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vgs_and_handles_empty() {
        let out = r#"{"report":[{"vg":[
            {"vg_name":"vg0","vg_size":"107374182400","vg_free":"53687091200","pv_count":"2","lv_count":"3"}
        ]}]}"#;
        assert_eq!(
            parse_vgs_json(out).unwrap(),
            vec![Vg {
                name: "vg0".into(),
                size: 107_374_182_400,
                free: 53_687_091_200,
                pv_count: 2,
                lv_count: 3,
            }]
        );
        // Installed but no VGs.
        assert_eq!(parse_vgs_json(r#"{"report":[{"vg":[]}]}"#).unwrap(), vec![]);
    }

    #[test]
    fn parses_lvs_marking_thin_pool_and_thin_volume() {
        let out = r#"{"report":[{"lv":[
            {"vg_name":"vg0","lv_name":"data","lv_size":"10737418240","lv_attr":"-wi-a-----","pool_lv":"","data_percent":""},
            {"vg_name":"vg0","lv_name":"pool0","lv_size":"107374182400","lv_attr":"twi-aotz--","pool_lv":"","data_percent":"5.00"},
            {"vg_name":"vg0","lv_name":"vm1","lv_size":"21474836480","lv_attr":"Vwi-a-tz--","pool_lv":"pool0","data_percent":"12.50"}
        ]}]}"#;
        let lvs = parse_lvs_json(out).unwrap();
        assert_eq!(lvs[0].kind, LvKind::Linear);
        assert_eq!(lvs[0].pool, None);
        assert_eq!(lvs[1].kind, LvKind::ThinPool);
        assert_eq!(lvs[1].data_percent, Some(5.0));
        assert_eq!(
            lvs[2],
            Lv {
                vg: "vg0".into(),
                name: "vm1".into(),
                size: 21_474_836_480,
                kind: LvKind::Thin,
                pool: Some("pool0".into()),
                data_percent: Some(12.5),
            }
        );
    }

    #[test]
    fn parses_pvs_including_orphan() {
        let out = r#"{"report":[{"pv":[
            {"pv_name":"/dev/sdb","vg_name":"vg0","pv_size":"53687091200","pv_free":"21474836480"},
            {"pv_name":"/dev/sdc","vg_name":"","pv_size":"53687091200","pv_free":"53687091200"}
        ]}]}"#;
        let pvs = parse_pvs_json(out).unwrap();
        assert_eq!(pvs[0].vg.as_deref(), Some("vg0"));
        assert_eq!(pvs[1].vg, None, "PV not in a VG");
        assert!(parse_pvs_json("not json").is_err());
    }
}
