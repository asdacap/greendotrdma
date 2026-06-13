//! Block device inventory via `lsblk --json` (sysfs-backed, unprivileged).

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub name: String,
    pub size: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub name: String,
    pub number: Option<u32>,
    pub size: u64,
    pub label: Option<String>,
    pub mountpoint: Option<String>,
}

#[derive(Deserialize)]
struct LsblkRoot {
    blockdevices: Vec<LsblkDev>,
}

#[derive(Deserialize)]
struct LsblkDev {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    size: u64,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    partlabel: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    children: Vec<LsblkDev>,
}

/// Trailing digits of a partition name ("nvme0n1p2" → 2, "sda3" → 3).
fn partition_number(name: &str) -> Option<u32> {
    let digits: String = name
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

pub fn parse_lsblk(json: &str) -> Result<Vec<Disk>> {
    let root: LsblkRoot = serde_json::from_str(json).context("parsing lsblk --json output")?;
    Ok(root
        .blockdevices
        .into_iter()
        // zvols (zd*) are managed on the ZFS page, not repartitioned here
        .filter(|d| d.kind == "disk" && !d.name.starts_with("zd"))
        .map(|d| Disk {
            partitions: d
                .children
                .into_iter()
                .filter(|c| c.kind == "part")
                .map(|c| Partition {
                    number: partition_number(&c.name),
                    size: c.size,
                    label: c.partlabel,
                    mountpoint: c.mountpoint,
                    name: c.name,
                })
                .collect(),
            name: d.name,
            size: d.size,
            model: d.model.filter(|m| !m.trim().is_empty()),
            serial: d.serial.filter(|s| !s.trim().is_empty()),
        })
        .collect())
}

pub async fn disks() -> Result<Vec<Disk>> {
    let output = tokio::process::Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "-o",
            "NAME,TYPE,SIZE,MODEL,SERIAL,PARTLABEL,MOUNTPOINT",
        ])
        .output()
        .await
        .context("running lsblk")?;
    anyhow::ensure!(
        output.status.success(),
        "lsblk failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    parse_lsblk(&String::from_utf8(output.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsblk_fixture_filtering_zvols_and_non_disks() {
        let json = r#"{
            "blockdevices": [
                {"name":"sda","type":"disk","size":4000787030016,"model":"WDC WD40EFRX","serial":"WD-X","partlabel":null,"mountpoint":null,
                 "children":[
                    {"name":"sda1","type":"part","size":536870912,"model":null,"serial":null,"partlabel":"boot","mountpoint":"/boot"},
                    {"name":"sda2","type":"part","size":4000248159744,"model":null,"serial":null,"partlabel":null,"mountpoint":null}
                 ]},
                {"name":"nvme0n1","type":"disk","size":512110190592,"model":"Samsung 980","serial":"S1","partlabel":null,"mountpoint":null,
                 "children":[
                    {"name":"nvme0n1p2","type":"part","size":1024,"model":null,"serial":null,"partlabel":"x","mountpoint":null}
                 ]},
                {"name":"zd0","type":"disk","size":10737418240,"model":null,"serial":null,"partlabel":null,"mountpoint":null},
                {"name":"sr0","type":"rom","size":1024,"model":null,"serial":null,"partlabel":null,"mountpoint":null}
            ]
        }"#;
        let disks = parse_lsblk(json).unwrap();
        assert_eq!(disks.len(), 2, "zd0 and sr0 filtered out");
        assert_eq!(disks[0].name, "sda");
        assert_eq!(disks[0].model.as_deref(), Some("WDC WD40EFRX"));
        assert_eq!(disks[0].partitions.len(), 2);
        assert_eq!(disks[0].partitions[0].number, Some(1));
        assert_eq!(disks[0].partitions[0].label.as_deref(), Some("boot"));
        assert_eq!(disks[0].partitions[0].mountpoint.as_deref(), Some("/boot"));
        assert_eq!(
            disks[1].partitions[0].number,
            Some(2),
            "nvme pN suffix parsed"
        );
        assert!(parse_lsblk("not json").is_err());
    }
}
