//! Block device inventory via `lsblk --json` (sysfs-backed, unprivileged).

use crate::fmt::human_bytes;
use crate::helper_client::HelperClient;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub name: String,
    pub size: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
    /// Set when the disk is formatted/used directly (no partition table).
    pub mountpoint: Option<String>,
    pub fstype: Option<String>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub name: String,
    pub number: Option<u32>,
    pub size: u64,
    pub label: Option<String>,
    pub mountpoint: Option<String>,
    /// `lsblk` filesystem type: `ext4`, `btrfs`, `zfs_member`, … or `None`.
    pub fstype: Option<String>,
}

/// What kind of device an [`AvailDevice`] points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailKind {
    Zvol,
    Lv,
    Partition,
    WholeDisk,
}

/// An *available* block device: one that is unmounted, not a ZFS pool member,
/// and not already used by an export. Suitable for the export dropdown; pool
/// callers further drop zvols and filesystem-bearing partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailDevice {
    /// `DevicePath`-shaped value: `/dev/sdaN`, `/dev/sdb`, or `/dev/zvol/<name>`.
    pub path: String,
    pub label: String,
    pub kind: AvailKind,
    pub fstype: Option<String>,
    pub size: u64,
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
    fstype: Option<String>,
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
                    fstype: c.fstype.filter(|f| !f.trim().is_empty()),
                    name: c.name,
                })
                .collect(),
            name: d.name,
            size: d.size,
            model: d.model.filter(|m| !m.trim().is_empty()),
            serial: d.serial.filter(|s| !s.trim().is_empty()),
            mountpoint: d.mountpoint.filter(|m| !m.trim().is_empty()),
            fstype: d.fstype.filter(|f| !f.trim().is_empty()),
        })
        .collect())
}

/// Label like `/dev/sda3 — 100.0 GiB ext4` (or `… no filesystem`).
fn device_label(path: &str, size: u64, fstype: Option<&str>) -> String {
    let fs = match fstype {
        Some("zfs_member") => "ZFS",
        Some("LVM2_member") => "LVM",
        Some(f) => f,
        None => "no filesystem",
    };
    format!("{path} — {} {fs}", human_bytes(size))
}

/// Filesystems that mean the device is already claimed (ZFS pool member or LVM
/// physical volume) and so must not be offered for new pools/exports.
fn in_use_fstype(fstype: Option<&str>) -> bool {
    matches!(fstype, Some("zfs_member" | "LVM2_member"))
}

/// Pure core of [`available_block_devices`]: given the disk inventory, the
/// candidate zvols (name, logical size), the candidate LVs (`/dev/<vg>/<lv>`
/// path, size), and the set of in-use device paths, produce the available
/// devices. A device is available when it is unmounted, not a ZFS pool member,
/// and not already in `in_use`.
pub fn available_from_disks(
    disks: &[Disk],
    zvols: &[(String, u64)],
    lvs: &[(String, u64)],
    in_use: &HashSet<String>,
) -> Vec<AvailDevice> {
    let mut out = Vec::new();
    for d in disks {
        // A partitioned disk is represented by its partitions, never offered
        // whole alongside them.
        if d.partitions.is_empty() {
            let path = format!("/dev/{}", d.name);
            if d.mountpoint.is_none()
                && !in_use_fstype(d.fstype.as_deref())
                && !in_use.contains(&path)
            {
                out.push(AvailDevice {
                    label: device_label(&path, d.size, d.fstype.as_deref()),
                    path,
                    kind: AvailKind::WholeDisk,
                    fstype: d.fstype.clone(),
                    size: d.size,
                });
            }
        } else {
            for p in &d.partitions {
                let path = format!("/dev/{}", p.name);
                if p.mountpoint.is_none()
                    && !in_use_fstype(p.fstype.as_deref())
                    && !in_use.contains(&path)
                {
                    out.push(AvailDevice {
                        label: device_label(&path, p.size, p.fstype.as_deref()),
                        path,
                        kind: AvailKind::Partition,
                        fstype: p.fstype.clone(),
                        size: p.size,
                    });
                }
            }
        }
    }
    for (name, size) in zvols {
        let path = format!("/dev/zvol/{name}");
        if !in_use.contains(&path) {
            out.push(AvailDevice {
                label: format!("zvol {name} — {}", human_bytes(*size)),
                path,
                kind: AvailKind::Zvol,
                fstype: None,
                size: *size,
            });
        }
    }
    for (path, size) in lvs {
        if !in_use.contains(path) {
            let name = path.strip_prefix("/dev/").unwrap_or(path);
            out.push(AvailDevice {
                label: format!("LV {name} — {}", human_bytes(*size)),
                path: path.clone(),
                kind: AvailKind::Lv,
                fstype: None,
                size: *size,
            });
        }
    }
    out
}

/// Available block devices for the export dropdown and pool form. Infallible:
/// a failed `lsblk`, absent ZFS, or absent LVM just yields fewer (or no)
/// entries. Reads LVs through the helper (LVM reporting needs root).
pub async fn available_block_devices(
    helper: &HelperClient,
    in_use: &HashSet<String>,
) -> Vec<AvailDevice> {
    let disks = disks().await.unwrap_or_default();
    let zvols: Vec<(String, u64)> = super::zfs::datasets()
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d.kind == super::zfs::DsKind::Volume)
        .map(|d| (d.name, d.volsize.unwrap_or(0)))
        .collect();
    // Thin pools are containers, not exportable block devices.
    let lvs: Vec<(String, u64)> = super::lvm::logical_volumes(helper)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter(|l| l.kind != super::lvm::LvKind::ThinPool)
        .map(|l| (format!("/dev/{}/{}", l.vg, l.name), l.size))
        .collect();
    available_from_disks(&disks, &zvols, &lvs, in_use)
}

pub async fn disks() -> Result<Vec<Disk>> {
    let output = tokio::process::Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "-o",
            "NAME,TYPE,SIZE,FSTYPE,MODEL,SERIAL,PARTLABEL,MOUNTPOINT",
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
    use rstest::rstest;

    #[rstest]
    #[case(Some("ext4"), "/dev/sda1 — 1.0 GiB ext4")]
    #[case(Some("zfs_member"), "/dev/sda1 — 1.0 GiB ZFS")]
    #[case(Some("LVM2_member"), "/dev/sda1 — 1.0 GiB LVM")]
    #[case(None, "/dev/sda1 — 1.0 GiB no filesystem")]
    fn device_label_names_special_members(#[case] fstype: Option<&str>, #[case] expected: &str) {
        assert_eq!(device_label("/dev/sda1", 1 << 30, fstype), expected);
    }

    #[test]
    fn parses_lsblk_fixture_filtering_zvols_and_non_disks() {
        let json = r#"{
            "blockdevices": [
                {"name":"sda","type":"disk","size":4000787030016,"fstype":null,"model":"WDC WD40EFRX","serial":"WD-X","partlabel":null,"mountpoint":null,
                 "children":[
                    {"name":"sda1","type":"part","size":536870912,"fstype":"vfat","model":null,"serial":null,"partlabel":"boot","mountpoint":"/boot"},
                    {"name":"sda2","type":"part","size":4000248159744,"fstype":"ext4","model":null,"serial":null,"partlabel":null,"mountpoint":null}
                 ]},
                {"name":"nvme0n1","type":"disk","size":512110190592,"fstype":null,"model":"Samsung 980","serial":"S1","partlabel":null,"mountpoint":null,
                 "children":[
                    {"name":"nvme0n1p2","type":"part","size":1024,"fstype":"zfs_member","model":null,"serial":null,"partlabel":"x","mountpoint":null}
                 ]},
                {"name":"zd0","type":"disk","size":10737418240,"fstype":null,"model":null,"serial":null,"partlabel":null,"mountpoint":null},
                {"name":"sr0","type":"rom","size":1024,"fstype":null,"model":null,"serial":null,"partlabel":null,"mountpoint":null}
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
        assert_eq!(disks[0].partitions[0].fstype.as_deref(), Some("vfat"));
        assert_eq!(disks[0].partitions[1].fstype.as_deref(), Some("ext4"));
        assert_eq!(
            disks[1].partitions[0].fstype.as_deref(),
            Some("zfs_member"),
            "fstype surfaced for pool members"
        );
        assert_eq!(
            disks[1].partitions[0].number,
            Some(2),
            "nvme pN suffix parsed"
        );
        assert!(parse_lsblk("not json").is_err());
    }

    fn disk(name: &str, partitions: Vec<Partition>) -> Disk {
        Disk {
            name: name.into(),
            size: 100 << 30,
            model: None,
            serial: None,
            mountpoint: None,
            fstype: None,
            partitions,
        }
    }

    fn part(name: &str, mountpoint: Option<&str>, fstype: Option<&str>) -> Partition {
        Partition {
            name: name.into(),
            number: partition_number(name),
            size: 50 << 30,
            label: None,
            mountpoint: mountpoint.map(Into::into),
            fstype: fstype.map(Into::into),
        }
    }

    #[test]
    fn available_filters_mounted_zfs_member_and_in_use() {
        let disks = vec![
            // partitioned: only the unmounted, non-zfs_member, non-in-use part.
            disk(
                "sda",
                vec![
                    part("sda1", Some("/boot"), Some("vfat")), // mounted → out
                    part("sda2", None, Some("ext4")),          // available
                    part("sda3", None, Some("zfs_member")),    // pool member → out
                    part("sda4", None, None),                  // in_use → out
                    part("sda5", None, Some("LVM2_member")),   // LVM PV → out
                ],
            ),
            // empty disk → offered whole.
            disk("sdb", vec![]),
            // mounted whole disk → out.
            Disk {
                mountpoint: Some("/data".into()),
                ..disk("sdc", vec![])
            },
            // zfs_member whole disk → out.
            Disk {
                fstype: Some("zfs_member".into()),
                ..disk("sdd", vec![])
            },
        ];
        let zvols = vec![
            ("tank/vm1".to_string(), 10 << 30),
            ("tank/used".to_string(), 5 << 30), // in_use → out
        ];
        let lvs = vec![
            ("/dev/vg0/data".to_string(), 8 << 30),
            ("/dev/vg0/used".to_string(), 4 << 30), // in_use → out
        ];
        let in_use = HashSet::from([
            "/dev/sda4".to_string(),
            "/dev/zvol/tank/used".to_string(),
            "/dev/vg0/used".to_string(),
        ]);

        let avail = available_from_disks(&disks, &zvols, &lvs, &in_use);
        let paths: Vec<&str> = avail.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/dev/sda2",
                "/dev/sdb",
                "/dev/zvol/tank/vm1",
                "/dev/vg0/data"
            ]
        );

        let sda2 = &avail[0];
        assert_eq!(sda2.kind, AvailKind::Partition);
        assert!(sda2.label.contains("/dev/sda2") && sda2.label.contains("ext4"));
        assert_eq!(avail[1].kind, AvailKind::WholeDisk);
        assert_eq!(avail[2].kind, AvailKind::Zvol);
        assert!(avail[2].label.starts_with("zvol tank/vm1"));
        assert_eq!(avail[3].kind, AvailKind::Lv);
        assert!(avail[3].label.starts_with("LV vg0/data"));
    }
}
