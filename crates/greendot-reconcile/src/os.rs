//! OS / packaging knowledge shared by greendot-web (dependency panel) and
//! greendotctl (install hints and the install task): best-effort OS /
//! package-manager detection from `/etc/os-release`, and the CLI → Debian
//! package map.

use std::fs;

/// The package-manager family we know how to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgFamily {
    /// Debian/Ubuntu and derivatives — `apt-get`.
    Debian,
    /// Anything without a package-manager mapping yet (dnf/pacman/zypper/…).
    Unsupported,
}

/// Detected OS, enough to pick an installer and label it in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    pub family: PkgFamily,
    /// Human label for messages/UI, e.g. "Ubuntu 26.04 LTS".
    pub pretty: String,
}

/// Parse the contents of an os-release file. Pure (no I/O) for testability.
pub fn parse_os_release(contents: &str) -> OsInfo {
    let (mut id, mut id_like, mut pretty) = (String::new(), String::new(), String::new());
    for line in contents.lines() {
        let Some((key, val)) = line.trim().split_once('=') else {
            continue;
        };
        let val = unquote(val.trim());
        match key.trim() {
            "ID" => id = val,
            "ID_LIKE" => id_like = val,
            "PRETTY_NAME" => pretty = val,
            _ => {}
        }
    }
    // Derivatives (Mint, Pop!_OS, Raspbian, …) carry debian/ubuntu in ID_LIKE.
    let debian = is_debian(&id) || id_like.split_whitespace().any(is_debian);
    let family = if debian {
        PkgFamily::Debian
    } else {
        PkgFamily::Unsupported
    };
    let pretty = [pretty, id, "unknown".to_string()]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap();
    OsInfo { family, pretty }
}

fn is_debian(id: &str) -> bool {
    matches!(id, "debian" | "ubuntu")
}

fn unquote(s: &str) -> String {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
        .to_string()
}

/// Detect the running system. Reads `/etc/os-release` (fallback
/// `/usr/lib/os-release`); unreadable → `Unsupported`/"unknown".
pub fn detect() -> OsInfo {
    fs::read_to_string("/etc/os-release")
        .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
        .map(|c| parse_os_release(&c))
        .unwrap_or_else(|_| OsInfo {
            family: PkgFamily::Unsupported,
            pretty: "unknown".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::ubuntu(
        "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\n",
        PkgFamily::Debian,
        "Ubuntu 26.04 LTS"
    )]
    #[case::debian(
        "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 13\"\n",
        PkgFamily::Debian,
        "Debian GNU/Linux 13"
    )]
    #[case::mint(
        "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nPRETTY_NAME=\"Linux Mint 22\"\n",
        PkgFamily::Debian,
        "Linux Mint 22"
    )]
    #[case::fedora(
        "ID=fedora\nPRETTY_NAME=\"Fedora Linux 41\"\n",
        PkgFamily::Unsupported,
        "Fedora Linux 41"
    )]
    #[case::arch(
        "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n",
        PkgFamily::Unsupported,
        "Arch Linux"
    )]
    #[case::nixos(
        "ID=nixos\nPRETTY_NAME=\"NixOS 25.11\"\n",
        PkgFamily::Unsupported,
        "NixOS 25.11"
    )]
    #[case::id_only("ID=fedora\n", PkgFamily::Unsupported, "fedora")]
    #[case::empty("", PkgFamily::Unsupported, "unknown")]
    fn parses_family_and_pretty(
        #[case] contents: &str,
        #[case] family: PkgFamily,
        #[case] pretty: &str,
    ) {
        let os = parse_os_release(contents);
        assert_eq!(os.family, family);
        assert_eq!(os.pretty, pretty);
    }
}

/// Maps a required CLI to the Debian/Ubuntu package that provides it. Used
/// both for the "not installed" hint and the install task.
pub fn package_for_cli(cli: &str) -> Option<&'static str> {
    Some(match cli {
        "zfs" | "zpool" => "zfsutils-linux",
        "vgs" | "lvs" | "pvs" | "vgcreate" | "vgextend" | "vgreduce" | "vgremove" | "lvcreate"
        | "lvremove" | "lvextend" | "lvreduce" | "lvrename" => "lvm2",
        "sfdisk" | "lsblk" | "mount" | "umount" => "util-linux",
        "resize2fs" | "e2fsck" => "e2fsprogs",
        "btrfs" => "btrfs-progs",
        "modprobe" => "kmod",
        "rdma" | "devlink" => "iproute2",
        "nvme" => "nvme-cli",
        "targetcli" | "targetctl" => "targetcli-fb",
        "exportfs" => "nfs-kernel-server",
        "smartctl" => "smartmontools",
        "apt-get" => "apt",
        _ => return None,
    })
}

/// Every CLI GreenDotRDMA may invoke, for the dependency panel.
pub const REQUIRED_CLIS: &[&str] = &[
    "zfs",
    "zpool",
    "vgs",
    "lvs",
    "sfdisk",
    "lsblk",
    "resize2fs",
    "e2fsck",
    "btrfs",
    "modprobe",
    "rdma",
    "devlink",
    "nvme",
    "targetctl",
    "exportfs",
    "smartctl",
];

#[cfg(test)]
mod package_tests {
    use super::*;
    use greendot_proto::PackageName;

    #[test]
    fn cli_to_package_map() {
        assert_eq!(package_for_cli("targetctl"), Some("targetcli-fb"));
        assert_eq!(package_for_cli("zpool"), Some("zfsutils-linux"));
        assert_eq!(package_for_cli("devlink"), Some("iproute2"));
        assert_eq!(package_for_cli("smartctl"), Some("smartmontools"));
        assert_eq!(package_for_cli("nonesuch"), None);
        // every required CLI maps to a valid package name
        for cli in REQUIRED_CLIS {
            let pkg = package_for_cli(cli).unwrap_or_else(|| panic!("no package for {cli}"));
            assert!(PackageName::new(pkg).is_ok(), "{pkg}");
        }
    }
}
