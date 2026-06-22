use crate::validate;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub what: &'static str,
    pub value: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {:?}", self.what, self.value)
    }
}

impl std::error::Error for ValidationError {}

/// A string newtype that can only hold values accepted by its validator.
/// Validation also runs on deserialization, so decoding a request is enough
/// to re-validate it.
macro_rules! validated_string {
    ($(#[$doc:meta])* $name:ident, $validator:path, $what:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
                let s = s.into();
                if $validator(&s) {
                    Ok(Self(s))
                } else {
                    Err(ValidationError { what: $what, value: s })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = ValidationError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

validated_string!(
    /// ZFS dataset/zvol name, e.g. `tank/vols/vm1`.
    DatasetName, validate::dataset_name, "dataset name");
validated_string!(
    /// ZFS snapshot name (the part after `@`).
    SnapName, validate::snap_name, "snapshot name");
validated_string!(
    /// NVMe qualified name, e.g. `nqn.2026-06.io.greendot:vm1`.
    Nqn, validate::nqn, "NQN");
validated_string!(
    /// iSCSI qualified name, e.g. `iqn.2026-06.io.greendot:vm1`.
    Iqn, validate::iqn, "IQN");
validated_string!(
    /// Bare kernel block device name, e.g. `sda`, `nvme0n1`.
    BlockDev, validate::block_dev, "block device");
validated_string!(
    /// Absolute device path: `/dev/zvol/<dataset>` or `/dev/<dev>`.
    DevicePath, validate::device_path, "device path");
validated_string!(
    /// Network interface name (IFNAMSIZ-limited).
    NetdevName, validate::netdev, "netdev name");
validated_string!(
    /// PCI device address `DOMAIN:BUS:DEV.FUNC`, e.g. `0000:00:10.0` (the
    /// `pci/` prefix is added by the helper, not stored here).
    PciAddress, validate::pci_address, "PCI address");
validated_string!(
    /// LIO backstore name.
    BackstoreName, validate::backstore_name, "backstore name");
validated_string!(
    /// GPT partition label.
    PartLabel, validate::part_label, "partition label");
validated_string!(
    /// System (PAM) user name.
    Username, validate::username, "username");
validated_string!(
    /// Short export name; becomes the NQN/IQN suffix.
    ExportName, validate::export_name, "export name");
validated_string!(
    /// A Debian/Ubuntu package name (for the install task).
    PackageName, validate::package_name, "package name");
validated_string!(
    /// ZFS pool name (the first component of a dataset path).
    PoolName, validate::pool_name, "pool name");
validated_string!(
    /// LVM volume-group name, e.g. `vg0`.
    VgName, validate::lvm_name, "volume group name");
validated_string!(
    /// LVM logical-volume name, e.g. `data`.
    LvName, validate::lvm_name, "logical volume name");
validated_string!(
    /// The helper's private btrfs temp-mount path (fixed shape, no traversal).
    MountPath, validate::mount_path, "mount path");
validated_string!(
    /// Absolute directory path to export over NFS, e.g. `/tank/share`.
    NfsExportPath, validate::nfs_export_path, "NFS export path");
validated_string!(
    /// A ZFS filesystem dataset's mountpoint (an absolute path); shares the
    /// export-path validator but is a distinct type from [`NfsExportPath`].
    MountPoint, validate::nfs_export_path, "mount point");
validated_string!(
    /// An NFS client access spec: host / IP / CIDR / `*`.
    NfsClient, validate::nfs_client, "NFS client");

/// A string whose Debug/Display output must never leak (passwords).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Rdma,
    Tcp,
    Loop,
}

impl Transport {
    /// Value written to nvmet's `addr_trtype` configfs attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Rdma => "rdma",
            Transport::Tcp => "tcp",
            Transport::Loop => "loop",
        }
    }
}

/// How `zpool create` should arrange the chosen devices into one top-level vdev.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VdevLayout {
    Stripe,
    Mirror,
    Raidz1,
    Raidz2,
    Raidz3,
}

impl VdevLayout {
    /// The `zpool create` vdev keyword, or `None` for a plain stripe (which
    /// takes no keyword — the devices are listed bare).
    pub fn keyword(self) -> Option<&'static str> {
        match self {
            VdevLayout::Stripe => None,
            VdevLayout::Mirror => Some("mirror"),
            VdevLayout::Raidz1 => Some("raidz1"),
            VdevLayout::Raidz2 => Some("raidz2"),
            VdevLayout::Raidz3 => Some("raidz3"),
        }
    }

    /// Minimum device count `zpool` requires for this layout.
    pub fn min_devices(self) -> usize {
        match self {
            VdevLayout::Stripe => 1,
            VdevLayout::Mirror | VdevLayout::Raidz1 => 2,
            VdevLayout::Raidz2 => 3,
            VdevLayout::Raidz3 => 4,
        }
    }

    /// Parses a form value (`stripe`/`mirror`/`raidz1`…) into a layout.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "stripe" => VdevLayout::Stripe,
            "mirror" => VdevLayout::Mirror,
            "raidz1" => VdevLayout::Raidz1,
            "raidz2" => VdevLayout::Raidz2,
            "raidz3" => VdevLayout::Raidz3,
            _ => return None,
        })
    }
}

/// Which LVM reporting command the helper should run on the web side's behalf.
/// LVM reporting needs root, so these reads go through the helper (unlike ZFS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LvmReport {
    Vgs,
    Lvs,
    Pvs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModule {
    NvmetLoop,
    NvmetTcp,
    NvmetRdma,
    Iscsi,
    Iser,
    Rxe,
    /// The kernel's NFS-over-RDMA transport. The real module is `rpcrdma`;
    /// `svcrdma` (server) and `xprtrdma` (client) are aliases for it.
    Rpcrdma,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChapCreds {
    pub username: String,
    pub password: Secret,
}

/// Export health as shown in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DotState {
    /// Served via RDMA.
    Green,
    /// Served, but not via RDMA.
    Yellow,
    /// Not served.
    Red,
}

/// Every export we create lives under these prefixes; reconciliation only
/// touches configfs objects whose NQN/IQN starts with them, leaving any
/// foreign (manually created) objects untouched.
pub const OUR_NQN_PREFIX: &str = "nqn.2026-06.io.greendot:";
pub const OUR_IQN_PREFIX: &str = "iqn.2026-06.io.greendot:";

// ---- Desired-state documents (the helper applies NvmetDesired directly to
// configfs; LioDesired is rendered to targetctl JSON and applied via restore) ----

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmetDesired {
    pub subsystems: Vec<NvmetSubsysSpec>,
    pub ports: Vec<NvmetPortSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmetSubsysSpec {
    pub nqn: Nqn,
    pub allow_any_host: bool,
    pub allowed_hosts: Vec<Nqn>,
    pub namespaces: Vec<NvmetNsSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmetNsSpec {
    pub nsid: u32,
    pub device_path: DevicePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmetPortSpec {
    pub id: u16,
    pub trtype: Transport,
    pub traddr: IpAddr,
    pub trsvcid: u16,
    /// NQNs linked to this port.
    pub subsystems: Vec<Nqn>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LioDesired {
    pub backstores: Vec<LioBackstoreSpec>,
    pub targets: Vec<LioTargetSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LioBackstoreSpec {
    pub name: BackstoreName,
    pub device_path: DevicePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LioTargetSpec {
    pub iqn: Iqn,
    pub enabled: bool,
    pub demo_mode: bool,
    pub luns: Vec<LioLunSpec>,
    pub portals: Vec<LioPortalSpec>,
    pub acls: Vec<Iqn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LioLunSpec {
    pub lun: u32,
    pub backstore: BackstoreName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LioPortalSpec {
    pub addr: IpAddr,
    pub port: u16,
    pub iser: bool,
}

// ---- NFS desired state (the helper writes our exports file directly and
// applies it surgically with `exportfs -o`/`-u`, leaving foreign exports and
// ZFS's own `/etc/exports.d/zfs.exports` untouched — no global `exportfs -ra`) ----

/// The standard NFS-over-RDMA service port (`nfsrdma`).
pub const NFS_RDMA_PORT: u16 = 20049;

/// Separates the three sections of an `NfsReport`'s streamed stdout — the live
/// `exportfs -s` dump, the `/proc/fs/nfsd/portlist` dump, and greendot's own
/// managed exports file (what it last applied, used for drift detection) — so
/// the web can parse one payload.
pub const NFS_PORTLIST_SENTINEL: &str = "--greendot-portlist--";
pub const NFS_MANAGED_SENTINEL: &str = "--greendot-managed--";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsDesired {
    pub exports: Vec<NfsExportSpec>,
    /// The RDMA listener port to assert on nfsd (normally [`NFS_RDMA_PORT`]).
    pub rdma_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsExportSpec {
    pub path: NfsExportPath,
    /// Stable per-export filesystem id, required for non-block-backed exports
    /// (the web derives it from the export id, offset into a reserved range).
    pub fsid: u32,
    pub clients: Vec<NfsClientSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsClientSpec {
    pub client: NfsClient,
    pub rw: bool,
}

// ---- Task streaming ----

/// Frames the helper streams back while running a task (one CLI command).
/// Terminated by exactly one `Finished`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum TaskEvent {
    /// The exact command being run; `stdin` is the input fed to it, if any.
    Started {
        command: String,
        args: Vec<String>,
        stdin: Option<String>,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    /// `error` is set for spawn failures (e.g. the CLI is not installed) and
    /// carries a human-actionable message; `ok` is the overall success.
    Finished {
        exit: i32,
        ok: bool,
        error: Option<String>,
    },
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
];

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // dataset names
    #[case::pool("tank", true)]
    #[case::nested("tank/vols/vm-100", true)]
    #[case::charset("tank/a-b_c.d:e", true)]
    #[case::empty("", false)]
    #[case::absolute("/tank", false)]
    #[case::trailing_slash("tank/", false)]
    #[case::double_slash("tank//a", false)]
    #[case::leading_dash("-tank", false)]
    #[case::component_dash("tank/-x", false)]
    #[case::dotdot("tank/..", false)]
    #[case::space("tank/a b", false)]
    #[case::shell_meta("tank/$(reboot)", false)]
    #[case::newline("tank/a\nb", false)]
    #[case::too_long(&"a/".repeat(200), false)]
    fn dataset_name(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(DatasetName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::auto("greendot-auto-20260613-020000", true)]
    #[case::charset("a-b_c.d:e", true)]
    #[case::empty("", false)]
    #[case::slash("a/b", false)]
    #[case::at_sign("tank@snap", false)]
    #[case::leading_dash("-snap", false)]
    fn snap_name(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(SnapName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::greendot("nqn.2026-06.io.greendot:vm1", true)]
    #[case::uuid(
        "nqn.2014-08.org.nvmexpress:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
        true
    )]
    #[case::empty("", false)]
    #[case::no_prefix("foo.2026-06.io.greendot", false)]
    #[case::bare_prefix("nqn.", false)]
    #[case::slash("nqn.2026-06.io.greendot/x", false)]
    #[case::space("nqn.2026-06.io greendot", false)]
    #[case::too_long(&format!("nqn.{}", "a".repeat(224)), false)]
    fn nqn(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(Nqn::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("iqn.2026-06.io.greendot:vm1", true)]
    #[case::initiator("iqn.1993-08.org.debian:01:abcdef12345", true)]
    #[case::empty("", false)]
    #[case::uppercase("iqn.2026-06.io.GREENDOT:vm1", false)]
    #[case::no_prefix("nqn.2026-06.io.greendot:vm1", false)]
    #[case::slash("iqn.2026-06.io.greendot/x", false)]
    fn iqn(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(Iqn::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::sata("sda", true)]
    #[case::nvme("nvme0n1", true)]
    #[case::loopdev("loop0", true)]
    #[case::empty("", false)]
    #[case::path("/dev/sda", false)]
    #[case::traversal("..", false)]
    #[case::uppercase("SDA", false)]
    #[case::leading_digit("0sda", false)]
    fn block_dev(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(BlockDev::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::disk("/dev/sda", true)]
    #[case::partition("/dev/nvme0n1p2", true)]
    #[case::zvol("/dev/zvol/tank/vols/vm1", true)]
    #[case::lv("/dev/vg0/data", true)]
    #[case::empty("", false)]
    #[case::relative("dev/sda", false)]
    #[case::traversal("/dev/../etc/shadow", false)]
    #[case::zvol_traversal("/dev/zvol/../sda", false)]
    #[case::lv_traversal("/dev/vg0/../sda", false)]
    #[case::lv_three_components("/dev/a/b/c", false)]
    #[case::outside_dev("/etc/passwd", false)]
    #[case::trailing("/dev/sda ", false)]
    fn device_path(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(DevicePath::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("vg0", true)]
    #[case::charset("vg-1_a.b+2", true)]
    #[case::empty("", false)]
    #[case::slash("vg/lv", false)]
    #[case::leading_dash("-vg", false)]
    #[case::dotdot("..", false)]
    #[case::too_long(&"a".repeat(128), false)]
    fn lvm_names(#[case] input: &str, #[case] ok: bool) {
        // VgName and LvName share the same validator.
        assert_eq!(VgName::new(input).is_ok(), ok, "{input:?}");
        assert_eq!(LvName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::eth("eth0", true)]
    #[case::predictable("enp3s0f0", true)]
    #[case::bridge("br-lan", true)]
    #[case::empty("", false)]
    #[case::slash("eth0/x", false)]
    #[case::dot(".", false)]
    #[case::dotdot("..", false)]
    #[case::too_long("abcdefghijklmnop", false)]
    fn netdev(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(NetdevName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::vf("0000:00:10.0", true)]
    #[case::pf("0000:3b:00.1", true)]
    #[case::hex_bus("0000:af:1e.7", true)]
    #[case::empty("", false)]
    #[case::no_domain("00:10.0", false)]
    #[case::uppercase("0000:00:10.A", false)]
    #[case::func_too_high("0000:00:10.8", false)]
    #[case::func_hex("0000:00:10.f", false)]
    #[case::short_domain("000:00:10.0", false)]
    #[case::trailing_space("0000:00:10.0 ", false)]
    #[case::slash("0000:00/10.0", false)]
    fn pci_address(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(PciAddress::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("vm1-disk", true)]
    #[case::empty("", false)]
    #[case::slash("a/b", false)]
    #[case::leading_dot(".hidden", false)]
    fn backstore_name(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(BackstoreName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("data", true)]
    #[case::empty("", false)]
    #[case::comma("a,b", false)]
    #[case::quote("a\"b", false)]
    #[case::too_long(&"a".repeat(37), false)]
    fn part_label(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(PartLabel::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("vm1", true)]
    #[case::dashed("vm1-data.0", true)]
    #[case::empty("", false)]
    #[case::uppercase("VM1", false)]
    #[case::underscore("vm_1", false)]
    #[case::slash("vm/1", false)]
    #[case::leading_dash("-vm", false)]
    fn export_name(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(ExportName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("targetctl", true)]
    #[case::fb("targetcli-fb", true)]
    #[case::plus("libstdc++6", true)]
    #[case::empty("", false)]
    #[case::space("a b", false)]
    #[case::uppercase("Nvmetcli", false)]
    #[case::shell_meta("foo;rm", false)]
    fn package_name(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(PackageName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("tank", true)]
    #[case::dashed("fast-pool.1", true)]
    #[case::colon("rpool:0", true)]
    #[case::empty("", false)]
    #[case::leading_digit("0pool", false)]
    #[case::leading_dash("-pool", false)]
    #[case::slash("a/b", false)]
    #[case::space("a b", false)]
    #[case::reserved_mirror("mirror", false)]
    #[case::reserved_raidz("raidz2", false)]
    #[case::reserved_case("RaidZ1", false)]
    #[case::reserved_cache("cache", false)]
    #[case::controller_ok("c3pool", true)]
    #[case::too_long(&"a".repeat(256), false)]
    fn pool_name(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(PoolName::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::sda("/run/greendotrdma/btrfs-resize-sda3", true)]
    #[case::nvme("/run/greendotrdma/btrfs-resize-nvme0n1p2", true)]
    #[case::empty("", false)]
    #[case::wrong_prefix("/run/greendotrdma/sda3", false)]
    #[case::traversal("/run/greendotrdma/btrfs-resize-../etc", false)]
    #[case::trailing_slash("/run/greendotrdma/btrfs-resize-sda3/", false)]
    #[case::path_in_name("/run/greendotrdma/btrfs-resize-/dev/sda", false)]
    fn mount_path(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(MountPath::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::simple("/tank/share", true)]
    #[case::deep("/mnt/archive/backups-2026", true)]
    #[case::dotted("/var/nfs.data.0", true)]
    #[case::root_only("/", false)]
    #[case::empty("", false)]
    #[case::relative("tank/share", false)]
    #[case::trailing_slash("/tank/share/", false)]
    #[case::double_slash("/tank//share", false)]
    #[case::traversal("/tank/../etc/shadow", false)]
    #[case::dot_component("/tank/./share", false)]
    #[case::space("/tank/a b", false)]
    #[case::shell_meta("/tank/$(reboot)", false)]
    fn nfs_export_path(#[case] input: &str, #[case] ok: bool) {
        // NfsExportPath and MountPoint share the validator.
        assert_eq!(NfsExportPath::new(input).is_ok(), ok, "{input:?}");
        assert_eq!(MountPoint::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::wildcard("*", true)]
    #[case::host("nfs-client.example.com", true)]
    #[case::ipv4("192.168.1.10", true)]
    #[case::cidr("192.168.101.0/24", true)]
    #[case::ipv6_cidr("2001:db8::/32", true)]
    #[case::empty("", false)]
    #[case::space("a b", false)]
    #[case::comma("a,b", false)]
    #[case::open_paren("host(rw", false)]
    #[case::close_paren("host)", false)]
    #[case::leading_dash_r("-r", false)]
    #[case::leading_dash_a("-a", false)]
    #[case::leading_dash_word("-foo", false)]
    fn nfs_client(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(NfsClient::new(input).is_ok(), ok, "{input:?}");
    }

    #[rstest]
    #[case::stripe(VdevLayout::Stripe, None, 1)]
    #[case::mirror(VdevLayout::Mirror, Some("mirror"), 2)]
    #[case::raidz1(VdevLayout::Raidz1, Some("raidz1"), 2)]
    #[case::raidz2(VdevLayout::Raidz2, Some("raidz2"), 3)]
    #[case::raidz3(VdevLayout::Raidz3, Some("raidz3"), 4)]
    fn vdev_layout(#[case] layout: VdevLayout, #[case] keyword: Option<&str>, #[case] min: usize) {
        assert_eq!(layout.keyword(), keyword);
        assert_eq!(layout.min_devices(), min);
        // parse() round-trips the snake_case form value.
        let form = keyword.unwrap_or("stripe");
        assert_eq!(VdevLayout::parse(form), Some(layout));
        assert_eq!(VdevLayout::parse("nonsense"), None);
    }

    #[test]
    fn cli_to_package_map() {
        assert_eq!(package_for_cli("targetctl"), Some("targetcli-fb"));
        assert_eq!(package_for_cli("zpool"), Some("zfsutils-linux"));
        assert_eq!(package_for_cli("devlink"), Some("iproute2"));
        assert_eq!(package_for_cli("nonesuch"), None);
        // every required CLI maps to a valid package name
        for cli in REQUIRED_CLIS {
            let pkg = package_for_cli(cli).unwrap_or_else(|| panic!("no package for {cli}"));
            assert!(PackageName::new(pkg).is_ok(), "{pkg}");
        }
    }

    #[rstest]
    #[case::simple("alice", true)]
    #[case::system("_apt", true)]
    #[case::dotted("john.doe", true)]
    #[case::empty("", false)]
    #[case::leading_digit("1alice", false)]
    #[case::space("a b", false)]
    #[case::colon("a:b", false)]
    fn username(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(Username::new(input).is_ok(), ok, "{input:?}");
    }
}
