use crate::validate;
use serde::{Deserialize, Serialize};
use std::fmt;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelModule {
    NvmetLoop,
    NvmetTcp,
    NvmetRdma,
    Iscsi,
    Iser,
    Rxe,
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
    #[case::empty("", false)]
    #[case::relative("dev/sda", false)]
    #[case::traversal("/dev/../etc/shadow", false)]
    #[case::zvol_traversal("/dev/zvol/../sda", false)]
    #[case::outside_dev("/etc/passwd", false)]
    #[case::trailing("/dev/sda ", false)]
    fn device_path(#[case] input: &str, #[case] ok: bool) {
        assert_eq!(DevicePath::new(input).is_ok(), ok, "{input:?}");
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
