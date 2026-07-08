//! The LIO configfs view (/sys/kernel/config/target). The reader
//! (`greendot_reconcile::actual::lio`) fills these in from the live tree.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualLio {
    pub backstores: Vec<Backstore>,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backstore {
    pub name: String,
    pub udev_path: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub iqn: String,
    pub enabled: bool,
    pub demo_mode: bool,
    /// Backstore names linked as LUNs (we only use lun_0).
    pub luns: Vec<String>,
    pub portals: Vec<Portal>,
    pub acls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Portal {
    /// Directory name, e.g. `10.0.0.5:3260` or `[::1]:3260`.
    pub addr_port: String,
    pub iser: bool,
}

impl Portal {
    /// The address part, without the port.
    pub fn addr(&self) -> &str {
        let addr = self
            .addr_port
            .rsplit_once(':')
            .map_or(self.addr_port.as_str(), |(a, _)| a);
        addr.trim_start_matches('[').trim_end_matches(']')
    }
}

/// One live iSCSI session: a connected initiator on one of our targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IscsiSession {
    pub target_iqn: String,
    pub initiator_iqn: String,
    /// The raw `info` text for an explicit-ACL session (empty for demo-mode
    /// dynamic sessions, which expose no per-session attributes).
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::v4("10.0.0.5:3260", "10.0.0.5")]
    #[case::v6("[::1]:3260", "::1")]
    fn portal_addr_extraction(#[case] dirname: &str, #[case] want: &str) {
        let portal = Portal {
            addr_port: dirname.into(),
            iser: false,
        };
        assert_eq!(portal.addr(), want);
    }
}
