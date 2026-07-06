//! Desired-state domain types and a read-only loader. The export/settings config
//! is the source of truth and lives in a hand-editable TOML file. The web
//! service owns writing it (via its SQLite-backed `Db`); reconciliation only
//! ever *reads* it here, so this module carries no database dependency.

use anyhow::{Context, Result};
use greendot_proto::{Iqn, Nqn, PciAddress};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

/// Every export we create lives under these prefixes; reconciliation never
/// touches configfs objects outside them. Defined in the shared protocol crate
/// so the helper scopes its configfs writes to the same prefix.
pub use greendot_proto::{OUR_IQN_PREFIX, OUR_NQN_PREFIX};

/// A block-device export served as an NVMe-oF subsystem. RDMA, TCP and the
/// local loopback are all valid transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeExport {
    pub id: i64,
    pub name: String,
    pub device_path: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub want_rdma: bool,
    pub want_tcp: bool,
    #[serde(default)]
    pub want_loop: bool,
    #[serde(default = "default_true")]
    pub allow_any_host: bool,
    #[serde(default)]
    pub initiators: Vec<String>,
    /// Physical ports this export listens on, as scheme-tagged selectors
    /// (`pci:0000:00:10.0`); empty means "the global default listen address".
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl NvmeExport {
    pub fn nqn(&self) -> Nqn {
        Nqn::new(format!("{OUR_NQN_PREFIX}{}", self.name))
            .expect("validated name forms a valid NQN")
    }
}

/// A block-device export served as an iSCSI target. RDMA is iSER; there is no
/// loopback transport (so no `want_loop`), and connected sessions are tracked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IscsiExport {
    pub id: i64,
    pub name: String,
    pub device_path: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub want_rdma: bool,
    pub want_tcp: bool,
    #[serde(default = "default_true")]
    pub allow_any_host: bool,
    #[serde(default)]
    pub initiators: Vec<String>,
    /// Physical ports this export listens on, as scheme-tagged selectors
    /// (`pci:0000:00:10.0`); empty means "the global default listen address".
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl IscsiExport {
    pub fn iqn(&self) -> Iqn {
        Iqn::new(format!("{OUR_IQN_PREFIX}{}", self.name))
            .expect("validated name forms a valid IQN")
    }
}

/// Parses a stored listen-interface selector into the physical port it pins.
/// The scheme prefix tags the identifier type so future schemes (`mac:`,
/// `name:`) can be added without breaking saved configs; unknown schemes (and
/// malformed addresses) parse to `None` and are skipped — graceful forward-compat.
pub fn parse_listen_iface(s: &str) -> Option<PciAddress> {
    s.strip_prefix("pci:")
        .and_then(|addr| PciAddress::new(addr).ok())
}

/// A file-level NFS export of an absolute directory path, served over RDMA.
/// Unlike a block-device export, this has a directory path and a list of
/// client access specs — different enough to warrant its own type/table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsExport {
    pub id: i64,
    pub path: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub clients: Vec<NfsClientEntry>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsClientEntry {
    pub client: String,
    #[serde(default = "default_true")]
    pub rw: bool,
}

pub(crate) fn default_true() -> bool {
    true
}

/// The desired state needed to reconcile, read straight from the config TOML.
pub struct Desired {
    pub nvme_exports: Vec<NvmeExport>,
    pub iscsi_exports: Vec<IscsiExport>,
    pub nfs_exports: Vec<NfsExport>,
    pub listen: IpAddr,
}

/// A read-only projection of the desired-state TOML: only the export tables and
/// `settings` matter to reconciliation. Unknown keys (snapshot policies, id
/// counters — owned by the web's `Db`) are ignored. A pre-split unified `export`
/// table is migrated forward in memory so a not-yet-upgraded config still
/// reconciles; the web service is the one that rewrites it on disk.
#[derive(Default, Deserialize)]
#[serde(default)]
struct DesiredDoc {
    settings: BTreeMap<String, String>,
    nvme_export: Vec<NvmeExport>,
    iscsi_export: Vec<IscsiExport>,
    nfs_export: Vec<NfsExport>,
    #[serde(rename = "export")]
    legacy_export: Vec<LegacyExport>,
}

/// The pre-split unified export row, read only to fold it into the typed tables.
#[derive(Deserialize)]
struct LegacyExport {
    id: i64,
    #[serde(default)]
    kind: String,
    name: String,
    device_path: String,
    #[serde(default = "default_true")]
    enabled: bool,
    want_rdma: bool,
    want_tcp: bool,
    #[serde(default)]
    want_loop: bool,
    #[serde(default = "default_true")]
    allow_any_host: bool,
    #[serde(default)]
    initiators: Vec<String>,
    #[serde(default)]
    last_error: Option<String>,
}

/// Folds a pre-split unified `export` table into the typed tables (ids preserved).
/// Read-only, so unlike the web's `Db` migration it seeds no id counters.
fn fold_legacy(doc: &mut DesiredDoc) {
    for e in std::mem::take(&mut doc.legacy_export) {
        if e.kind == "iscsi" {
            doc.iscsi_export.push(IscsiExport {
                id: e.id,
                name: e.name,
                device_path: e.device_path,
                enabled: e.enabled,
                want_rdma: e.want_rdma,
                want_tcp: e.want_tcp,
                allow_any_host: e.allow_any_host,
                initiators: e.initiators,
                interfaces: Vec::new(),
                last_error: e.last_error,
            });
        } else {
            doc.nvme_export.push(NvmeExport {
                id: e.id,
                name: e.name,
                device_path: e.device_path,
                enabled: e.enabled,
                want_rdma: e.want_rdma,
                want_tcp: e.want_tcp,
                want_loop: e.want_loop,
                allow_any_host: e.allow_any_host,
                initiators: e.initiators,
                interfaces: Vec::new(),
                last_error: e.last_error,
            });
        }
    }
}

/// Reads the desired state from `state_path` with no side effects (no SQLite,
/// no first-boot write), so a standalone `greendotctl reconcile` only ever
/// *reads* config — the web service stays the sole writer. Exports are
/// normalized exactly as `Db::list_nvme_exports`/`list_iscsi_exports` return them.
pub fn read_desired(state_path: &Path) -> Result<Desired> {
    let mut doc = match std::fs::read_to_string(state_path) {
        Ok(text) => toml::from_str::<DesiredDoc>(&text)
            .with_context(|| format!("parsing {}", state_path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DesiredDoc::default(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", state_path.display())),
    };
    fold_legacy(&mut doc);
    let mut nvme_exports = doc.nvme_export;
    nvme_exports.sort_by(|a, b| a.name.cmp(&b.name));
    for e in &mut nvme_exports {
        e.initiators.sort();
    }
    let mut iscsi_exports = doc.iscsi_export;
    iscsi_exports.sort_by(|a, b| a.name.cmp(&b.name));
    for e in &mut iscsi_exports {
        e.initiators.sort();
    }
    let mut nfs_exports = doc.nfs_export;
    nfs_exports.sort_by(|a, b| a.path.cmp(&b.path));
    let listen = doc
        .settings
        .get("listen_addr")
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    Ok(Desired {
        nvme_exports,
        iscsi_exports,
        nfs_exports,
        listen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_iface_accepts_pci_scheme_only() {
        // A `pci:`-tagged valid address parses to its bare PCI address.
        assert_eq!(
            parse_listen_iface("pci:0000:00:10.0").map(|p| p.to_string()),
            Some("0000:00:10.0".to_owned())
        );
        // An unknown scheme, a missing scheme, and a malformed address all reject
        // (so future schemes stay forward-compatible and bad input is skipped).
        assert!(parse_listen_iface("mac:00:11:22:33:44:55").is_none());
        assert!(parse_listen_iface("0000:00:10.0").is_none());
        assert!(parse_listen_iface("pci:nonsense").is_none());
    }

    #[test]
    fn read_desired_normalizes_and_migrates_legacy_and_missing_is_empty() {
        // Missing file → an empty desired state with the unspecified listen addr.
        let missing = read_desired(Path::new("/nonexistent/gd-state.toml")).unwrap();
        assert!(missing.nvme_exports.is_empty() && missing.iscsi_exports.is_empty());
        assert_eq!(
            missing.listen,
            IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED)
        );

        // A pre-split unified `export` table (tagged with `kind`) plus typed NFS
        // and a `listen_addr` setting — exports are split, sorted, and initiators
        // sorted, exactly like the web's `Db` returns them.
        let state =
            std::env::temp_dir().join(format!("gd-readdesired-{}.toml", std::process::id()));
        std::fs::write(
            &state,
            r#"
[settings]
listen_addr = "10.0.0.5"

[[export]]
id = 2
kind = "nvme"
name = "vm2"
device_path = "/dev/zvol/tank/vm2"
want_rdma = true
want_tcp = false
initiators = ["nqn.b", "nqn.a"]

[[export]]
id = 1
kind = "iscsi"
name = "tape"
device_path = "/dev/zvol/tank/tape"
want_rdma = true
want_tcp = false

[[nfs_export]]
id = 1
path = "/tank/share"
"#,
        )
        .unwrap();
        let d = read_desired(&state).unwrap();
        assert_eq!(d.listen, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(
            d.nvme_exports.iter().map(|e| &e.name).collect::<Vec<_>>(),
            ["vm2"]
        );
        // Initiators were sorted on read.
        assert_eq!(d.nvme_exports[0].initiators, ["nqn.a", "nqn.b"]);
        assert_eq!(
            d.iscsi_exports.iter().map(|e| &e.name).collect::<Vec<_>>(),
            ["tape"]
        );
        assert_eq!(
            d.nfs_exports.iter().map(|e| &e.path).collect::<Vec<_>>(),
            ["/tank/share"]
        );
        std::fs::remove_file(&state).ok();
    }
}
