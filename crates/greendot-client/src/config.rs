//! The on-disk target list: `/etc/greendot-client/targets.toml`, mode 0640
//! (it holds bearer tokens; the `greendot-client` group both reads it and may
//! drive the agent, so group-readability adds no privilege). Written
//! atomically (tmp + rename). Actual connections/mounts are never persisted —
//! they are re-derived from /sys and /proc/mounts.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/greendot-client";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetEntry {
    /// Alias; defaults to the target's hostname from `GET /target`.
    pub name: String,
    /// `host` or `host:port` of the target's web UI.
    pub host: String,
    /// The raw bearer token from the connection string.
    pub token: String,
    /// The pinned TLS fingerprint; `None` = plain-HTTP target.
    #[serde(default)]
    pub cert_sha256: Option<String>,
}

impl TargetEntry {
    pub fn pairing(&self) -> crate::pairing::Pairing {
        crate::pairing::Pairing {
            token: self.token.clone(),
            host: self.host.clone(),
            fingerprint: self.cert_sha256.clone(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Doc {
    target: Vec<TargetEntry>,
}

pub struct Targets {
    path: PathBuf,
    doc: Doc,
}

impl Targets {
    pub fn load(dir: &Path) -> Result<Targets> {
        let path = dir.join("targets.toml");
        let doc = match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Doc::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Targets { path, doc })
    }

    fn save(&self) -> Result<()> {
        let dir = self.path.parent().expect("targets.toml has a parent");
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let text = toml::to_string_pretty(&self.doc).context("serializing targets")?;
        let tmp = self.path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o640))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming into {}", self.path.display()))?;
        Ok(())
    }

    pub fn list(&self) -> &[TargetEntry] {
        &self.doc.target
    }

    /// Finds a target by alias or host.
    pub fn find(&self, key: &str) -> Result<&TargetEntry> {
        self.doc
            .target
            .iter()
            .find(|t| t.name == key || t.host == key)
            .with_context(|| format!("no target {key:?} — see `greendot-client list`"))
    }

    pub fn add(&mut self, entry: TargetEntry) -> Result<()> {
        if entry.name.is_empty() || entry.name.contains(['/', ' ']) {
            bail!("invalid target name {:?}", entry.name);
        }
        if let Some(t) = self
            .doc
            .target
            .iter()
            .find(|t| t.name == entry.name || t.host == entry.host)
        {
            bail!(
                "target {:?} ({}) already exists — `remove` it first to re-pair",
                t.name,
                t.host
            );
        }
        self.doc.target.push(entry);
        self.save()
    }

    pub fn remove(&mut self, key: &str) -> Result<TargetEntry> {
        let idx = self
            .doc
            .target
            .iter()
            .position(|t| t.name == key || t.host == key)
            .with_context(|| format!("no target {key:?}"))?;
        let removed = self.doc.target.remove(idx);
        self.save()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, host: &str) -> TargetEntry {
        TargetEntry {
            name: name.into(),
            host: host.into(),
            token: "gdt_x".into(),
            cert_sha256: Some("ab".repeat(32)),
        }
    }

    #[test]
    fn add_find_remove_persist_and_permissions() {
        let dir = std::env::temp_dir().join(format!("gd-client-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();

        let mut t = Targets::load(&dir).unwrap();
        assert!(t.list().is_empty(), "missing file is an empty list");
        t.add(entry("nas1", "10.0.0.5:8443")).unwrap();
        t.add(entry("nas2", "10.0.0.6:8443")).unwrap();
        // Duplicate alias or host rejected; bad names rejected.
        assert!(t.add(entry("nas1", "10.0.0.9:1")).is_err());
        assert!(t.add(entry("other", "10.0.0.5:8443")).is_err());
        assert!(t.add(entry("has space", "h:1")).is_err());

        // find by alias or host; pairing round-trips the stored fields.
        assert_eq!(t.find("nas2").unwrap().host, "10.0.0.6:8443");
        assert_eq!(t.find("10.0.0.6:8443").unwrap().name, "nas2");
        assert!(t.find("nope").is_err());
        let p = t.find("nas1").unwrap().pairing();
        assert_eq!(
            (p.host.as_str(), p.token.as_str(), p.fingerprint.is_some()),
            ("10.0.0.5:8443", "gdt_x", true)
        );

        // 0640 on the written file.
        let mode = std::os::unix::fs::MetadataExt::mode(
            &std::fs::metadata(dir.join("targets.toml")).unwrap(),
        );
        assert_eq!(mode & 0o777, 0o640);

        // Reload from disk and remove.
        let mut t = Targets::load(&dir).unwrap();
        assert_eq!(t.list().len(), 2);
        assert_eq!(t.remove("nas1").unwrap().name, "nas1");
        let t = Targets::load(&dir).unwrap();
        assert_eq!(t.list().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
