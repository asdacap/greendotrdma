//! Web-server configuration: the web-only keys (listen address, TLS,
//! databases) plus the flattened reconcile subset that `greendotctl
//! reconcile` also reads from the same TOML file.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Every key the config file may contain (ours + the flattened reconcile
/// subset). serde's `deny_unknown_fields` cannot be combined with `flatten`,
/// so [`Config::load`] checks this list to keep rejecting typos.
const KNOWN_KEYS: &[&str] = &[
    "listen",
    "db_path",
    "metrics_db_path",
    "tls_cert",
    "tls_key",
    "helper_socket",
    "state_path",
    "nvmet_root",
    "lio_root",
];

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    /// Task run-history (SQLite). The desired-state config lives in
    /// `reconcile.state_path`.
    pub db_path: PathBuf,
    pub metrics_db_path: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// The shared keys greendotctl also reads (socket, state, configfs roots).
    #[serde(flatten)]
    pub reconcile: greendot_proto::config::Config,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:8080".parse().unwrap(),
            db_path: "/var/lib/greendotrdma/state.db".into(),
            metrics_db_path: "/var/lib/greendotrdma/metrics.db".into(),
            tls_cert: None,
            tls_key: None,
            reconcile: greendot_proto::config::Config::default(),
        }
    }
}

impl Config {
    /// Loads from the given TOML file; missing argument means defaults.
    /// Unknown keys are rejected (a typo must not silently fall back to a
    /// default).
    pub fn load(path: Option<String>) -> Result<Self> {
        match path {
            None => Ok(Config::default()),
            Some(path) => {
                let text =
                    std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
                let table: toml::Table =
                    toml::from_str(&text).with_context(|| format!("parsing {path}"))?;
                if let Some(unknown) = table.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
                    bail!("unknown config key {unknown:?} in {path}");
                }
                toml::from_str(&text).with_context(|| format!("parsing {path}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_toml(tag: &str, body: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("gd-webcfg-{}-{tag}.toml", std::process::id()));
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn defaults_partial_override_flatten_and_errors() {
        // No path → built-in defaults.
        let d = Config::load(None).unwrap();
        assert_eq!(d.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(d.tls_cert, None);

        // A partial file overrides only its keys — including flattened
        // reconcile keys — and the rest keep their defaults.
        let path = temp_toml(
            "ok",
            "listen = \"0.0.0.0:9000\"\nstate_path = \"/tmp/state.toml\"\n",
        );
        let c = Config::load(Some(path.clone())).unwrap();
        assert_eq!(c.listen, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(c.reconcile.state_path, PathBuf::from("/tmp/state.toml"));
        assert_eq!(c.db_path, Config::default().db_path);
        assert_eq!(
            c.reconcile.helper_socket,
            Config::default().reconcile.helper_socket
        );
        std::fs::remove_file(&path).ok();

        // A missing file, a bad value, and an unknown key (typo) all error.
        assert!(Config::load(Some("/nonexistent/gd.toml".into())).is_err());
        let bad = temp_toml("bad", "listen = \"not-a-socket-addr\"\n");
        assert!(Config::load(Some(bad.clone())).is_err());
        std::fs::remove_file(&bad).ok();
        let typo = temp_toml("typo", "listne = \"0.0.0.0:9000\"\n");
        assert!(
            Config::load(Some(typo.clone()))
                .unwrap_err()
                .to_string()
                .contains("unknown config key"),
        );
        std::fs::remove_file(&typo).ok();
    }
}
