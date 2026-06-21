use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub helper_socket: PathBuf,
    /// Task run-history (SQLite). The desired-state config lives in `state_path`.
    pub db_path: PathBuf,
    /// Desired-state config (exports, settings, snapshot policies) as TOML.
    pub state_path: PathBuf,
    pub metrics_db_path: PathBuf,
    pub nvmet_root: PathBuf,
    pub lio_root: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:8080".parse().unwrap(),
            helper_socket: "/run/greendotrdma/helper.sock".into(),
            db_path: "/var/lib/greendotrdma/state.db".into(),
            state_path: "/var/lib/greendotrdma/state.toml".into(),
            metrics_db_path: "/var/lib/greendotrdma/metrics.db".into(),
            nvmet_root: "/sys/kernel/config/nvmet".into(),
            lio_root: "/sys/kernel/config/target".into(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl Config {
    /// Loads from the given TOML file; missing argument means defaults.
    pub fn load(path: Option<String>) -> Result<Self> {
        match path {
            None => Ok(Config::default()),
            Some(path) => {
                let text =
                    std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
                toml::from_str(&text).with_context(|| format!("parsing {path}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_toml(body: &str) -> String {
        let path = std::env::temp_dir().join(format!("gd-cfg{}.toml", rand::random::<u32>()));
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn defaults_partial_override_and_errors() {
        // No path → built-in defaults.
        let d = Config::load(None).unwrap();
        assert_eq!(d.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(d.tls_cert, None);

        // A partial file overrides only its keys; the rest keep their defaults.
        let path = temp_toml("listen = \"0.0.0.0:9000\"\ndb_path = \"/tmp/state.db\"\n");
        let c = Config::load(Some(path.clone())).unwrap();
        assert_eq!(c.listen, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(c.db_path, PathBuf::from("/tmp/state.db"));
        assert_eq!(c.helper_socket, Config::default().helper_socket);
        std::fs::remove_file(&path).ok();

        // A missing file and a value that fails to deserialize both error.
        assert!(Config::load(Some("/nonexistent/gd.toml".into())).is_err());
        let bad = temp_toml("listen = \"not-a-socket-addr\"\n");
        assert!(Config::load(Some(bad.clone())).is_err());
        std::fs::remove_file(&bad).ok();
    }
}
