use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub helper_socket: PathBuf,
    pub db_path: PathBuf,
    pub nvmet_root: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:8080".parse().unwrap(),
            helper_socket: "/run/greendotrdma/helper.sock".into(),
            db_path: "/var/lib/greendotrdma/state.db".into(),
            nvmet_root: "/sys/kernel/config/nvmet".into(),
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
