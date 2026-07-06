use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

/// The reconcile-relevant subset of `/etc/greendotrdma/config.toml` — the keys
/// both greendotctl and greendot-web read. The web server's own keys (listen
/// address, TLS, database paths) live in greendot-web's `Config`, which
/// flattens this struct; unknown keys are ignored here so both binaries parse
/// the same file.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub helper_socket: PathBuf,
    /// Desired-state config (exports, settings, snapshot policies) as TOML.
    pub state_path: PathBuf,
    pub nvmet_root: PathBuf,
    pub lio_root: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            helper_socket: "/run/greendotrdma/helper.sock".into(),
            state_path: "/var/lib/greendotrdma/state.toml".into(),
            nvmet_root: "/sys/kernel/config/nvmet".into(),
            lio_root: "/sys/kernel/config/target".into(),
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

    fn temp_toml(tag: &str, body: &str) -> String {
        let path = std::env::temp_dir().join(format!("gd-cfg-{}-{tag}.toml", std::process::id()));
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn defaults_partial_override_and_errors() {
        // No path → built-in defaults.
        let d = Config::load(None).unwrap();
        assert_eq!(
            d.helper_socket,
            PathBuf::from("/run/greendotrdma/helper.sock")
        );

        // A partial file overrides only its keys; the rest keep their defaults,
        // and web-only keys (`listen`, TLS, …) are ignored, not rejected.
        let path = temp_toml(
            "ok",
            "listen = \"0.0.0.0:9000\"\nstate_path = \"/tmp/state.toml\"\n",
        );
        let c = Config::load(Some(path.clone())).unwrap();
        assert_eq!(c.state_path, PathBuf::from("/tmp/state.toml"));
        assert_eq!(c.helper_socket, Config::default().helper_socket);
        std::fs::remove_file(&path).ok();

        // A missing file and a value of the wrong type both error.
        assert!(Config::load(Some("/nonexistent/gd.toml".into())).is_err());
        let bad = temp_toml("bad", "state_path = 12\n");
        assert!(Config::load(Some(bad.clone())).is_err());
        std::fs::remove_file(&bad).ok();
    }
}
