//! `greendot-cli` — the command-line counterpart to the web service. It shares
//! greendot-web's modules and talks to the same root helper. The web UI runs
//! these subcommands as recorded tasks.
//!
//! Usage: `greendot-cli reconcile [config.toml]`

use anyhow::Result;
use greendot_web::{config, reconcile};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().init();
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("reconcile") => match run_reconcile(args.next()).await {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("reconcile: {e:#}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("usage: greendot-cli reconcile [config.toml]");
            if let Some(cmd) = other {
                eprintln!("unknown command: {cmd}");
            }
            ExitCode::from(2)
        }
    }
}

async fn run_reconcile(config_path: Option<String>) -> Result<bool> {
    let config = config::Config::load(config_path)?;
    reconcile::cli_run(&config).await
}
