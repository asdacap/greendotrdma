use anyhow::{Context, Result};
use greendot_web::{auth, config, helper_client, metrics, routes, snapshots, state, task_runner};
use std::sync::Arc;
use std::time::Duration;

/// The argv the web service runs to reconcile: the sibling `greendot-cli`
/// (installed next to this binary) with the same config file, so it reads the
/// same desired state and helper socket.
fn reconcile_cmd(config_arg: Option<String>) -> Vec<String> {
    let cli = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("greendot-cli")))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "greendot-cli".into());
    let mut cmd = vec![cli, "reconcile".into()];
    cmd.extend(config_arg);
    cmd
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let config_arg = std::env::args().nth(1);
    let config = config::Config::load(config_arg.clone())?;

    let tls = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| {
                    format!(
                        "loading TLS cert {} / key {}",
                        cert.display(),
                        key.display()
                    )
                })?,
        ),
        (None, None) => None,
        _ => anyhow::bail!("tls_cert and tls_key must be set together"),
    };

    let state = Arc::new(routes::AppState {
        helper: helper_client::HelperClient::new(config.helper_socket.clone()),
        sessions: auth::Sessions::new(Duration::from_secs(24 * 3600)),
        secure_cookies: tls.is_some(),
        db: state::Db::open(&config.db_path, &config.state_path)?,
        metrics: metrics::Metrics::open(&config.metrics_db_path)?,
        nvmet_root: config.nvmet_root.clone(),
        lio_root: config.lio_root.clone(),
        reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
        tasks: task_runner::TaskHub::default(),
        reconcile_cmd: reconcile_cmd(config_arg),
    });
    let app = routes::app(Arc::clone(&state));

    // Startup reconcile restores configfs after a reboot; the periodic pass
    // self-heals drift and keeps dot reasons fresh.
    let reconcile_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = routes::block_export::reconcile_state(&reconcile_state).await {
                tracing::error!(error = %e, "periodic reconcile failed");
            }
        }
    });
    tokio::spawn(snapshots::scheduler(Arc::clone(&state)));
    tokio::spawn(metrics::collect::collector(state));

    match tls {
        Some(tls) => {
            tracing::info!(listen = %config.listen, "serving HTTPS");
            axum_server::bind_rustls(config.listen, tls)
                .serve(app.into_make_service())
                .await?;
        }
        None => {
            tracing::warn!(listen = %config.listen, "serving plain HTTP — passwords cross the wire unencrypted");
            let listener = tokio::net::TcpListener::bind(config.listen)
                .await
                .with_context(|| format!("binding {}", config.listen))?;
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
