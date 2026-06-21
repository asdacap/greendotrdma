mod actual;
mod auth;
mod config;
mod dot;
mod fmt;
mod helper_client;
mod metrics;
mod reconcile;
mod routes;
mod snapshots;
mod state;
mod task_runner;

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let config = config::Config::load(std::env::args().nth(1))?;

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
        reconcile_lock: tokio::sync::Mutex::new(()),
        tasks: task_runner::TaskHub::default(),
    });
    let app = routes::app(Arc::clone(&state));

    // Startup reconcile restores configfs after a reboot; the periodic pass
    // self-heals drift and keeps dot reasons fresh.
    let reconcile_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = routes::exports::reconcile_state(&reconcile_state).await {
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
