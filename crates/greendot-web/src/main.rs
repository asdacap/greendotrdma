mod auth;
mod config;
mod helper_client;
mod routes;

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
    });
    let app = routes::app(state);

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
