mod config;
mod routes;

use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let config = config::Config::load(std::env::args().nth(1))?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, "serving");
    axum::serve(listener, routes::app()).await?;
    Ok(())
}
