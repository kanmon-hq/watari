#![forbid(unsafe_code)]

use anyhow::Context;
use std::net::SocketAddr;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use watari::app::{create_router, init_app_state};
use watari::config::{Config, LogFormat};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load configuration
    let config = Config::from_env().context("Failed to load configuration from environment")?;

    // 2. Setup structured logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    match config.log_format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    }

    tracing::info!(
        listen_addr = %config.listen_addr,
        storage_backend = ?config.storage_backend,
        secret_backend = ?config.secret_backend,
        "Starting Watari Egress Proxy"
    );

    // 3. Initialize application state
    let listen_addr = config.listen_addr;
    let state = init_app_state(config)
        .await
        .context("Failed to initialize application state")?;

    let app = create_router(state);

    // 4. Bind listener and run with graceful shutdown
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind listener on {listen_addr}"))?;

    tracing::info!("Watari listening on http://{listen_addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("Server error during execution")?;

    tracing::info!("Watari shutdown gracefully");
    Ok(())
}

/// Graceful shutdown handler listening for SIGINT / SIGTERM / Ctrl+C.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C / SIGINT signal, initiating shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal, initiating shutdown...");
        },
    }
}
