//! Kora App Backend 2FA service — Phase 1.
//!
//! Implements the 2FA/auth endpoints from `docs/openapi.yaml`:
//! `/2fa/enable`, `/2fa/disable`, `/2fa/verify`, `/2fa/login`, `/2fa/recover`,
//! `/2fa/recovery-log`, `/2fa/audit-log/{user_id}`, and `/health`.

mod config;
mod crypto;
mod db;
mod error;
mod jwt;
mod middleware;
mod routes;
mod totp;

use config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(Config::log_filter())
        .init();

    let config = Config::from_env()?;
    tracing::info!(
        version = config::VERSION,
        git_sha = config::GIT_SHA,
        ?config,
        "configuration loaded"
    );

    let bind_addr = config.bind_addr;
    let pool = db::connect(&config).await?;
    db::run_migrations(&pool).await?;
    tracing::info!("migrations applied");

    let app = routes::router(routes::AppState::new(config, pool));

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "kora-2fa listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Resolves on SIGINT or SIGTERM so in-flight requests can drain.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
