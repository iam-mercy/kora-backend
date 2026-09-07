//! Kora App Backend 2FA service — Phase 1.
//!
//! Implements the 2FA/auth endpoints from `docs/openapi.yaml`:
//! `/2fa/enable`, `/2fa/disable`, `/2fa/verify`, `/2fa/login`, `/2fa/recover`,
//! `/2fa/recovery-log`, `/2fa/audit-log/{user_id}`, and `/health`.

mod config;
mod error;

use config::Config;

fn main() -> anyhow::Result<()> {
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

    // HTTP server + routes land in the following commits.
    Ok(())
}
