//! Database access: the connection pool and the row/DTO types.

pub mod models;

use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::Config;

/// Embedded migrations from the workspace-root `migrations/` directory.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Boot-time connect-retry budget. Even with a compose healthcheck, the
/// service can still win the race to start before Postgres is accepting
/// connections in orchestrated environments; [`connect_with_retry`] retries
/// instead of exiting on the first refusal.
pub const CONNECT_MAX_ATTEMPTS: u32 = 5;

/// Delay before the second connect attempt; each further retry doubles it
/// (1s, 2s, 4s, 8s across the default five attempts).
pub const CONNECT_BASE_BACKOFF: Duration = Duration::from_secs(1);

/// Exponential backoff before retry `attempt` (1-based): `base * 2^(attempt-1)`,
/// with the exponent clamped so misuse cannot overflow.
pub fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    base * 2u32.pow(attempt.saturating_sub(1).min(16))
}

/// Build the Postgres pool from configuration. Does not run migrations.
pub async fn connect(config: &Config) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .min_connections(config.db_pool_min)
        .max_connections(config.db_pool_max)
        .acquire_timeout(config.db_pool_acquire_timeout)
        .connect(&config.database_url)
        .await
}

/// Apply any pending migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

/// Pool utilisation snapshot, surfaced on `/health` when `POOL_STATS_ENABLED`.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PoolStats {
    pub size: u32,
    pub idle: usize,
}

impl PoolStats {
    pub fn capture(pool: &PgPool) -> Self {
        Self {
            size: pool.size(),
            idle: pool.num_idle(),
        }
    }
}

/// How long an account stays locked after 5 consecutive failed attempts
/// (`docs/openapi.yaml`: "locked for 15 minutes").
pub const LOCKOUT_DURATION: Duration = Duration::from_secs(15 * 60);

/// Consecutive failures that trip the lockout (`docs/openapi.yaml`: "After 5
/// consecutive failures"). The compare against this bound happens inside the
/// same `UPDATE` that increments `failed_attempts`, so parallel failed
/// attempts cannot slip past it.
pub const MAX_FAILED_ATTEMPTS: i32 = 5;
