//! Database access: the connection pool and the row/DTO types.

pub mod models;

use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::Config;

/// Embedded migrations from the workspace-root `migrations/` directory.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

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
