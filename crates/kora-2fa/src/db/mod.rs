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

/// Like [`connect`], but retry up to `max_attempts` times with exponential
/// backoff ([`backoff_delay`]) before surfacing the last error. Every failed
/// attempt is logged; the caller decides what a final failure means.
pub async fn connect_with_backoff(
    config: &Config,
    max_attempts: u32,
    base_backoff: Duration,
) -> Result<PgPool, sqlx::Error> {
    let max_attempts = max_attempts.max(1);
    for attempt in 1..=max_attempts {
        match connect(config).await {
            Ok(pool) => {
                if attempt > 1 {
                    tracing::info!(attempt, "database connection established after retry");
                }
                return Ok(pool);
            }
            Err(err) if attempt == max_attempts => {
                tracing::error!(
                    attempt,
                    max_attempts,
                    error = %err,
                    "database unreachable after the final attempt; giving up"
                );
                return Err(err);
            }
            Err(err) => {
                let retry_in = backoff_delay(base_backoff, attempt);
                tracing::warn!(
                    attempt,
                    max_attempts,
                    ?retry_in,
                    error = %err,
                    "database connect failed; retrying"
                );
                tokio::time::sleep(retry_in).await;
            }
        }
    }
    unreachable!("the loop returns on the final attempt")
}

/// [`connect_with_backoff`] with the default boot budget
/// ([`CONNECT_MAX_ATTEMPTS`] / [`CONNECT_BASE_BACKOFF`]). This is what the
/// binary calls at startup so a not-yet-ready Postgres delays the boot
/// instead of killing it.
pub async fn connect_with_retry(config: &Config) -> Result<PgPool, sqlx::Error> {
    connect_with_backoff(config, CONNECT_MAX_ATTEMPTS, CONNECT_BASE_BACKOFF).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_doubles_each_attempt() {
        let base = Duration::from_secs(1);
        assert_eq!(backoff_delay(base, 1), Duration::from_secs(1));
        assert_eq!(backoff_delay(base, 2), Duration::from_secs(2));
        assert_eq!(backoff_delay(base, 3), Duration::from_secs(4));
        assert_eq!(backoff_delay(base, 4), Duration::from_secs(8));
    }

    #[test]
    fn backoff_delay_treats_attempt_zero_as_the_base() {
        assert_eq!(
            backoff_delay(Duration::from_millis(50), 0),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn default_boot_budget_is_five_attempts_from_one_second() {
        assert_eq!(CONNECT_MAX_ATTEMPTS, 5);
        assert_eq!(CONNECT_BASE_BACKOFF, Duration::from_secs(1));
    }

    /// Points at a port nothing listens on, with a short acquire timeout so
    /// each attempt fails fast.
    fn unreachable_db_config() -> Config {
        Config {
            database_url: "postgresql://x:x@127.0.0.1:1/none".to_owned(),
            db_pool_min: 0,
            db_pool_max: 1,
            db_pool_acquire_timeout: Duration::from_millis(50),
            pool_stats_enabled: false,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            jwt_secret: "unused".to_owned(),
            totp_encryption_key: [0u8; 32],
            session_token_ttl: Duration::from_secs(900),
        }
    }

    #[tokio::test]
    async fn connect_with_backoff_gives_up_after_the_attempt_budget() {
        let started = std::time::Instant::now();
        let result =
            connect_with_backoff(&unreachable_db_config(), 3, Duration::from_millis(20)).await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "an unreachable DB must not succeed");
        // Three attempts means two backoffs (20ms + 40ms), so the call
        // cannot have bailed after a single try.
        assert!(
            elapsed >= Duration::from_millis(60),
            "expected the loop to sleep between retries, took {elapsed:?}"
        );
    }
}
