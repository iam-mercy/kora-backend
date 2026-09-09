//! Runtime configuration, loaded from the environment.
//!
//! Mirrors `docs/environment-variables.md` for the Phase 1 subset, plus the
//! four vars that doc does not cover but the service needs — `JWT_SECRET`,
//! `TOTP_ENCRYPTION_KEY`, `BIND_ADDR`, `SESSION_TOKEN_TTL_SECS`. Each of
//! those is flagged in `ASSUMPTIONS.md` (#1, #3, #4, #11) as a gap versus
//! the authoritative env-var doc.
//!
//! Deliberately NOT loaded here (deferred per the Phase 1 brief):
//! `SECRET_PROVIDER`, `AWS_SECRETS_JSON`, `LEADERBOARD_DECAY_LAMBDA`,
//! `WEBHOOK_LOG_MAX_ENTRIES`, `REDIS_URL`.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;

/// Crate version, from `Cargo.toml` via Cargo. Used in `/health` / build-info.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git commit hash, baked by `build.rs`. `"unknown"` when git was
/// unavailable at build time.
pub const GIT_SHA: &str = env!("GIT_SHA");

/// The placeholder `JWT_SECRET` shipped in `.env.example`. Running with this
/// value outside local development is a security hole — see
/// [`Config::example_secrets_in_use`].
pub const EXAMPLE_JWT_SECRET: &str = "dev-only-insecure-change-me";

/// The placeholder `TOTP_ENCRYPTION_KEY` from `.env.example`, decoded to its
/// 32 raw bytes (base64 `MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=`).
pub const EXAMPLE_TOTP_ENCRYPTION_KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

/// Fully validated service configuration.
#[derive(Clone)]
pub struct Config {
    /// `DATABASE_URL` — PostgreSQL connection string. Required.
    pub database_url: String,
    /// `DB_POOL_MIN` — min connections kept in the pool. Default `1`.
    pub db_pool_min: u32,
    /// `DB_POOL_MAX` — max connections the pool will open. Default `10`.
    pub db_pool_max: u32,
    /// `DB_POOL_ACQUIRE_TIMEOUT_SECS` — wait for a connection. Default `30`.
    pub db_pool_acquire_timeout: Duration,
    /// `POOL_STATS_ENABLED` — expose pool utilisation on `/health`. Default off.
    pub pool_stats_enabled: bool,

    /// `BIND_ADDR` — socket to listen on. Default `0.0.0.0:8080`.
    /// (Not in `environment-variables.md` — see ASSUMPTIONS.md #4.)
    pub bind_addr: SocketAddr,

    /// `JWT_SECRET` — HS256 key for verifying incoming bearer tokens and
    /// signing `/2fa/login` session tokens.
    /// (Not in `environment-variables.md` — see ASSUMPTIONS.md #1.)
    pub jwt_secret: String,

    /// `TOTP_ENCRYPTION_KEY` — 32 raw bytes (decoded from base64) used as the
    /// AES-256-GCM key that encrypts TOTP secrets at rest.
    /// (Not in `environment-variables.md` — see ASSUMPTIONS.md #3.)
    pub totp_encryption_key: [u8; 32],

    /// `SESSION_TOKEN_TTL_SECS` — lifetime of a minted `/2fa/login` session
    /// token. Default `900` (15 minutes).
    /// (Not in `environment-variables.md` — see ASSUMPTIONS.md #11.)
    pub session_token_ttl: Duration,
}

/// Everything that can go wrong while reading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is not set")]
    Missing(&'static str),
    #[error("environment variable {var} is invalid: {source}")]
    Invalid {
        var: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes, got {0}")]
    KeyLength(usize),
}

impl Config {
    /// Read and validate every configuration value from the process
    /// environment. Returns the first error encountered.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = require("DATABASE_URL")?;

        let db_pool_min = parse_or("DB_POOL_MIN", 1)?;
        let db_pool_max = parse_or("DB_POOL_MAX", 10)?;
        let db_pool_acquire_timeout =
            Duration::from_secs(parse_or("DB_POOL_ACQUIRE_TIMEOUT_SECS", 30)?);
        let pool_stats_enabled = parse_bool_or("POOL_STATS_ENABLED", false)?;

        let bind_addr = parse_or::<SocketAddr>("BIND_ADDR", default_bind_addr())?;

        let jwt_secret = require("JWT_SECRET")?;
        if jwt_secret.trim().is_empty() {
            return Err(ConfigError::Missing("JWT_SECRET"));
        }

        let totp_encryption_key = load_totp_key()?;

        let session_token_ttl = Duration::from_secs(parse_or("SESSION_TOKEN_TTL_SECS", 900)?);

        let config = Self {
            database_url,
            db_pool_min,
            db_pool_max,
            db_pool_acquire_timeout,
            pool_stats_enabled,
            bind_addr,
            jwt_secret,
            totp_encryption_key,
            session_token_ttl,
        };

        for var in config.example_secrets_in_use() {
            tracing::warn!(
                env_var = var,
                "SECURITY: {var} is set to the .env.example placeholder value — \
                 generate a real secret before deploying; this build must not \
                 run outside local development with this value"
            );
        }

        Ok(config)
    }

    /// `tracing` filter directive: `RUST_LOG` if set, else a sensible default.
    pub fn log_filter() -> String {
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info,kora_2fa=info".to_owned())
    }

    /// Names of the secret env vars still set to their `.env.example`
    /// placeholder value. Empty for a correctly provisioned deployment.
    /// [`Config::from_env`] calls this at boot and warns loudly for each hit
    /// so a real deployment cannot silently ship the example secrets.
    pub fn example_secrets_in_use(&self) -> Vec<&'static str> {
        let mut flagged = Vec::new();
        if self.jwt_secret == EXAMPLE_JWT_SECRET {
            flagged.push("JWT_SECRET");
        }
        if self.totp_encryption_key == EXAMPLE_TOTP_ENCRYPTION_KEY {
            flagged.push("TOTP_ENCRYPTION_KEY");
        }
        flagged
    }
}

/// Redacts the two secret fields; every other field is printed so operators
/// can confirm what was loaded.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &redact_url(&self.database_url))
            .field("db_pool_min", &self.db_pool_min)
            .field("db_pool_max", &self.db_pool_max)
            .field("db_pool_acquire_timeout", &self.db_pool_acquire_timeout)
            .field("pool_stats_enabled", &self.pool_stats_enabled)
            .field("bind_addr", &self.bind_addr)
            .field(
                "jwt_secret",
                &format_args!("<redacted {} chars>", self.jwt_secret.len()),
            )
            .field(
                "totp_encryption_key",
                &format_args!("<redacted {} bytes>", self.totp_encryption_key.len()),
            )
            .field("session_token_ttl", &self.session_token_ttl)
            .finish()
    }
}

/// Strips any `user:password@` component from a connection string for logging.
fn redact_url(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end + 3 => {
            format!("{}://***@{}", &url[..scheme_end], &url[at + 1..])
        }
        _ => url.to_owned(),
    }
}

fn default_bind_addr() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

fn require(var: &'static str) -> Result<String, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(var)),
    }
}

fn parse_or<T>(var: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match std::env::var(var) {
        Err(_) => Ok(default),
        Ok(v) if v.is_empty() => Ok(default),
        Ok(v) => v.parse().map_err(|source| ConfigError::Invalid {
            var,
            source: Box::new(source),
        }),
    }
}

fn parse_bool_or(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    match std::env::var(var) {
        Err(_) => Ok(default),
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "" => Ok(default),
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid {
                var,
                source: format!("expected a boolean, got {other:?}").into(),
            }),
        },
    }
}

fn load_totp_key() -> Result<[u8; 32], ConfigError> {
    let raw = require("TOTP_ENCRYPTION_KEY")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw.trim()))
        .map_err(|source| ConfigError::Invalid {
            var: "TOTP_ENCRYPTION_KEY",
            source: Box::new(source),
        })?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::KeyLength(decoded.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Config` with real, non-placeholder secrets.
    fn sample_config() -> Config {
        Config {
            database_url: "postgresql://u:p@localhost/db".to_owned(),
            db_pool_min: 1,
            db_pool_max: 10,
            db_pool_acquire_timeout: Duration::from_secs(30),
            pool_stats_enabled: false,
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            jwt_secret: "a-real-provisioned-secret".to_owned(),
            totp_encryption_key: [1u8; 32],
            session_token_ttl: Duration::from_secs(900),
        }
    }

    #[test]
    fn real_secrets_are_not_flagged() {
        assert!(sample_config().example_secrets_in_use().is_empty());
    }

    #[test]
    fn placeholder_jwt_secret_is_flagged() {
        let mut config = sample_config();
        config.jwt_secret = EXAMPLE_JWT_SECRET.to_owned();
        assert_eq!(config.example_secrets_in_use(), vec!["JWT_SECRET"]);
    }

    #[test]
    fn placeholder_totp_key_is_flagged() {
        let mut config = sample_config();
        config.totp_encryption_key = EXAMPLE_TOTP_ENCRYPTION_KEY;
        assert_eq!(config.example_secrets_in_use(), vec!["TOTP_ENCRYPTION_KEY"]);
    }

    #[test]
    fn both_placeholders_are_flagged_together() {
        let mut config = sample_config();
        config.jwt_secret = EXAMPLE_JWT_SECRET.to_owned();
        config.totp_encryption_key = EXAMPLE_TOTP_ENCRYPTION_KEY;
        assert_eq!(
            config.example_secrets_in_use(),
            vec!["JWT_SECRET", "TOTP_ENCRYPTION_KEY"]
        );
    }

    /// The decoded `EXAMPLE_TOTP_ENCRYPTION_KEY` constant must stay in lock
    /// step with the base64 literal in `.env.example` — otherwise the guard
    /// silently stops matching a deployment that copied that file verbatim.
    #[test]
    fn example_totp_key_matches_the_env_example_literal() {
        const ENV_EXAMPLE_B64: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(ENV_EXAMPLE_B64)
            .expect("literal is valid base64");
        assert_eq!(decoded.as_slice(), EXAMPLE_TOTP_ENCRYPTION_KEY);
    }
}
