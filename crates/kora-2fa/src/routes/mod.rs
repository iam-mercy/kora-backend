//! HTTP routing, shared handler state, and cross-handler helpers.
//!
//! Only the Phase 1 endpoints are mounted here. The `/admin/*`,
//! `/tenant/provision`, and `/ws/leaderboard` paths in `docs/openapi.yaml`
//! are deliberately absent — not stubbed (ASSUMPTIONS.md #14).

pub mod health;
pub mod recovery;
pub mod twofa;

use std::sync::Arc;

use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::Router;
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::db::models::{AuditEvent, TwoFactorRow};

/// State shared by every handler: configuration + the DB pool.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
}

impl AppState {
    pub fn new(config: Config, pool: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            pool,
        }
    }
}

/// Build the Phase 1 router: the eight in-scope endpoints from
/// `docs/openapi.yaml`, behind the shared hardening stack. Everything is
/// self-only bearer-authenticated except `/2fa/login` and `/health`.
pub fn router(state: AppState) -> Router {
    let endpoints = Router::new()
        .route("/health", get(health::health))
        .route("/2fa/enable", post(twofa::enable))
        .route("/2fa/disable", post(twofa::disable))
        .route("/2fa/verify", post(twofa::verify))
        .route("/2fa/login", post(twofa::login))
        .route("/2fa/recover", post(recovery::recover))
        .route("/2fa/recovery-log", get(recovery::recovery_log))
        .route("/2fa/audit-log/{user_id}", get(recovery::audit_log));

    hardening_layers(endpoints).with_state(state)
}

/// The cross-cutting hardening stack applied to every route.
///
/// `.layer()` applies bottom-to-top, so the calls read inner-to-outer: the
/// last one added is the outermost wrapper and sees the request first / the
/// response last.
///
/// Generic over the router's state type so tests can drive the exact stack
/// against a throwaway stateless router.
pub fn hardening_layers<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(TraceLayer::new_for_http())
}

// ─── Cross-handler helpers ─────────────────────────────────────────────────

/// Best-effort client IP + user agent for audit rows (ASSUMPTIONS.md #13):
/// first hop of `X-Forwarded-For`, else `X-Real-IP`; `User-Agent` verbatim.
pub fn client_meta(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        });

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .filter(|s| !s.is_empty());

    (ip, user_agent)
}

/// Load a user's 2FA record, if any.
pub async fn load_record(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<TwoFactorRow>, sqlx::Error> {
    sqlx::query_as!(
        TwoFactorRow,
        r#"
        SELECT user_id, email, issuer,
               secret_ciphertext, secret_nonce,
               enabled, pending, failed_attempts, locked_until
        FROM two_factor_records
        WHERE user_id = $1
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await
}

/// Append one audit row.
pub async fn insert_audit(
    exec: impl sqlx::PgExecutor<'_>,
    user_id: &str,
    event: AuditEvent,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO audit_log (user_id, event, ip_address, user_agent)
        VALUES ($1, $2, $3, $4)
        "#,
        user_id,
        event.as_str(),
        ip,
        user_agent
    )
    .execute(exec)
    .await
    .map(|_| ())
}
