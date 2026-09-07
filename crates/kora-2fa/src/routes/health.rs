//! `GET /health` — liveness probe, no authentication (`docs/openapi.yaml`).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::db::PoolStats;
use crate::routes::AppState;

#[derive(Serialize)]
struct HealthBody {
    /// `"ok"` when healthy. The spec only documents the 200 case.
    status: &'static str,
    /// Present only when `POOL_STATS_ENABLED` is set
    /// (`docs/environment-variables.md`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pool: Option<PoolStats>,
}

/// Returns `200 {"status":"ok"}` when the DB is reachable, `503
/// {"status":"degraded"}` otherwise.
pub async fn health(State(state): State<AppState>) -> Response {
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();

    let pool = state
        .config
        .pool_stats_enabled
        .then(|| PoolStats::capture(&state.pool));

    if db_ok {
        (StatusCode::OK, Json(HealthBody { status: "ok", pool })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthBody {
                status: "degraded",
                pool,
            }),
        )
            .into_response()
    }
}
