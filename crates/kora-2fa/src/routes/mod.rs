//! HTTP routing and shared handler state.
//!
//! Only the Phase 1 endpoints are mounted here. The `/admin/*`,
//! `/tenant/provision`, and `/ws/leaderboard` paths in `docs/openapi.yaml`
//! are deliberately absent — not stubbed (ASSUMPTIONS.md #14).

pub mod health;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use sqlx::PgPool;
use tower_http::trace::TraceLayer;

use crate::config::Config;

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

/// Build the Phase 1 router. Endpoint groups are added by the following
/// commits; for now only `/health` is mounted.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
