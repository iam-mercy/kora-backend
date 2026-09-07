//! HTTP routing and shared handler state.
//!
//! Only the Phase 1 endpoints are mounted here. The `/admin/*`,
//! `/tenant/provision`, and `/ws/leaderboard` paths in `docs/openapi.yaml`
//! are deliberately absent — not stubbed (ASSUMPTIONS.md #14).

use std::sync::Arc;

use sqlx::PgPool;

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
