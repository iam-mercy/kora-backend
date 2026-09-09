//! Tests for the cross-cutting hardening stack in `routes::hardening_layers`
//! (`routes::router`): panic-catching, request-body cap, and request timeout.
//!
//! None of these touch Postgres — the router is built over a lazy pool that
//! is never queried — so they run without a database, unlike the
//! `#[sqlx::test]` suite in `integration.rs`.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use tower_http::timeout::TimeoutLayer;

use kora_2fa::config::Config;
use kora_2fa::routes::{self, AppState, REQUEST_BODY_LIMIT_BYTES, REQUEST_TIMEOUT};

/// A pool that parses its URL but never connects — enough to build the real
/// `AppState`/`router` for tests that never reach a handler that queries.
fn lazy_pool() -> PgPool {
    PgPool::connect_lazy("postgresql://kora:kora@127.0.0.1:5432/unused").unwrap()
}

fn test_config() -> Config {
    Config {
        database_url: "unused-in-tests".to_owned(),
        db_pool_min: 1,
        db_pool_max: 1,
        db_pool_acquire_timeout: Duration::from_secs(1),
        pool_stats_enabled: false,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        jwt_secret: "hardening-tests-secret".to_owned(),
        totp_encryption_key: [7u8; 32],
        session_token_ttl: Duration::from_secs(900),
    }
}

/// The production router, over a never-queried pool.
fn production_router() -> Router {
    routes::router(AppState::new(test_config(), lazy_pool()))
}

async fn send(app: Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// The body cap is wired into the real `router()`: an oversized POST to a
/// genuine endpoint is refused before auth or the handler runs.
#[tokio::test]
async fn production_router_rejects_oversized_body() {
    let oversized = "x".repeat(REQUEST_BODY_LIMIT_BYTES + 1);
    let req = Request::builder()
        .method("POST")
        .uri("/2fa/verify")
        .header("content-type", "application/json")
        .header("content-length", oversized.len())
        .body(Body::from(oversized))
        .unwrap();

    let (status, _) = send(production_router(), req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Wrap a bare router in the exact hardening stack `router()` uses.
fn hardened(router: Router) -> Router {
    routes::hardening_layers(router)
}

async fn boom() -> &'static str {
    panic!("handler blew up")
}

/// A panic inside a handler is caught and rendered as the same
/// `{error, message}` 500 envelope `AppError::internal` produces — the
/// connection is not dropped.
#[tokio::test]
async fn handler_panic_becomes_the_error_envelope() {
    let app = hardened(Router::new().route("/boom", get(boom)));
    let req = Request::builder().uri("/boom").body(Body::empty()).unwrap();

    let (status, body) = send(app, req).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], "INTERNAL");
    assert_eq!(body["message"], "An internal error occurred");
}

async fn echo(body: String) -> String {
    body
}

/// With no `content-length` to pre-check, the cap still trips while the body
/// is being read: the handler never sees more than the limit.
#[tokio::test]
async fn oversized_streamed_body_trips_the_limit_mid_read() {
    let app = hardened(Router::new().route("/echo", post(echo)));
    let oversized = "x".repeat(REQUEST_BODY_LIMIT_BYTES + 1);
    let req = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::from(oversized))
        .unwrap();

    let (status, _) = send(app, req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// A body at exactly the cap is accepted.
#[tokio::test]
async fn body_at_the_cap_is_accepted() {
    let app = hardened(Router::new().route("/echo", post(echo)));
    let at_cap = "x".repeat(REQUEST_BODY_LIMIT_BYTES);
    let req = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::from(at_cap))
        .unwrap();

    let (status, _) = send(app, req).await;
    assert_eq!(status, StatusCode::OK);
}

/// A quick request passes through the full hardening stack untouched.
#[tokio::test]
async fn fast_request_passes_through_the_stack() {
    let app = hardened(Router::new().route("/ping", get(|| async { "pong" })));
    let req = Request::builder().uri("/ping").body(Body::empty()).unwrap();

    let (status, _) = send(app, req).await;
    assert_eq!(status, StatusCode::OK);
}

/// The `TimeoutLayer` the stack uses replaces an over-budget response with a
/// `408`. Exercised here with a short budget so the test stays fast; the
/// production budget is asserted separately below.
#[tokio::test]
async fn timeout_layer_replaces_a_slow_response_with_408() {
    let slow = get(|| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        "too late"
    });
    let app = Router::new()
        .route("/slow", slow)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_millis(50),
        ));
    let req = Request::builder().uri("/slow").body(Body::empty()).unwrap();

    let (status, _) = send(app, req).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
}

/// Pin the production request budget so it cannot be shortened by accident.
#[test]
fn production_request_timeout_is_10s() {
    assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(10));
}
