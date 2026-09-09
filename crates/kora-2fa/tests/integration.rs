//! End-to-end tests against a real Postgres.
//!
//! Each test gets its own migrated database from `#[sqlx::test]` and drives
//! the exact `routes::router` the binary serves, via `tower`'s `oneshot`.
//! Covers: enable -> verify activates -> login (valid / invalid / expired)
//! -> lockout after 5 failures -> recovery with a backup code disables 2FA
//! -> the audit log records each event.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use kora_2fa::config::Config;
use kora_2fa::jwt;
use kora_2fa::routes::{router, AppState};

const JWT_SECRET: &str = "integration-secret";
const ENC_KEY: [u8; 32] = [42u8; 32];

fn test_config() -> Config {
    Config {
        database_url: "unused-in-tests".to_owned(),
        db_pool_min: 1,
        db_pool_max: 5,
        db_pool_acquire_timeout: Duration::from_secs(5),
        pool_stats_enabled: false,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        jwt_secret: JWT_SECRET.to_owned(),
        totp_encryption_key: ENC_KEY,
        session_token_ttl: Duration::from_secs(900),
    }
}

fn app(pool: PgPool) -> Router {
    router(AppState::new(test_config(), pool))
}

fn bearer(sub: &str) -> String {
    let token = jwt::mint_session_token(sub, JWT_SECRET, Duration::from_secs(300)).unwrap();
    format!("Bearer {token}")
}

fn post(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", t);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(t) = token {
        b = b.header("authorization", t);
    }
    b.body(Body::empty()).unwrap()
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build a live TOTP from a base32 secret and produce a code for `offset`
/// 30-second steps away from now (0 = current).
fn totp_code(secret: &str, offset: i64) -> String {
    let totp = kora_2fa::totp::build(secret, "Kora App", "alice@kora.app").unwrap();
    let t = (now_secs() as i64 + offset * 30) as u64;
    totp.generate(t)
}

/// Read the raw lockout counter for a user straight off the row.
async fn failed_attempts(pool: &PgPool, user_id: &str) -> i32 {
    sqlx::query_scalar!(
        "SELECT failed_attempts FROM two_factor_records WHERE user_id = $1",
        user_id,
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Enable + activate 2FA for `user`, returning the base32 secret. Leaves the
/// account enabled with `failed_attempts = 0`.
async fn activate(app: &Router, user: &str) -> String {
    let auth = bearer(user);
    let (status, body) = call(
        app,
        post(
            "/2fa/enable",
            Some(&auth),
            json!({ "user_id": user, "email": "alice@kora.app" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enable: {body}");
    let secret = body["secret"].as_str().unwrap().to_owned();
    let (status, body) = call(
        app,
        post(
            "/2fa/verify",
            Some(&auth),
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate: {body}");
    secret
}

/// Fire `n` wrong-TOTP `/2fa/verify` calls at `user` concurrently and return
/// their status codes once every one has completed.
async fn race_wrong_totp(app: &Router, user: &str, n: usize) -> Vec<StatusCode> {
    let auth = bearer(user);
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..n {
        let (app, auth, user) = (app.clone(), auth.clone(), user.to_owned());
        set.spawn(async move {
            call(
                &app,
                post(
                    "/2fa/verify",
                    Some(&auth),
                    json!({ "user_id": user, "token": "000000" }),
                ),
            )
            .await
            .0
        });
    }
    let mut out = Vec::with_capacity(n);
    while let Some(res) = set.join_next().await {
        out.push(res.unwrap());
    }
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn full_2fa_lifecycle(pool: PgPool) {
    let app = app(pool);
    let user = "user_abc123";
    let auth = bearer(user);

    // ── enable ──────────────────────────────────────────────────────────
    let (status, body) = call(
        &app,
        post(
            "/2fa/enable",
            Some(&auth),
            json!({ "user_id": user, "email": "alice@kora.app" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let secret = body["secret"].as_str().unwrap().to_owned();
    let backup_codes: Vec<String> = body["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(backup_codes.len(), 10);
    assert!(body["qr_code_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://"));

    // ── verify activates 2FA ────────────────────────────────────────────
    let (status, body) = call(
        &app,
        post(
            "/2fa/verify",
            Some(&auth),
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], json!(true));

    // ── login with a valid token ───────────────────────────────────────
    let (status, body) = call(
        &app,
        post(
            "/2fa/login",
            None,
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session = body["session_token"].as_str().unwrap();
    assert_eq!(
        jwt::verify_bearer(session, JWT_SECRET).unwrap().sub,
        user,
        "session token is a valid JWT for the user"
    );

    // ── login with an expired token (90s in the past, outside skew) ─────
    let (status, _) = call(
        &app,
        post(
            "/2fa/login",
            None,
            json!({ "user_id": user, "token": totp_code(&secret, -3) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ── login with a malformed token ───────────────────────────────────
    let (status, body) = call(
        &app,
        post(
            "/2fa/login",
            None,
            json!({ "user_id": user, "token": "abc" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A successful verify clears the failure counter left by the expired /
    // malformed attempts above, so the lockout loop starts from zero.
    let (status, _) = call(
        &app,
        post(
            "/2fa/verify",
            Some(&auth),
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // ── 5 consecutive failures -> lockout (423 on the 5th) ─────────────
    for attempt in 1..=5 {
        let (status, _) = call(
            &app,
            post(
                "/2fa/verify",
                Some(&auth),
                json!({ "user_id": user, "token": "000000" }),
            ),
        )
        .await;
        let expected = if attempt < 5 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::LOCKED
        };
        assert_eq!(status, expected, "attempt {attempt}");
    }

    // A valid token is now refused because the account is locked.
    let (status, _) = call(
        &app,
        post(
            "/2fa/verify",
            Some(&auth),
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::LOCKED);

    // ── recover with a backup code: consumes it, disables 2FA ──────────
    let (status, body) = call(
        &app,
        post(
            "/2fa/recover",
            Some(&auth),
            json!({ "user_id": user, "backup_code": backup_codes[0] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], json!(true));
    assert_eq!(body["remaining_codes"], json!(9));

    // 2FA is off now: a second recover attempt 404s.
    let (status, _) = call(
        &app,
        post(
            "/2fa/recover",
            Some(&auth),
            json!({ "user_id": user, "backup_code": backup_codes[1] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // ── audit log recorded each event ─────────────────────────────────
    let (status, body) = call(&app, get(&format!("/2fa/audit-log/{user}"), Some(&auth))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(events.contains(&"enabled"), "{events:?}");
    assert!(events.contains(&"login"), "{events:?}");
    assert!(events.contains(&"recovered"), "{events:?}");
    // AuditLogEntry carries no user_id and AuditLogPage no page_size.
    assert!(body["entries"][0].get("user_id").is_none());
    assert!(body.get("page_size").is_none());
    assert_eq!(body["total"], json!(events.len()));

    // ── recovery log shows the one consumed code, scoped to this user ──
    let (status, body) = call(&app, get("/2fa/recovery-log", Some(&auth))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], json!(1));
    assert_eq!(body["entries"][0]["user_id"], json!(user));
    assert_eq!(body["entries"][0]["code_index"], json!(0));
    assert_eq!(body["page_size"], json!(20));
}

#[sqlx::test(migrations = "../../migrations")]
async fn auth_is_bearer_only_and_self_scoped(pool: PgPool) {
    let app = app(pool);

    // No bearer -> 401.
    let (status, _) = call(
        &app,
        post(
            "/2fa/enable",
            None,
            json!({ "user_id": "u1", "email": "u1@kora.app" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Bearer for a different subject -> 403.
    let (status, body) = call(
        &app,
        post(
            "/2fa/enable",
            Some(&bearer("someone_else")),
            json!({ "user_id": "u1", "email": "u1@kora.app" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], json!("FORBIDDEN"));

    // Set up two users, each with a consumed backup code.
    for user in ["u1", "u2"] {
        let auth = bearer(user);
        let (_, body) = call(
            &app,
            post(
                "/2fa/enable",
                Some(&auth),
                json!({ "user_id": user, "email": format!("{user}@kora.app") }),
            ),
        )
        .await;
        let secret = body["secret"].as_str().unwrap().to_owned();
        let code = body["backup_codes"][0].as_str().unwrap().to_owned();
        call(
            &app,
            post(
                "/2fa/verify",
                Some(&auth),
                json!({ "user_id": user, "token": totp_code(&secret, 0) }),
            ),
        )
        .await;
        call(
            &app,
            post(
                "/2fa/recover",
                Some(&auth),
                json!({ "user_id": user, "backup_code": code }),
            ),
        )
        .await;
    }

    // u1's recovery-log shows only u1's redemption.
    let (status, body) = call(&app, get("/2fa/recovery-log", Some(&bearer("u1")))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], json!(1));
    assert_eq!(body["entries"][0]["user_id"], json!("u1"));

    // u1 cannot read u2's audit log.
    let (status, _) = call(&app, get("/2fa/audit-log/u2", Some(&bearer("u1")))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Audit log for an unknown user -> 404.
    let (status, _) = call(&app, get("/2fa/audit-log/ghost", Some(&bearer("ghost")))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn enable_conflicts_once_active(pool: PgPool) {
    let app = app(pool);
    let user = "dup_user";
    let auth = bearer(user);
    let enable = || {
        post(
            "/2fa/enable",
            Some(&auth),
            json!({ "user_id": user, "email": "dup@kora.app" }),
        )
    };

    // First enable + a second while still pending both succeed (restart).
    let (s1, b1) = call(&app, enable()).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = call(&app, enable()).await;
    assert_eq!(s2, StatusCode::OK, "pending setup can restart");

    // Activate, then a further enable is a 409.
    let secret = b1["secret"].as_str().unwrap().to_owned();
    // The restart rotated the secret, so activate with the latest one.
    let (_, b2) = call(&app, enable()).await;
    let secret = b2["secret"].as_str().map(str::to_owned).unwrap_or(secret);
    call(
        &app,
        post(
            "/2fa/verify",
            Some(&auth),
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;

    let (status, body) = call(&app, enable()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], json!("TWO_FACTOR_ALREADY_ENABLED"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn health_reports_ok(pool: PgPool) {
    let app = app(pool);
    let (status, body) = call(&app, get("/health", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "status": "ok" }));
}

#[sqlx::test(migrations = "../../migrations")]
async fn lockout_counter_starts_at_zero(pool: PgPool) {
    let app = app(pool.clone());
    let user = "counter_zero";
    activate(&app, user).await;
    assert_eq!(failed_attempts(&pool, user).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_wrong_totp_never_loses_a_failure(pool: PgPool) {
    const N: usize = 5;
    let app = app(pool.clone());
    let user = "race_user";
    let secret = activate(&app, user).await;
    let auth = bearer(user);

    // Fire N wrong-TOTP verifies at the same user_id concurrently, the way a
    // parallel guessing attack would, rather than one after another.
    let statuses = race_wrong_totp(&app, user, N).await;
    assert_eq!(statuses.len(), N);
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::UNAUTHORIZED || *s == StatusCode::LOCKED),
        "each wrong guess is a 401, or a 423 once the lock trips: {statuses:?}"
    );

    // The whole point: every one of the N failures is counted. The old
    // read-modify-write in register_failure let concurrent requests read the
    // same starting count and write the same value, so this landed below N
    // and the lockout never tripped.
    assert_eq!(
        failed_attempts(&pool, user).await,
        N as i32,
        "all {N} concurrent failures must be recorded"
    );

    // N == MAX_FAILED_ATTEMPTS, so the lock genuinely tripped: even a valid
    // token is refused now.
    let (status, _) = call(
        &app,
        post(
            "/2fa/verify",
            Some(&auth),
            json!({ "user_id": user, "token": totp_code(&secret, 0) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::LOCKED);
}
