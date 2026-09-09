//! `/2fa/enable`, `/2fa/disable`, `/2fa/verify`, `/2fa/login`.

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgExecutor;
use totp_rs::TOTP;

use crate::crypto;
use crate::db::models::{
    AuditEvent, DisableTwoFactorRequest, EnableTwoFactorRequest, EnableTwoFactorResponse,
    LoginResponse, LoginWithTwoFactorRequest, SuccessResponse, TwoFactorRow,
    VerifyTwoFactorRequest,
};
use crate::db::{LOCKOUT_DURATION, MAX_FAILED_ATTEMPTS};
use crate::error::{ApiResult, AppError};
use crate::jwt;
use crate::middleware::auth::AuthUser;
use crate::routes::{client_meta, insert_audit, load_record, AppState};
use crate::totp;

/// `POST /2fa/enable` — generate a TOTP secret + backup codes and store the
/// pending setup. Activation happens on the first `/2fa/verify`.
///
/// 200 `EnableTwoFactorResponse` · 400 · 401 · 403 (not self) ·
/// 409 when 2FA is already active.
pub async fn enable(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Result<Json<EnableTwoFactorRequest>, JsonRejection>,
) -> ApiResult<Json<EnableTwoFactorResponse>> {
    let Json(req) = body?;
    auth.require_self(&req.user_id)?;

    if req.user_id.trim().is_empty() {
        return Err(AppError::bad_request("user_id must not be empty"));
    }
    if !req.email.contains('@') || req.email.len() < 3 {
        return Err(AppError::bad_request("email is not a valid address"));
    }
    let issuer = req
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Kora App")
        .to_owned();

    // A fully-enabled record is a 409; a still-pending one may be restarted
    // (ASSUMPTIONS.md #9).
    if let Some(existing) = load_record(&state.pool, &req.user_id).await? {
        if existing.enabled {
            return Err(AppError::conflict(
                "TWO_FACTOR_ALREADY_ENABLED",
                "2FA is already enabled for this user",
            ));
        }
    }

    let secret = totp::generate_secret_base32();
    let (ciphertext, nonce) = crypto::seal_secret(&state.config.totp_encryption_key, &secret)?;
    let qr_code_uri = totp::otpauth_uri(&totp::build(&secret, &issuer, &req.email)?);

    let plaintext_codes = crypto::generate_backup_codes();
    let mut hashed = Vec::with_capacity(plaintext_codes.len());
    for code in &plaintext_codes {
        hashed.push(crypto::hash_backup_code(code)?);
    }

    let mut tx = state.pool.begin().await?;

    sqlx::query!(
        r#"
        INSERT INTO two_factor_records
            (user_id, email, issuer, secret_ciphertext, secret_nonce,
             enabled, pending, failed_attempts, locked_until, updated_at)
        VALUES ($1, $2, $3, $4, $5, FALSE, TRUE, 0, NULL, now())
        ON CONFLICT (user_id) DO UPDATE SET
            email             = EXCLUDED.email,
            issuer            = EXCLUDED.issuer,
            secret_ciphertext = EXCLUDED.secret_ciphertext,
            secret_nonce      = EXCLUDED.secret_nonce,
            enabled           = FALSE,
            pending           = TRUE,
            failed_attempts   = 0,
            locked_until      = NULL,
            updated_at        = now()
        "#,
        req.user_id,
        req.email,
        issuer,
        ciphertext,
        nonce,
    )
    .execute(&mut *tx)
    .await?;

    // Drop any unconsumed codes from a previous setup attempt; consumed rows
    // stay as recovery-log history (ASSUMPTIONS.md #7).
    sqlx::query!(
        "DELETE FROM backup_codes WHERE user_id = $1 AND consumed = FALSE",
        req.user_id,
    )
    .execute(&mut *tx)
    .await?;

    for (idx, hash) in hashed.iter().enumerate() {
        sqlx::query!(
            "INSERT INTO backup_codes (user_id, code_index, code_hash) VALUES ($1, $2, $3)",
            req.user_id,
            idx as i32,
            hash,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(Json(EnableTwoFactorResponse {
        secret,
        qr_code_uri,
        backup_codes: plaintext_codes,
    }))
}

/// `POST /2fa/disable` — clear the secret and unconsumed backup codes after
/// confirming a current TOTP token.
///
/// 200 `SuccessResponse` · 400 · 401 invalid token · 403 (not self) ·
/// 404 no record. No lockout (spec assigns 423 only to verify/login).
pub async fn disable(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Result<Json<DisableTwoFactorRequest>, JsonRejection>,
) -> ApiResult<Json<SuccessResponse>> {
    let Json(req) = body?;
    auth.require_self(&req.user_id)?;

    let record = load_record(&state.pool, &req.user_id)
        .await?
        .ok_or_else(|| AppError::not_found("no 2FA record for this user"))?;

    let (Some(ct), Some(nonce)) = (
        record.secret_ciphertext.as_deref(),
        record.secret_nonce.as_deref(),
    ) else {
        return Err(AppError::not_found("2FA is not enabled for this user"));
    };

    if !totp::is_valid_format(&req.token) {
        return Err(AppError::bad_request("token must be exactly 6 digits"));
    }

    let secret = crypto::open_secret(&state.config.totp_encryption_key, ct, nonce)?;
    let totp = totp::build(&secret, &record.issuer, &record.email)?;
    if !totp::verify(&totp, &req.token) {
        return Err(AppError::unauthorized(
            "INVALID_TOKEN",
            "the provided TOTP token is invalid",
        ));
    }

    let (ip, ua) = client_meta(&headers);
    let mut tx = state.pool.begin().await?;
    sqlx::query!(
        r#"
        UPDATE two_factor_records SET
            enabled           = FALSE,
            pending           = FALSE,
            secret_ciphertext = NULL,
            secret_nonce      = NULL,
            failed_attempts   = 0,
            locked_until      = NULL,
            updated_at        = now()
        WHERE user_id = $1
        "#,
        req.user_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "DELETE FROM backup_codes WHERE user_id = $1 AND consumed = FALSE",
        req.user_id,
    )
    .execute(&mut *tx)
    .await?;
    insert_audit(
        &mut *tx,
        &req.user_id,
        AuditEvent::Disabled,
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(SuccessResponse::ok("2FA disabled")))
}

/// `POST /2fa/verify` — validate a 6-digit TOTP. The first success after
/// `/2fa/enable` activates 2FA (`enabled` audit event); later successes are
/// plain checks (`verified`).
///
/// 200 `SuccessResponse` · 400 malformed · 401 invalid / not enabled ·
/// 403 (not self) · 423 locked. (The spec assigns no 404 to this endpoint.)
pub async fn verify(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Result<Json<VerifyTwoFactorRequest>, JsonRejection>,
) -> ApiResult<Json<SuccessResponse>> {
    let Json(req) = body?;
    auth.require_self(&req.user_id)?;
    let now = Utc::now();

    let record = load_record(&state.pool, &req.user_id)
        .await?
        .ok_or_else(|| {
            AppError::unauthorized("TWO_FACTOR_NOT_ENABLED", "2FA is not enabled for this user")
        })?;

    if record.is_locked(now) {
        return Err(AppError::locked(
            "account is locked after too many failed attempts",
        ));
    }
    if !totp::is_valid_format(&req.token) {
        return Err(AppError::bad_request("token must be exactly 6 digits"));
    }

    let totp = totp_from_record(&state, &record)?;
    if !totp::verify(&totp, &req.token) {
        return Err(register_failure(&state.pool, &record, now).await?);
    }

    let (ip, ua) = client_meta(&headers);
    let activating = record.pending;
    let mut tx = state.pool.begin().await?;
    sqlx::query!(
        r#"
        UPDATE two_factor_records
        SET enabled = TRUE, pending = FALSE,
            failed_attempts = 0, locked_until = NULL,
            updated_at = now()
        WHERE user_id = $1
        "#,
        req.user_id,
    )
    .execute(&mut *tx)
    .await?;
    let event = if activating {
        AuditEvent::Enabled
    } else {
        AuditEvent::Verified
    };
    insert_audit(&mut *tx, &req.user_id, event, ip.as_deref(), ua.as_deref()).await?;
    tx.commit().await?;

    Ok(Json(SuccessResponse::ok(if activating {
        "2FA enabled"
    } else {
        "token verified"
    })))
}

/// `POST /2fa/login` — second factor of a two-step login. Unauthenticated:
/// the spec gives this path no `security` block (ASSUMPTIONS.md #5). Returns
/// a freshly minted HS256 session token.
///
/// 200 `LoginResponse` · 400 malformed · 401 invalid / not enabled ·
/// 423 locked.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<LoginWithTwoFactorRequest>, JsonRejection>,
) -> ApiResult<Json<LoginResponse>> {
    let Json(req) = body?;
    let now = Utc::now();

    let not_enabled =
        || AppError::unauthorized("INVALID_TOKEN", "invalid TOTP token or 2FA not enabled");

    let record = load_record(&state.pool, &req.user_id)
        .await?
        .ok_or_else(not_enabled)?;

    if record.is_locked(now) {
        return Err(AppError::locked(
            "account is locked after too many failed attempts",
        ));
    }
    if !record.enabled {
        return Err(not_enabled());
    }
    if !totp::is_valid_format(&req.token) {
        return Err(AppError::bad_request("token must be exactly 6 digits"));
    }

    let totp = totp_from_record(&state, &record)?;
    if !totp::verify(&totp, &req.token) {
        return Err(register_failure(&state.pool, &record, now).await?);
    }

    let (ip, ua) = client_meta(&headers);
    let mut tx = state.pool.begin().await?;
    clear_failures(&mut *tx, &req.user_id).await?;
    insert_audit(
        &mut *tx,
        &req.user_id,
        AuditEvent::Login,
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;
    tx.commit().await?;

    let session_token = jwt::mint_session_token(
        &req.user_id,
        &state.config.jwt_secret,
        state.config.session_token_ttl,
    )?;
    Ok(Json(LoginResponse { session_token }))
}

// ─── shared lockout / verification helpers ─────────────────────────────────

/// Decrypt a record's stored secret and build a live `TOTP`. A record with
/// no secret means 2FA is not active → 401.
fn totp_from_record(state: &AppState, record: &TwoFactorRow) -> ApiResult<TOTP> {
    let (ct, nonce) = record
        .secret_ciphertext
        .as_deref()
        .zip(record.secret_nonce.as_deref())
        .ok_or_else(|| {
            AppError::unauthorized("TWO_FACTOR_NOT_ENABLED", "2FA is not enabled for this user")
        })?;
    let secret = crypto::open_secret(&state.config.totp_encryption_key, ct, nonce)?;
    Ok(totp::build(&secret, &record.issuer, &record.email)?)
}

/// Record one failed attempt against `record`. Trips the lock on the
/// `MAX_FAILED_ATTEMPTS`-th consecutive failure. Returns the error the caller
/// should surface: 423 once locked, otherwise 401.
async fn register_failure(
    exec: impl PgExecutor<'_>,
    record: &TwoFactorRow,
    now: DateTime<Utc>,
) -> Result<AppError, sqlx::Error> {
    let attempts = record.failed_attempts + 1;
    let locked = attempts >= MAX_FAILED_ATTEMPTS;
    let locked_until = locked.then(|| lockout_deadline(now));

    sqlx::query!(
        r#"
        UPDATE two_factor_records
        SET failed_attempts = $2, locked_until = $3, updated_at = now()
        WHERE user_id = $1
        "#,
        record.user_id,
        attempts,
        locked_until,
    )
    .execute(exec)
    .await?;

    Ok(failure_error(locked))
}

/// The error a failed TOTP check surfaces to the caller: **423** once the
/// lockout has tripped, otherwise a plain **401**.
fn failure_error(locked: bool) -> AppError {
    if locked {
        AppError::locked("account locked after too many failed attempts; retry in 15 minutes")
    } else {
        AppError::unauthorized("INVALID_TOKEN", "the provided TOTP token is invalid")
    }
}

/// The `locked_until` value for a lockout that trips at `now`: `now` plus the
/// configured `LOCKOUT_DURATION`.
fn lockout_deadline(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::seconds(LOCKOUT_DURATION.as_secs() as i64)
}

/// Clear the failure counter and lock after any successful verification.
async fn clear_failures(exec: impl PgExecutor<'_>, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE two_factor_records SET failed_attempts = 0, locked_until = NULL WHERE user_id = $1",
        user_id,
    )
    .execute(exec)
    .await
    .map(|_| ())
}
