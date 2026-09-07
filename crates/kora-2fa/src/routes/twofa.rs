//! `/2fa/enable`, `/2fa/disable`, `/2fa/verify`, `/2fa/login`.

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;

use crate::crypto;
use crate::db::models::{
    AuditEvent, DisableTwoFactorRequest, EnableTwoFactorRequest, EnableTwoFactorResponse,
    SuccessResponse,
};
use crate::error::{ApiResult, AppError};
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
