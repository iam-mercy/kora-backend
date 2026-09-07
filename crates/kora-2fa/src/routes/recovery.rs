//! `/2fa/recover`, `/2fa/recovery-log`, `/2fa/audit-log/{user_id}`.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;

use crate::crypto;
use crate::db::models::{
    AuditEvent, AuditLogEntry, AuditLogPage, Pagination, RecoverWithBackupRequest,
    RecoverWithBackupResponse, RecoveryLogEntry, RecoveryLogPage,
};
use crate::error::{ApiResult, AppError};
use crate::middleware::auth::AuthUser;
use crate::routes::{client_meta, insert_audit, load_record, AppState};

/// `POST /2fa/recover` — consume one backup code and disable 2FA so the user
/// can re-enrol on a new device.
///
/// 200 `RecoverWithBackupResponse` · 400 · 401 invalid code · 403 (not self)
/// · 404 no record. No lockout (spec assigns 423 only to verify/login).
pub async fn recover(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Result<Json<RecoverWithBackupRequest>, JsonRejection>,
) -> ApiResult<Json<RecoverWithBackupResponse>> {
    let Json(req) = body?;
    auth.require_self(&req.user_id)?;

    let record = load_record(&state.pool, &req.user_id)
        .await?
        .ok_or_else(|| AppError::not_found("no 2FA record for this user"))?;
    if !record.enabled {
        return Err(AppError::not_found("2FA is not enabled for this user"));
    }

    let candidates = sqlx::query!(
        r#"
        SELECT id, code_hash
        FROM backup_codes
        WHERE user_id = $1 AND consumed = FALSE
        ORDER BY code_index
        "#,
        req.user_id,
    )
    .fetch_all(&state.pool)
    .await?;

    let matched = candidates
        .into_iter()
        .find(|row| crypto::verify_backup_code(&req.backup_code, &row.code_hash));

    let Some(matched) = matched else {
        return Err(AppError::unauthorized(
            "INVALID_BACKUP_CODE",
            "the provided backup code is invalid or already used",
        ));
    };

    let (ip, ua) = client_meta(&headers);
    let mut tx = state.pool.begin().await?;
    sqlx::query!(
        "UPDATE backup_codes SET consumed = TRUE, consumed_at = now() WHERE id = $1",
        matched.id,
    )
    .execute(&mut *tx)
    .await?;
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
    insert_audit(
        &mut *tx,
        &req.user_id,
        AuditEvent::Recovered,
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;
    tx.commit().await?;

    let remaining_codes = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!" FROM backup_codes WHERE user_id = $1 AND consumed = FALSE"#,
        req.user_id,
    )
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(RecoverWithBackupResponse {
        success: true,
        remaining_codes,
    }))
}

/// `GET /2fa/recovery-log` — this caller's backup-code redemptions, paginated.
///
/// There is no `user_id` parameter, so the query is scoped to `jwt.sub`
/// (ASSUMPTIONS.md #6): a caller only ever sees their own redemptions.
///
/// 200 `RecoveryLogPage` · 401.
pub async fn recovery_log(
    State(state): State<AppState>,
    auth: AuthUser,
    page: Result<Query<Pagination>, QueryRejection>,
) -> ApiResult<Json<RecoveryLogPage>> {
    let Query(pagination) = page?;
    let spec = pagination.resolve();

    let entries = sqlx::query_as!(
        RecoveryLogEntry,
        r#"
        SELECT user_id,
               consumed_at AS "used_at!",
               code_index
        FROM backup_codes
        WHERE consumed = TRUE AND user_id = $1
        ORDER BY consumed_at DESC
        LIMIT $2 OFFSET $3
        "#,
        auth.sub,
        spec.page_size,
        spec.offset(),
    )
    .fetch_all(&state.pool)
    .await?;

    let total = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!" FROM backup_codes WHERE consumed = TRUE AND user_id = $1"#,
        auth.sub,
    )
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(RecoveryLogPage {
        entries,
        total,
        page: spec.page,
        page_size: spec.page_size,
    }))
}

/// `GET /2fa/audit-log/{user_id}` — paginated 2FA audit events for a user.
///
/// Self-only: `jwt.sub` must equal the path `user_id`, otherwise 403
/// (ASSUMPTIONS.md #6).
///
/// 200 `AuditLogPage` · 401 · 403 (not self) · 404 no record.
pub async fn audit_log(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
    page: Result<Query<Pagination>, QueryRejection>,
) -> ApiResult<Json<AuditLogPage>> {
    auth.require_self(&user_id)?;
    let Query(pagination) = page?;
    let spec = pagination.resolve();

    if load_record(&state.pool, &user_id).await?.is_none() {
        return Err(AppError::not_found("no 2FA record for this user"));
    }

    let entries = sqlx::query_as!(
        AuditLogEntry,
        r#"
        SELECT event,
               created_at AS "timestamp!",
               ip_address,
               user_agent
        FROM audit_log
        WHERE user_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT $2 OFFSET $3
        "#,
        user_id,
        spec.page_size,
        spec.offset(),
    )
    .fetch_all(&state.pool)
    .await?;

    let total = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!" FROM audit_log WHERE user_id = $1"#,
        user_id,
    )
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(AuditLogPage {
        entries,
        total,
        page: spec.page,
    }))
}
