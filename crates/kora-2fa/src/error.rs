//! The shared error envelope.
//!
//! Every error response in `docs/openapi.yaml` is the same shape:
//! ```json
//! { "error": "<machine-readable code>", "message": "<human-readable detail>" }
//! ```
//! `AppError` is the one type handlers return on the sad path; its
//! `IntoResponse` renders exactly that envelope with the status code the spec
//! assigns to each situation.

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Handler result alias.
pub type ApiResult<T> = Result<T, AppError>;

/// A fully-formed error response: HTTP status + `{error, message}` body.
#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

/// Wire shape of the error envelope.
#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: &'a str,
}

impl AppError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// 400 — invalid request body or parameters.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    /// 401 — missing/invalid auth, or an invalid/expired TOTP or backup code.
    /// `code` distinguishes the cases (`UNAUTHORIZED`, `INVALID_TOKEN`,
    /// `INVALID_BACKUP_CODE`, `TWO_FACTOR_NOT_ENABLED`, ...).
    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    /// 403 — authenticated, but `jwt.sub` does not own the target resource.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "FORBIDDEN", message)
    }

    /// 404 — no 2FA record for the requested user.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    /// 409 — 2FA already enabled for this user.
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    /// 423 — account locked after too many failed attempts.
    pub fn locked(message: impl Into<String>) -> Self {
        Self::new(StatusCode::LOCKED, "ACCOUNT_LOCKED", message)
    }

    /// 500 — unexpected server-side failure. The detail is logged, not leaked.
    pub fn internal(context: impl std::fmt::Display) -> Self {
        tracing::error!(error = %context, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "An internal error occurred",
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.code,
            message: &self.message,
        };
        (self.status, Json(body)).into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.status.as_u16(),
            self.code,
            self.message
        )
    }
}

impl std::error::Error for AppError {}

/// Database failures are always 500 to the caller; the cause is logged.
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::internal(format!("database error: {err}"))
    }
}

/// A malformed / wrong-shape JSON body is a 400, in the envelope, not Axum's
/// default plain-text 422.
impl From<JsonRejection> for AppError {
    fn from(rej: JsonRejection) -> Self {
        Self::bad_request(rej.body_text())
    }
}

impl From<QueryRejection> for AppError {
    fn from(rej: QueryRejection) -> Self {
        Self::bad_request(rej.body_text())
    }
}

impl From<PathRejection> for AppError {
    fn from(rej: PathRejection) -> Self {
        Self::bad_request(rej.body_text())
    }
}
