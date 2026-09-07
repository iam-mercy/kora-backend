//! Bearer-JWT authentication extractor.
//!
//! `AuthUser` is the gate on every authenticated Phase 1 endpoint. It pulls
//! the `Authorization: Bearer <jwt>` header, verifies it (HS256, `exp`
//! enforced), and exposes the `sub` claim. Phase 1 has no `X-User-Id`
//! service-to-service alternate — that header is never read (ASSUMPTIONS.md
//! #2).

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::error::AppError;
use crate::jwt;
use crate::routes::AppState;

/// An authenticated caller. Its `sub` is the only authorization signal in
/// Phase 1 — see [`AuthUser::require_self`].
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub sub: String,
}

impl AuthUser {
    /// Enforce the uniform Phase 1 rule (ASSUMPTIONS.md #6): the caller may
    /// only act on their own `user_id`. Any mismatch is a 403 — there is no
    /// admin override yet.
    pub fn require_self(&self, resource_user_id: &str) -> Result<(), AppError> {
        if self.sub == resource_user_id {
            Ok(())
        } else {
            Err(AppError::forbidden(
                "token subject does not match the requested user_id",
            ))
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::unauthorized("UNAUTHORIZED", "missing Authorization header")
            })?;

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| AppError::unauthorized("UNAUTHORIZED", "expected a Bearer token"))?;

        let claims = jwt::verify_bearer(token, &state.config.jwt_secret)?;
        Ok(AuthUser { sub: claims.sub })
    }
}
