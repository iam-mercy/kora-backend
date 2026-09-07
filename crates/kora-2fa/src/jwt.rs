//! HS256 bearer-token verification and session-token minting.
//!
//! `openapi.yaml` requires a "Supabase / Kora App JWT" but
//! `environment-variables.md` documents no JWT config, so Phase 1 verifies
//! HS256 tokens against a single `JWT_SECRET` and does not check issuer or
//! audience (ASSUMPTIONS.md #1). `/2fa/login` mints its session token the
//! same way (ASSUMPTIONS.md #5), with a `SESSION_TOKEN_TTL_SECS` lifetime.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// Minimal claim set: subject + issued-at + expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// The authenticated user id.
    pub sub: String,
    /// Issued-at (seconds since the Unix epoch).
    pub iat: u64,
    /// Expiry (seconds since the Unix epoch). Verification enforces this.
    pub exp: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("invalid or expired token: {0}")]
    Invalid(String),
    #[error("could not mint session token: {0}")]
    Mint(String),
}

impl From<JwtError> for AppError {
    fn from(err: JwtError) -> Self {
        match err {
            JwtError::Invalid(msg) => AppError::unauthorized("INVALID_TOKEN", msg),
            JwtError::Mint(msg) => AppError::internal(msg),
        }
    }
}

/// Verify an HS256 bearer token and return its claims. Enforces the `exp`
/// claim; does not validate issuer/audience (none configured — see
/// ASSUMPTIONS.md #1).
pub fn verify_bearer(token: &str, secret: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    // No clock-skew grace: an expired token is expired. (jsonwebtoken
    // defaults to 60s of leeway.)
    validation.leeway = 0;
    validation.set_required_spec_claims(&["exp", "sub"]);
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| JwtError::Invalid(e.to_string()))
}

/// Mint a short-lived HS256 session token for `sub`.
pub fn mint_session_token(sub: &str, secret: &str, ttl: Duration) -> Result<String, JwtError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| JwtError::Mint(e.to_string()))?
        .as_secs();
    let claims = Claims {
        sub: sub.to_owned(),
        iat: now,
        exp: now + ttl.as_secs(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| JwtError::Mint(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    #[test]
    fn mint_then_verify_round_trips() {
        let token = mint_session_token("user_abc123", SECRET, Duration::from_secs(60)).unwrap();
        let claims = verify_bearer(&token, SECRET).unwrap();
        assert_eq!(claims.sub, "user_abc123");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = mint_session_token("u", SECRET, Duration::from_secs(60)).unwrap();
        assert!(verify_bearer(&token, "other-secret").is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        // exp in the past.
        let token = mint_session_token("u", SECRET, Duration::from_secs(0)).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(verify_bearer(&token, SECRET).is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(verify_bearer("not.a.jwt", SECRET).is_err());
    }
}
