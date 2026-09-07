//! TOTP generation and verification.
//!
//! The RFC 6238 algorithm itself comes from the `totp-rs` crate — it is not
//! hand-rolled here. Phase 1 fixes the parameters to the authenticator-app
//! defaults (ASSUMPTIONS.md #12): HMAC-SHA1, 6 digits, 30-second step, and a
//! ±1-step (±30s) verification window.

use totp_rs::{Algorithm, Secret, TOTP};

pub const ALGORITHM: Algorithm = Algorithm::SHA1;
pub const DIGITS: usize = 6;
pub const STEP: u64 = 30;
pub const SKEW: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("stored TOTP secret is not valid base32")]
    Secret,
    #[error("could not construct TOTP: {0}")]
    Build(String),
}

impl From<TotpError> for crate::error::AppError {
    fn from(err: TotpError) -> Self {
        crate::error::AppError::internal(err)
    }
}

/// A freshly generated 160-bit secret, base32-encoded (this is the exact
/// string returned as `EnableTwoFactorResponse.secret`).
pub fn generate_secret_base32() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// Build a `TOTP` from a stored base32 secret plus the labels that go into
/// the `otpauth://` URI.
pub fn build(secret_base32: &str, issuer: &str, account_name: &str) -> Result<TOTP, TotpError> {
    let bytes = Secret::Encoded(secret_base32.to_owned())
        .to_bytes()
        .map_err(|_| TotpError::Secret)?;
    TOTP::new(
        ALGORITHM,
        DIGITS,
        SKEW,
        STEP,
        bytes,
        Some(issuer.to_owned()),
        account_name.to_owned(),
    )
    .map_err(|e| TotpError::Build(e.to_string()))
}

/// `otpauth://totp/...` URI for QR-code generation.
pub fn otpauth_uri(totp: &TOTP) -> String {
    totp.get_url()
}

/// Verify a candidate token against the current time (±`SKEW` steps). A clock
/// error is treated as a failed verification.
pub fn verify(totp: &TOTP, token: &str) -> bool {
    totp.check_current(token).unwrap_or(false)
}

/// True iff `token` is exactly 6 ASCII digits. Handlers use this to return
/// 400 (malformed) rather than 401 (well-formed but wrong).
pub fn is_valid_format(token: &str) -> bool {
    token.len() == DIGITS && token.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totp() -> TOTP {
        build(&generate_secret_base32(), "Kora App", "alice@kora.app").unwrap()
    }

    #[test]
    fn generated_secret_is_at_least_128_bits() {
        let s = generate_secret_base32();
        let bytes = Secret::Encoded(s).to_bytes().unwrap();
        assert!(bytes.len() >= 16, "got {} bytes", bytes.len());
    }

    #[test]
    fn current_token_verifies() {
        let t = totp();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = t.generate(now);
        assert!(verify(&t, &token));
    }

    #[test]
    fn wrong_token_is_rejected() {
        let t = totp();
        assert!(!verify(&t, "000000"));
    }

    #[test]
    fn skew_allows_one_step_but_not_two() {
        let t = totp();
        let now = 1_700_000_000u64; // fixed reference instant
        let one_step_ago = t.generate(now - STEP);
        let two_steps_ago = t.generate(now - 2 * STEP);
        assert!(t.check(&one_step_ago, now));
        assert!(!t.check(&two_steps_ago, now));
    }

    #[test]
    fn otpauth_uri_has_issuer_and_scheme() {
        let uri = otpauth_uri(&totp());
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(uri.contains("issuer=Kora%20App"), "{uri}");
        assert!(uri.contains("secret="), "{uri}");
    }

    #[test]
    fn format_check() {
        assert!(is_valid_format("123456"));
        assert!(!is_valid_format("12345"));
        assert!(!is_valid_format("1234567"));
        assert!(!is_valid_format("12a456"));
        assert!(!is_valid_format(""));
    }
}
