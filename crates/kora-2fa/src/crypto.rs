//! At-rest encryption for the TOTP secret, and hashing for backup codes.
//!
//! - TOTP secret: AES-256-GCM under `TOTP_ENCRYPTION_KEY` (ASSUMPTIONS.md #3).
//!   A fresh random 96-bit nonce per row is stored next to the ciphertext.
//! - Backup codes: Argon2id PHC strings. Plaintext is never persisted
//!   (ASSUMPTIONS.md #13).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::rand_core::OsRng as ArgonRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::Rng;

/// Unambiguous alphabet for backup codes (no `0/O`, `1/I/L`).
const BACKUP_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// Backup codes generated per `/2fa/enable`.
pub const BACKUP_CODE_COUNT: usize = 10;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("failed to encrypt secret")]
    Encrypt,
    #[error("failed to decrypt secret")]
    Decrypt,
    #[error("password hashing failed: {0}")]
    Hash(String),
}

impl From<CryptoError> for crate::error::AppError {
    fn from(err: CryptoError) -> Self {
        crate::error::AppError::internal(err)
    }
}

/// Seal a TOTP secret. Returns `(ciphertext_with_tag, nonce)`.
pub fn seal_secret(key: &[u8; 32], plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::Encrypt)?;
    Ok((ciphertext, nonce.to_vec()))
}

/// Open a sealed TOTP secret. Fails on a wrong key, wrong nonce, or any
/// tampering (GCM tag mismatch).
pub fn open_secret(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<String, CryptoError> {
    if nonce.len() != 12 {
        return Err(CryptoError::Decrypt);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::Decrypt)
}

/// Generate `BACKUP_CODE_COUNT` fresh backup codes in `XXXX-XXXX` form.
pub fn generate_backup_codes() -> Vec<String> {
    let mut rng = OsRng;
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let pick = |rng: &mut OsRng| {
                let chars: Vec<u8> = (0..8)
                    .map(|_| BACKUP_ALPHABET[rng.gen_range(0..BACKUP_ALPHABET.len())])
                    .collect();
                String::from_utf8(chars).expect("alphabet is ASCII")
            };
            let s = pick(&mut rng);
            format!("{}-{}", &s[..4], &s[4..])
        })
        .collect()
}

/// Argon2id hash of a backup code, as a PHC string for storage.
pub fn hash_backup_code(code: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut ArgonRng);
    Argon2::default()
        .hash_password(normalize(code).as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CryptoError::Hash(e.to_string()))
}

/// Constant-time-ish verification of a candidate backup code against a stored
/// PHC hash. A malformed stored hash returns `false`, not an error.
pub fn verify_backup_code(candidate: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(normalize(candidate).as_bytes(), &parsed)
        .is_ok()
}

/// Backup codes are compared case-insensitively with surrounding whitespace
/// and any internal dashes/spaces removed, so `a1b2-c3d4`, `A1B2 C3D4`, and
/// `A1B2-C3D4` all match.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn seal_open_round_trips() {
        let (ct, nonce) = seal_secret(&KEY, "JBSWY3DPEHPK3PXP").unwrap();
        assert_ne!(ct, b"JBSWY3DPEHPK3PXP");
        assert_eq!(nonce.len(), 12);
        assert_eq!(open_secret(&KEY, &ct, &nonce).unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let (ct, nonce) = seal_secret(&KEY, "SECRETVALUE").unwrap();
        let wrong = [8u8; 32];
        assert!(open_secret(&wrong, &ct, &nonce).is_err());
    }

    #[test]
    fn open_tampered_ciphertext_fails() {
        let (mut ct, nonce) = seal_secret(&KEY, "SECRETVALUE").unwrap();
        ct[0] ^= 0xff;
        assert!(open_secret(&KEY, &ct, &nonce).is_err());
    }

    #[test]
    fn nonces_differ_between_calls() {
        let (_, n1) = seal_secret(&KEY, "X").unwrap();
        let (_, n2) = seal_secret(&KEY, "X").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn backup_codes_are_well_formed_and_distinct() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        for code in &codes {
            let (a, b) = code.split_once('-').expect("dash-separated");
            assert_eq!(a.len(), 4);
            assert_eq!(b.len(), 4);
            assert!(code
                .chars()
                .all(|c| c == '-' || BACKUP_ALPHABET.contains(&(c as u8))));
        }
    }

    #[test]
    fn hash_then_verify() {
        let hash = hash_backup_code("A1B2-C3D4").unwrap();
        assert!(verify_backup_code("A1B2-C3D4", &hash));
        // Normalization: formatting differences still match.
        assert!(verify_backup_code("a1b2c3d4", &hash));
        assert!(!verify_backup_code("Z9Z9-Z9Z9", &hash));
    }

    #[test]
    fn verify_rejects_malformed_stored_hash() {
        assert!(!verify_backup_code("whatever", "not-a-phc-string"));
    }
}
