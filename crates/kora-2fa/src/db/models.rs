//! Request bodies, response DTOs, and DB row types.
//!
//! Field names and JSON shapes here mirror `docs/openapi.yaml` exactly so
//! handlers can return these types with no translation layer (ASSUMPTIONS.md
//! #13). Serialization differences from a naive derive are called out inline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Requests ──────────────────────────────────────────────────────────────

/// `EnableTwoFactorRequest`
#[derive(Debug, Deserialize)]
pub struct EnableTwoFactorRequest {
    pub user_id: String,
    pub email: String,
    /// Issuer label shown in authenticator apps. Defaults to `Kora App`.
    #[serde(default)]
    pub issuer: Option<String>,
}

/// `DisableTwoFactorRequest`
#[derive(Debug, Deserialize)]
pub struct DisableTwoFactorRequest {
    pub user_id: String,
    /// Current TOTP code, to confirm intent.
    pub token: String,
}

/// `VerifyTwoFactorRequest`
#[derive(Debug, Deserialize)]
pub struct VerifyTwoFactorRequest {
    pub user_id: String,
    pub token: String,
}

/// `LoginWithTwoFactorRequest`
#[derive(Debug, Deserialize)]
pub struct LoginWithTwoFactorRequest {
    pub user_id: String,
    pub token: String,
}

/// `RecoverWithBackupRequest`
#[derive(Debug, Deserialize)]
pub struct RecoverWithBackupRequest {
    pub user_id: String,
    pub backup_code: String,
}

/// `page` / `page_size` query parameters, shared by the two log endpoints.
/// Bounds match `components.parameters` in `docs/openapi.yaml`
/// (page >= 0 default 0; page_size 1..=100 default 20).
#[derive(Debug, Deserialize)]
pub struct Pagination {
    #[serde(default)]
    pub page: Option<i64>,
    #[serde(default)]
    pub page_size: Option<i64>,
}

/// Clamped, ready-to-use pagination values.
#[derive(Debug, Clone, Copy)]
pub struct PageSpec {
    pub page: i64,
    pub page_size: i64,
}

impl Pagination {
    pub fn resolve(&self) -> PageSpec {
        let page = self.page.unwrap_or(0).max(0);
        let page_size = self.page_size.unwrap_or(20).clamp(1, 100);
        PageSpec { page, page_size }
    }
}

impl PageSpec {
    pub fn offset(&self) -> i64 {
        self.page * self.page_size
    }
}

// ─── Responses ─────────────────────────────────────────────────────────────

/// `EnableTwoFactorResponse`
#[derive(Debug, Serialize)]
pub struct EnableTwoFactorResponse {
    /// Base32-encoded TOTP secret.
    pub secret: String,
    /// `otpauth://` URI for QR-code generation.
    pub qr_code_uri: String,
    /// One-time backup codes, plaintext, returned exactly once.
    pub backup_codes: Vec<String>,
}

/// `SuccessResponse`. `message` is optional in the spec; omitted from JSON
/// when not set.
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl SuccessResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: Some(message.into()),
        }
    }
}

/// `LoginResponse`
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_token: String,
}

/// `RecoverWithBackupResponse`
#[derive(Debug, Serialize)]
pub struct RecoverWithBackupResponse {
    pub success: bool,
    /// Backup codes still available after this one was consumed.
    pub remaining_codes: i64,
}

/// `RecoveryLogEntry`
#[derive(Debug, Serialize)]
pub struct RecoveryLogEntry {
    pub user_id: String,
    pub used_at: DateTime<Utc>,
    pub code_index: i32,
}

/// `RecoveryLogPage` — has `page_size` (unlike `AuditLogPage`).
#[derive(Debug, Serialize)]
pub struct RecoveryLogPage {
    pub entries: Vec<RecoveryLogEntry>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// `AuditLogEntry`. Note: the schema has **no `user_id` field** — it is
/// intentionally not serialized here. `timestamp` is the row's `created_at`.
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub event: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// `AuditLogPage` — note: **no `page_size` field**, matching the spec.
#[derive(Debug, Serialize)]
pub struct AuditLogPage {
    pub entries: Vec<AuditLogEntry>,
    pub total: i64,
    pub page: i64,
}

// ─── Audit events ──────────────────────────────────────────────────────────

/// The `AuditLogEntry.event` enum. Serializes/stores as its lowercase name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    Enabled,
    Disabled,
    Verified,
    Recovered,
    Login,
}

impl AuditEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEvent::Enabled => "enabled",
            AuditEvent::Disabled => "disabled",
            AuditEvent::Verified => "verified",
            AuditEvent::Recovered => "recovered",
            AuditEvent::Login => "login",
        }
    }
}

// ─── DB rows ───────────────────────────────────────────────────────────────

/// A `two_factor_records` row, as loaded by `user_id`.
#[derive(Debug)]
pub struct TwoFactorRow {
    pub user_id: String,
    pub email: String,
    pub issuer: String,
    pub secret_ciphertext: Option<Vec<u8>>,
    pub secret_nonce: Option<Vec<u8>>,
    pub enabled: bool,
    pub pending: bool,
    pub failed_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TwoFactorRow {
    /// True while `locked_until` is in the future.
    pub fn is_locked(&self, now: DateTime<Utc>) -> bool {
        self.locked_until.is_some_and(|until| until > now)
    }
}
