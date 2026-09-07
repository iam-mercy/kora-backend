-- Phase 1 schema for the kora-2fa service.
--
-- Column names and types are chosen to line up with the OpenAPI schemas in
-- docs/openapi.yaml so handler responses serialize with no translation layer
-- (see ASSUMPTIONS.md #13).

-- ── two_factor_records ─────────────────────────────────────────────────────
-- One row per user. `user_id` is the caller-supplied identifier (Supabase /
-- Kora App user id); this service never mints it.
CREATE TABLE two_factor_records (
    user_id           TEXT PRIMARY KEY,
    email             TEXT NOT NULL,
    issuer            TEXT NOT NULL DEFAULT 'Kora App',

    -- Base32 TOTP secret, AES-256-GCM sealed with TOTP_ENCRYPTION_KEY
    -- (ASSUMPTIONS.md #3). `secret_ciphertext` includes the GCM tag;
    -- `secret_nonce` is the 96-bit IV. Both NULL once 2FA is disabled —
    -- "disable clears all stored secrets" (openapi.yaml /2fa/disable).
    secret_ciphertext BYTEA,
    secret_nonce      BYTEA,

    -- State machine (ASSUMPTIONS.md #10):
    --   /2fa/enable       -> enabled=false, pending=true
    --   first /2fa/verify -> enabled=true,  pending=false
    --   /2fa/disable      -> enabled=false, pending=false, secret NULLed
    --   /2fa/recover      -> enabled=false, pending=false, secret NULLed
    enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    pending           BOOLEAN NOT NULL DEFAULT TRUE,

    -- Postgres-backed lockout (ASSUMPTIONS.md #8): 5 consecutive failed TOTP
    -- checks -> locked_until = now() + 15 min. No Redis in Phase 1.
    failed_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until      TIMESTAMPTZ,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A secret is present exactly while 2FA is active or mid-setup.
    CONSTRAINT secret_presence_matches_state
        CHECK ((secret_ciphertext IS NOT NULL) = (enabled OR pending)),
    -- Ciphertext and nonce are set/cleared together.
    CONSTRAINT secret_nonce_paired
        CHECK ((secret_ciphertext IS NULL) = (secret_nonce IS NULL))
);

-- ── backup_codes ───────────────────────────────────────────────────────────
-- Per-user one-time recovery codes. Plaintext is returned exactly once from
-- /2fa/enable; only the Argon2id hash is stored. Consumed rows are retained
-- forever as the source for /2fa/recovery-log (ASSUMPTIONS.md #7). On
-- (re-)enable the service deletes the user's UNCONSUMED rows and inserts a
-- fresh batch, so there is deliberately no UNIQUE(user_id, code_index):
-- `code_index` only labels position within a batch, and consumed rows from
-- an earlier enrollment may repeat an index (disambiguated by consumed_at).
CREATE TABLE backup_codes (
    id          BIGSERIAL PRIMARY KEY,
    user_id     TEXT NOT NULL
                    REFERENCES two_factor_records (user_id) ON DELETE CASCADE,
    code_index  INTEGER NOT NULL,
    code_hash   TEXT NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT consumed_at_matches_consumed
        CHECK (consumed = (consumed_at IS NOT NULL))
);

CREATE INDEX backup_codes_user_consumed_idx ON backup_codes (user_id, consumed);
CREATE INDEX backup_codes_recovery_log_idx
    ON backup_codes (user_id, consumed_at DESC)
    WHERE consumed;

-- ── audit_log ──────────────────────────────────────────────────────────────
-- Append-only. `event` matches AuditLogEntry.event exactly. `created_at`
-- serializes as "timestamp" in the API. `user_id` is for filtering only and
-- is NOT emitted inside AuditLogEntry. No FK: audit history outlives the 2FA
-- record.
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    TEXT NOT NULL,
    event      TEXT NOT NULL
                   CHECK (event IN ('enabled', 'disabled', 'verified', 'recovered', 'login')),
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_user_created_idx ON audit_log (user_id, created_at DESC);
