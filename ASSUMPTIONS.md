# ASSUMPTIONS — kora-backend Phase 1

Every judgment call made while implementing Phase 1 of the `kora-2fa` service.
The authoritative contract is `docs/openapi.yaml` +
`docs/environment-variables.md` (both fetched verbatim from
`github.com/iam-mercy/kora-app`). Where those two files are silent or
contradict each other, the resolution is recorded here rather than guessed
silently.

---

## 1. `JWT_SECRET` — added env var, not in the authoritative env doc

`openapi.yaml` puts `bearerAuth` ("Supabase / Kora App JWT") on nearly every
endpoint, but `environment-variables.md` documents **no** JWT secret, JWKS
URL, issuer, or audience anywhere.

**Decision:** add a single `JWT_SECRET` env var and verify tokens as
**HS256**. Middleware checks signature + `exp` only and extracts the `sub`
claim as the authenticated principal. No user/session table is built.

**Gap:** this is a divergence from the authoritative env-var doc. Real Kora
/ Supabase auth is almost certainly RS256/ES256 against a JWKS endpoint with
issuer + audience validation. `JWT_SECRET` should be replaced with the real
auth-infra config (`SUPABASE_JWT_SECRET` / JWKS URL / `JWT_ISSUER` /
`JWT_AUDIENCE`) once that decision is made, and this doc reconciled with a
new revision of `environment-variables.md`.

---

## 2. `X-User-Id` service-to-service header — deferred, not implemented

`openapi.yaml`'s prose says read/verification endpoints "accept either
Bearer JWT or an `X-User-Id` header for service-to-service calls." But **no
such `securityScheme` is defined** in `components.securitySchemes` (only
`bearerAuth`), and every Phase 1 endpoint's `security` block lists
`bearerAuth` alone.

**Decision:** implement what is machine-specified — **Bearer JWT only** — on
every authenticated endpoint. The `X-User-Id` alternate is **not** read and
has no effect.

**Deferred:** an `X-User-Id` (or mTLS / service-token) path for trusted
service-to-service callers, to arrive alongside a real `securityScheme` in
the spec and the RBAC / admin work in a later phase.

---

## 3. `TOTP_ENCRYPTION_KEY` — added env var, not in the authoritative env doc

`EnableTwoFactorResponse.secret` is documented as "Base32-encoded TOTP
secret (store securely)". Storing it plaintext in Postgres is not "securely".

**Decision:** add a `TOTP_ENCRYPTION_KEY` env var — 32 bytes, base64-encoded
(standard alphabet, padding optional) — and encrypt the TOTP secret at rest
with **AES-256-GCM** (random 96-bit nonce per row, stored alongside the
ciphertext). The plaintext secret exists in memory only during `/2fa/enable`
(to build the response) and during token verification.

**Gap:** not in `environment-variables.md`. Should be folded into the
secret-provider abstraction (`SECRET_PROVIDER` / AWS Secrets Manager) when
that lands, and this doc reconciled.

---

## 4. `BIND_ADDR` — added env var, not in the authoritative env doc

The service has to bind a socket; `environment-variables.md` names no
host/port var. `openapi.yaml`'s `servers` block implies `:8080` for local
dev.

**Decision:** add `BIND_ADDR`, default `0.0.0.0:8080`.

**Gap:** not in the authoritative env doc; reconcile there.

---

## 5. `/2fa/login` is unauthenticated; `session_token` is a minted HS256 JWT

`/2fa/login` is the **only** Phase 1 path with **no `security` block** in
`openapi.yaml` — correct, since it is the second factor of a two-step login
and no session exists yet. Its body carries `user_id` + `token`.

**Decision:**
- `/2fa/login` requires no `Authorization` header. It looks up the 2FA
  record by the body's `user_id` and verifies the TOTP token.
- On success it returns `LoginResponse.session_token`: a short-lived HS256
  JWT signed with `JWT_SECRET`, claims `{ sub: <user_id>, iat, exp }`.
- TTL is controlled by `SESSION_TOKEN_TTL_SECS` (see #11), default 900s.

**Gap:** the real session-issuance authority is Supabase / Kora App, not
this service. Minting our own JWT here is a Phase 1 stand-in and should be
replaced by a delegated call / redirect to the real auth service.

---

## 6. Authorization rule: self-only access on every Phase 1 endpoint

There is no user or role table in Phase 1, so the JWT `sub` claim is the
only available authorization signal. The rule is **uniform across all Phase
1 endpoints, reads and writes alike** — no read/write distinction:

> `jwt.sub` MUST equal the `user_id` of the resource being accessed.
> Mismatch → **403** with the standard error envelope.

Applied as:

| Endpoint | Enforcement |
|---|---|
| `POST /2fa/enable` | `jwt.sub == body.user_id` |
| `POST /2fa/disable` | `jwt.sub == body.user_id` |
| `POST /2fa/verify` | `jwt.sub == body.user_id` |
| `POST /2fa/recover` | `jwt.sub == body.user_id` |
| `GET /2fa/audit-log/{user_id}` | `jwt.sub == path user_id` (403 on mismatch, no exceptions) |
| `GET /2fa/recovery-log` | no `user_id` param, so the **query itself is scoped**: `WHERE user_id = jwt.sub`. A caller only ever sees their own backup-code redemptions. |
| `POST /2fa/login` | unauthenticated (see #5) |
| `GET /health` | unauthenticated |

**Rationale:** the earlier plan let any valid JWT read any user's audit log
(IPs, user agents, security-event timestamps) and `/2fa/recovery-log` had no
user filter at all — it would have returned every user's backup-code
redemption history to any authenticated caller. That is an access-control
gap, not a style choice, so it is closed here.

**Deferred:** broader-than-self access — an admin override role, or the
`X-User-Id` service-to-service read path (#2) — until RBAC and the `/admin/*`
endpoints exist in a later phase.

---

## 7. `/2fa/recovery-log` is a filtered view of `backup_codes`, not its own table

`RecoveryLogEntry` is `{ user_id, used_at, code_index }`. Every one of those
fields already lives on a consumed `backup_codes` row (`user_id`,
`consumed_at`, `code_index`).

**Decision:** serve `/2fa/recovery-log` directly from
`SELECT user_id, consumed_at AS used_at, code_index FROM backup_codes
WHERE consumed = true AND user_id = $sub ORDER BY consumed_at DESC` with
`LIMIT/OFFSET` pagination. No dedicated `recovery_log` table. The `audit_log`
table still records a `recovered` event per recovery for the audit-log
endpoint.

---

## 8. Rate limiting: only the documented lockout, in Postgres (no Redis)

`openapi.yaml` prose: "Verification and login endpoints are rate-limited per
`user_id`. After 5 consecutive failures the account is locked for 15
minutes." `environment-variables.md` says the service "starts without Redis
if unset."

**Decision:** implement **only** the 5-consecutive-failure / 15-minute
lockout, using two columns on `two_factor_records`
(`failed_attempts INT`, `locked_until TIMESTAMPTZ`). No Redis dependency is
added in Phase 1.

- A failed TOTP check on `/2fa/verify` or `/2fa/login` increments
  `failed_attempts`. The increment happens **in a single SQL `UPDATE`**
  (`failed_attempts = failed_attempts + 1`), never a read-then-write in
  application code: parallel wrong guesses against the same `user_id` must
  not be able to lose an increment and race around the lock.
- When `failed_attempts` reaches 5, `locked_until = now() + 15 min`. This is
  decided in the same statement as the increment, so the attempt that trips
  the lock is the one that reports **423**.
- While `now() < locked_until`, `/2fa/verify` and `/2fa/login` short-circuit
  with **423**.
- Any successful verification resets `failed_attempts = 0`,
  `locked_until = NULL`.
- A successful `/2fa/recover` (backup code) also clears the lockout, since it
  disables 2FA entirely.

The atomic increment is pinned by
`tests/integration.rs::concurrent_wrong_totp_never_loses_a_failure`, which
fires `MAX_FAILED_ATTEMPTS` wrong-TOTP requests at one `user_id` in parallel
and asserts every one is counted.

**Deferred:** a general per-`user_id` request-rate limiter (the
`REDIS_URL`-backed limiter referenced in the env doc). Not in Phase 1.

---

## 9. `/2fa/enable` when a record already exists

`openapi.yaml`: `409` means "2FA already enabled for this user".

**Decision:**
- `enabled = true` → **409** `TWO_FACTOR_ALREADY_ENABLED`.
- A row exists but is still **pending** (`enabled = false`, never confirmed
  via `/2fa/verify`) → treat `/2fa/enable` as a **setup restart**: generate a
  fresh secret + fresh backup codes, overwrite the pending row, return
  `200`. This lets a user who lost the QR code before confirming start over.
- No row → create a pending row, return `200`.

---

## 10. State machine: `pending` vs `enabled`

`two_factor_records` carries `enabled BOOL` and `pending BOOL`.

- `/2fa/enable` → `enabled = false`, `pending = true`.
- First successful `/2fa/verify` → `enabled = true`, `pending = false`
  (this is the activation; audit event `enabled`).
- Subsequent `/2fa/verify` while `enabled = true` → plain check, no state
  change (audit event `verified`).
- `/2fa/verify` while the row is still `pending` but the token is wrong →
  `401`, and it counts toward the lockout like any other failure.
- `/2fa/disable` and `/2fa/recover` → `enabled = false`, `pending = false`,
  secret + backup codes cleared.

---

## 11. `SESSION_TOKEN_TTL_SECS` — added env var (ops flexibility)

The `/2fa/login` session-token lifetime (#5) is configurable via
`SESSION_TOKEN_TTL_SECS`, default **900** (15 minutes), rather than a
hardcoded constant.

**Gap:** like #1/#3/#4, not in `environment-variables.md`; reconcile there
when real auth infra is decided.

---

## 12. Fixed TOTP parameters for Phase 1 (SHA1 / 6 digits / 30s step)

`kora-app`'s `CHANGELOG.md` (not one of the two fetched contract files)
notes that the backend-2fa service was eventually meant to support a
**configurable** TOTP algorithm / digit count / period ("cryptographic
agility").

**Decision:** Phase 1 hard-codes RFC 6238 defaults — **HMAC-SHA1, 6 digits,
30-second step, ±1 step (30s) verification skew**. These are what Google
Authenticator / Authy / 1Password expect with a bare `otpauth://` URI, so
interop is maximised.

**Intentional simplification, recorded so it is not forgotten:** per-tenant
(or per-user) TOTP algorithm/digits/period configuration most likely belongs
with **`/tenant/provision` (Phase 2)** — `ProvisionTenantRequest` already
carries a per-tenant `issuer`. When that phase lands, the TOTP builder here
should take its parameters from tenant config instead of constants.

---

## 13. Misc field / behaviour mappings

- **`AuditLogEntry` has no `user_id` field** in the schema — the API
  response omits it (the caller already knows the user from the path). The
  DB column exists for filtering only.
- **`AuditLogPage` has no `page_size` field** (only `entries`, `total`,
  `page`) — matched exactly. `RecoveryLogPage` does have `page_size` and it
  is populated.
- **`created_at` DB column serializes as `timestamp`** in `AuditLogEntry` to
  match the schema field name.
- **`total`** in both page responses = count of all matching rows, ignoring
  `page` / `page_size`.
- **`ip_address` / `user_agent`** are captured from the request's
  `X-Forwarded-For` (first hop) / `User-Agent` headers when present, else
  `NULL`. They are recorded on audit rows only.
- **`404`** on `/2fa/disable`, `/2fa/recover`, `/2fa/audit-log/{user_id}` =
  no `two_factor_records` row for that `user_id` (all three list `404` in
  their `openapi.yaml` responses).
- **`/2fa/verify` and `/2fa/login` never return `404`** — the spec assigns
  them only `400/401/423`. A missing record, or a record with no active
  secret, is therefore reported as **`401`** (`TWO_FACTOR_NOT_ENABLED` /
  `INVALID_TOKEN`), matching `/2fa/login`'s documented 401 text "Invalid
  TOTP token or 2FA not enabled".
- **`/2fa/verify` `400`** = token not exactly 6 ASCII digits.
  **`401`** = well-formed token that does not match. **`423`** once the
  lockout has tripped (including on the failing attempt that trips it).
- **`/2fa/disable` and `/2fa/recover` do not drive or read the lockout** —
  neither lists `423` in the spec. A wrong TOTP on `/2fa/disable` or a wrong
  backup code on `/2fa/recover` is a plain `401` and leaves
  `failed_attempts` untouched. Only `/2fa/verify` and `/2fa/login` (the two
  endpoints the spec marks with `423`) increment the counter and enforce the
  lock.
- **Backup codes**: 10 codes generated per enable, format `XXXX-XXXX`
  (uppercase Crockford-ish base32, dash-separated), hashed with Argon2id,
  returned in plaintext exactly once from `/2fa/enable`. `code_index` is the
  0-based position in that batch.
- **`GIT_SHA`** falls back to `"unknown"` when git is unavailable at build
  time, matching the env doc.
- **`RUST_LOG`** unset → default filter `info,kora_2fa=info`.

---

## 14. Out of scope for Phase 1 (built as nothing, not as stubs)

Per the Phase 1 brief, these `openapi.yaml` paths get **no** route, table,
or stub: `/admin/quota`, `/admin/quota/unlimited`, `/admin/canary`,
`/admin/flagged`, `/admin/flagged/{user_id}`,
`/admin/users/{user_id}/2fa-summary`, `/tenant/provision`,
`/ws/leaderboard`. Their schemas remain in the vendored `docs/openapi.yaml`
(unmodified) but nothing references them.

Correspondingly unimplemented env vars: `SECRET_PROVIDER`,
`AWS_SECRETS_JSON`, `LEADERBOARD_DECAY_LAMBDA`, `WEBHOOK_LOG_MAX_ENTRIES`,
`REDIS_URL`.

---

## 15. CI shape and the `.sqlx` offline cache

The Phase 1 brief says to mirror `kora-app`'s own CI, but the brief also
forbids looking at anything in that repo beyond the two doc files. So
`.github/workflows/ci.yml` is a conventional Rust pipeline rather than a
literal copy: `cargo fmt --check`, `cargo clippy -- -D warnings`,
`cargo test` against a Postgres 16 service container, and `cargo audit`.
Reconcile job names / runner versions with `kora-app`'s workflows when that
repo is in reach.

`cargo audit` flags **RUSTSEC-2023-0071** (`rsa` 0.9 "Marvin Attack" timing
sidechannel, no fixed release). `rsa` is a transitive dependency of
`sqlx-macros-core -> sqlx-mysql`, which the sqlx query macros pull in
unconditionally even though this service is built Postgres-only and never
opens a MySQL connection. The vulnerable code path is unreachable at
runtime, so the advisory is ignored in `.cargo/audit.toml` with that
rationale. Remove the ignore once sqlx drops the transitive dep or `rsa`
ships a constant-time fix.

Compile-time-checked queries (`sqlx::query!`) need either a live database or
a committed query cache. The cache — `.sqlx/` at the repo root, generated by
`cargo sqlx prepare` — is checked in, and CI sets `SQLX_OFFLINE=true` so the
`fmt`/`clippy`/build steps need no database. Regenerate it (and commit the
diff) whenever a query or the schema changes:

```
docker compose up -d
DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa \
  cargo sqlx migrate run
DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa \
  cargo sqlx prepare --workspace
```

## 16. `AuthUser` on `/2fa/login`

`/2fa/login` takes no `Authorization` header (#5). The other six
authenticated endpoints extract `AuthUser` (HS256 verify, `exp` enforced,
zero clock leeway) and then call `require_self` against the body or path
`user_id`. A token whose `sub` differs from the target `user_id` is a 403,
never a silent success — there is no cross-user or admin path in Phase 1
(#6).

---

## 17. Container image and the compose stack

The service ships a multi-stage [`Dockerfile`](Dockerfile), and
`docker-compose.yml` runs it alongside Postgres.

**Decisions:**
- **Build image** — `rust:${RUST_VERSION}-slim-bookworm`, `RUST_VERSION`
  defaulting to `1.98` (a concrete pin of `rust-toolchain.toml`'s `stable`;
  overridable as a compose build arg). `slim` needs `build-essential` added —
  `ring` (via sqlx' rustls TLS) wants a C compiler. `rust-toolchain.toml` is
  copied in and `rustup show` run early so the `stable` channel resolves once,
  in a cached layer, rather than mid-build.
- **Dependency cache** — `cargo-chef` (pinned) so a source-only edit re-uses
  the cooked-dependency layer, plus BuildKit cache mounts on
  `/usr/local/cargo/{registry,git}` so crate downloads survive across builds.
- **Offline build** — `SQLX_OFFLINE=true` + the checked-in `.sqlx/` cache;
  the image builds with no database (#15). `migrations/` is embedded by
  `sqlx::migrate!` at compile time, so the runtime image omits it.
- **Runtime image** — `gcr.io/distroless/cc-debian12:nonroot`, pinned by
  digest: glibc + `ca-certificates`, no shell or package manager, runs as uid
  65532. Just the stripped binary is copied in; the result is ~47 MB.
- **No `HEALTHCHECK`** in the image (distroless has no tool to run one);
  probe `GET /health` from the orchestrator. Compose still gates the service
  on `postgres`'s own healthcheck via `depends_on: condition:
  service_healthy`.
- **`GIT_SHA`** is `"unknown"` in the image — `.git/` is excluded from the
  build context and `build.rs` degrades gracefully (see
  `docs/environment-variables.md`).
- **Env** — compose feeds the service `.env.example` and overrides
  `DATABASE_URL`. The dev `JWT_SECRET` / `TOTP_ENCRYPTION_KEY` in that file
  are for local use only.
- **DB connection path** — the service reaches Postgres via
  `host.docker.internal:5432` (the host's published port), not the compose
  bridge. Service-name DNS resolves, but some nested/sandboxed Docker setups
  (Codespaces, some CI) filter container-to-container traffic on user-defined
  bridges; the host path works everywhere and Postgres already publishes
  5432. `extra_hosts: host.docker.internal:host-gateway` makes the name
  resolve on plain Linux Docker too.

---

## 18. Router hardening layers

Neither `openapi.yaml` nor `environment-variables.md` says anything about
panic handling, request-size caps, or per-request timeouts. Phase 1 adds a
small, non-configurable hardening stack in `routes::hardening_layers`,
applied by `routes::router` to every endpoint.

**Decisions:**
- **Panic → the shared error envelope.** `tower_http::catch_panic::
  CatchPanicLayer` is the outermost layer. A handler panic is caught and
  rendered as the same `{ "error": "INTERNAL", "message": "An internal error
  occurred" }` / `500` body `AppError::internal` produces (the panic payload
  is logged, never returned), instead of the connection being dropped
  mid-response.
- **Request-body cap — 64 KiB** (`REQUEST_BODY_LIMIT_BYTES`), via
  `tower_http::limit::RequestBodyLimitLayer`. Every Phase 1 body is a small
  JSON object; an over-cap request is refused with `413` (up front when a
  `Content-Length` says so, otherwise once the byte count is exceeded on
  read) before a handler buffers it.
- **Request timeout — 10 s** (`REQUEST_TIMEOUT`), via
  `tower_http::timeout::TimeoutLayer` (with `StatusCode::REQUEST_TIMEOUT`).
  A handler that outruns the budget — e.g. a wedged DB call — has its
  response replaced with a `408` so a slow dependency cannot pin a
  connection open indefinitely.

**Gap:** the two limits are hardcoded constants, not env vars. If Phase 2
needs them tunable, add them to a future revision of
`environment-variables.md` alongside `#1`/`#3`/`#4`/`#11`. `axum`'s built-in
`DefaultBodyLimit` (2 MiB) still applies underneath the tighter cap.

Covered by `tests/hardening.rs` (panic envelope, body cap up-front and
mid-read, timeout `408`, pass-through of ordinary responses) and the
`panic_message` unit tests in `routes`.
