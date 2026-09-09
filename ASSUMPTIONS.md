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
`cargo test` against a Postgres 16 service container, `cargo-deny`, a
`cargo-llvm-cov` coverage run, and a container image build + vulnerability
scan. Reconcile job names / runner versions with `kora-app`'s workflows when
that repo is in reach.

> **Superseded in part by §21.** The advisory handling described in the next
> paragraph moved from `cargo audit` + `.cargo/audit.toml` to `cargo-deny` +
> `deny.toml`. Under `cargo-deny`'s graph-based check **RUSTSEC-2023-0071 is
> no longer flagged and no longer ignored anywhere** — see §21 for why and
> for the coverage / container-scan jobs.

`cargo audit` flagged **RUSTSEC-2023-0071** (`rsa` 0.9 "Marvin Attack"
timing sidechannel, no fixed release). `rsa` is a transitive dependency of
`sqlx-macros-core -> sqlx-mysql`, which the sqlx query macros pull in
unconditionally even though this service is built Postgres-only and never
opens a MySQL connection. The vulnerable code path is unreachable at
runtime — and `rsa` never actually activates in the resolved graph, which is
why `cargo-deny` does not report it — so `cargo audit` had the advisory
ignored in `.cargo/audit.toml` with that rationale.

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

---

## 19. Boot-time guard against the `.env.example` placeholder secrets

`.env.example` ships a dev `JWT_SECRET` (`dev-only-insecure-change-me`) and a
dev `TOTP_ENCRYPTION_KEY` (base64
`MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=`), and `docker-compose.yml`
feeds that file to the service verbatim (#17). Nothing stops a real
deployment from doing the same and silently shipping known secrets.

**Decision:** `Config::from_env` compares the loaded `JWT_SECRET` /
`TOTP_ENCRYPTION_KEY` against those exact placeholder values
(`config::EXAMPLE_JWT_SECRET`, `config::EXAMPLE_TOTP_ENCRYPTION_KEY`) and
emits a loud `WARN` per hit (`Config::example_secrets_in_use` returns the
list). The service still **starts** — refusing would break the local compose
stack and CI, both of which use the example file on purpose — so the check
is a warning, not a hard stop. Promote it to a refusal once real auth infra
(#1) lands and `.env.example` no longer carries usable secrets.

Covered by the `config` unit tests (`placeholder_jwt_secret_is_flagged`,
`placeholder_totp_key_is_flagged`, `both_placeholders_are_flagged_together`,
`real_secrets_are_not_flagged`, and a drift guard tying the decoded key
constant back to the `.env.example` base64 literal).

---

## 20. Boot-time database-connect retry

`main` used to call `db::connect` once and propagate the error, so the
process exited if Postgres was not yet accepting connections at startup.
Compose gates the service on `postgres`'s healthcheck (#17), but that race
is still real in other orchestrated environments (a rescheduled pod, a
CI runner bringing services up in parallel).

**Decision:** `main` connects via `db::connect_with_retry`, which retries up
to `db::CONNECT_MAX_ATTEMPTS` (5) times with exponential backoff from
`db::CONNECT_BASE_BACKOFF` (1s → 2s → 4s → 8s; `db::backoff_delay`). Only
after the final attempt fails does it return the error, and `main` then
exits non-zero as before. `db::connect_with_backoff` takes the budget as
parameters for testing. Migrations and the rest of boot are unchanged.

Covered by the `db` unit tests (`backoff_delay` schedule, default budget,
and `connect_with_backoff_gives_up_after_the_attempt_budget` against an
unreachable port).

---

## 21. Supply-chain policy: `cargo-deny` replaces `cargo audit`

§15 described CI as `fmt` / `clippy` / `test` / `cargo audit`, with the one
RUSTSEC advisory it flagged suppressed in `.cargo/audit.toml`. That file was
a bare `ignore = ["RUSTSEC-2023-0071"]` — a suppression list with no policy
around it, and nothing checking licenses, dependency sources, or duplicate
versions at all.

**Decision:** replace the `cargo audit` job with **`cargo-deny`** (CI job
`cargo-deny`, config `deny.toml` at the repo root), running all four checks:

- **advisories** — same RUSTSEC database `cargo audit` used.
- **licenses** — every crate must resolve to an allow-listed permissive /
  public-domain SPDX id. One scoped exception: `webpki-roots` carries
  Mozilla's CA bundle under `CDLA-Permissive-2.0`.
- **bans** — one version per crate (`multiple-versions = "deny"`) and no
  `version = "*"` deps. The 15 crates duplicated in today's graph (the
  `windows-sys` import-lib stack, `syn` 2.x/3.x, the `rand` 0.8/0.9 family,
  `getrandom`, `hashbrown`) are each enumerated in `skip` with the reason
  they can't be collapsed yet.
- **sources** — crates.io only; no git or alternate-registry deps.

`.cargo/audit.toml` is deleted. **`RUSTSEC-2023-0071` is not ignored
anywhere any more** and CI is still green: `cargo audit` flagged it because
`rsa` 0.9.x sits in `Cargo.lock` as a transitive of `sqlx-mysql`, but that
crate never activates in this Postgres-only build (`cargo tree -i rsa`
returns nothing), so `cargo-deny`'s graph-based advisory check does not see
it. `deny.toml`'s `[advisories]` block records this, with instructions to
re-add a *scoped* ignore there (not a blanket one) if a future dependency
change pulls `rsa` into the real graph.

**Why the job is green on day one rather than blocking existing CI:** every
current finding — the 15 duplicate pairs and the one non-standard license —
is written into `deny.toml` as an explicit, commented exception. The policy
is "deny", the exceptions are the enumerated exhaust of what's already here,
and the value is that the *next* new duplicate, disallowed license, fresh
advisory, or git dependency fails the PR that introduces it. If a finding
does land on `main` (an advisory published against a crate we already ship),
the escape hatch is a one-line `ignore = [{ id = "...", reason = "..." }]`
in `[advisories]` with the reason recorded, same shape as every other
exception in the file — not disabling the job.

**Gap:** the job runs `EmbarkStudios/cargo-deny-action@v2`, which tracks the
latest `cargo-deny` rather than a pinned version, so a new lint or a
tightened default in that tool could turn CI red on an unrelated PR. Pin the
version in the action inputs if that churn shows up. The `skip` list is also
a standing maintenance item — each entry should be retested against upstream
and deleted as the ecosystem converges.

Reconcile job names / policy with `kora-app`'s own workflows when that repo
is in reach (same caveat as §15).

---

## 22. Coverage measurement (`cargo-llvm-cov`), report-only

kora-app's brief describes the service as well-tested and cites 100% function
coverage, but Phase 1 CI had no coverage measurement — "well-tested" was a
claim with no number behind it.

**Decision:** add a `coverage` CI job running `cargo llvm-cov` (LLVM
source-based instrumentation, via `llvm-tools-preview` +
`taiki-e/install-action`) over `--workspace --all-targets`, against the same
Postgres 16 service container the `test` job uses. It publishes:

- the line / function / region summary table to `$GITHUB_STEP_SUMMARY`,
- a one-line `Lines: x%  Functions: y%` headline, extracted from the JSON
  report with `jq`,
- `lcov.info` + `coverage.json` as the `coverage` artifact.

**Report-only, deliberately.** No `--fail-under-lines` / `--fail-under-functions`
gate yet:

- The first CI run is what establishes the real number. Setting a threshold
  before seeing it would either be guessed too low to mean anything or too
  high and immediately red.
- A line-coverage floor makes unrelated refactors that move code around fail
  CI for reasons reviewers can't act on quickly.
- `--all-targets` coverage does not include doctests (that needs a nightly
  toolchain), so the figure is a floor, not the whole picture.

**How to promote it to a gate:** once a few runs show a stable number, add
`--fail-under-lines <floor>` (a few points below the observed value, as
headroom) to the `cargo llvm-cov` invocation, and record the chosen floor
here. Function coverage can get its own `--fail-under-functions` if the
100% claim is meant to be enforced rather than just reported.

**Gap:** the job re-compiles the workspace with instrumentation rather than
reusing the `test` job's artifacts, so it roughly doubles that job's wall
time. Acceptable for a small workspace; revisit (e.g. `cargo-nextest` +
a shared instrumented build) if CI time becomes a problem.

---

## 23. Container image vulnerability scanning (Trivy), report-only

`cargo-deny` (§21) checks the *source* dependency graph. It says nothing
about the runtime image: the `gcr.io/distroless/cc-debian12` base's OS
packages (glibc, libgcc, OpenSSL, zlib, …) and anything linked into the
release binary. #17 pins the base by digest but a pinned digest still ages —
a CVE disclosed against glibc tomorrow is in the image we ship today.

**Decision:** add an `image` CI job that builds the release `Dockerfile` and
runs **Trivy** against the resulting image:

- a `HIGH,CRITICAL` findings **table** to the job log,
- a **SARIF** report uploaded as the `trivy` artifact and, where the repo
  has code scanning enabled, to the Security tab
  (`github/codeql-action/upload-sarif`, `continue-on-error` so repos without
  it don't fail),
- `--ignore-unfixed`: CVEs with no upstream fix are noise here — we can't
  patch a distroless base ourselves — so only actionable (fixable) findings
  are reported,
- suppressions, if any, live in `.trivyignore` (empty today) with a comment
  and expiry per entry.

**Report-only, deliberately** (`exit-code: 0`):

- The first run establishes the baseline. Gating before seeing it risks
  turning `main` red on the first unrelated PR.
- Image CVEs appear with **zero repo activity** — a new advisory against a
  base package flips the result between one PR and the next. A blocking scan
  on a fast-moving DB means unrelated PRs eating failures for something the
  author can't fix in that PR. Report-first, gate once the baseline is known
  to be clean and a bump cadence for the base image exists.
- `--ignore-unfixed` already means a blocking version would only fire on
  *fixable* HIGH/CRITICAL CVEs — the right eventual gate, but still worth a
  few runs of observation first.

**How to promote it to a gate:** set `exit-code: "1"` on the table scan
(keep `--ignore-unfixed` and `severity: HIGH,CRITICAL`), after confirming a
clean baseline and adding a routine that bumps the distroless base digest
(§17) on a schedule so fixable findings have a path to green.

**Gaps:**
- Adds a full release image build to CI (~minutes, mitigated by the GHA
  layer cache and cargo-chef). It does not block the Rust jobs — they run in
  parallel — but it is the long pole of a green run.
- `aquasecurity/trivy-action` is pinned to a release tag, not a commit SHA;
  the action's tags were re-cut after a 2025 supply-chain incident, so a SHA
  pin (or a vendored Trivy binary) is the stricter choice if that risk
  matters here.
- Trivy also offers config/IaC and secret scanning; only image
  vulnerability scanning is wired up.
