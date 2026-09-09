# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately:

1. **DO NOT** open a public GitHub issue.
2. Use GitHub's **"Report a vulnerability"** button under this repository's
   **Security → Advisories** tab, or email the maintainer privately
   (`[security contact needed]`).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **24 hours** — initial response acknowledging receipt
- **72 hours** — initial assessment and severity classification
- **7 days** — detailed response with a fix timeline

## Security Properties of `kora-2fa` (Phase 1)

These are the guarantees the current service is built to provide. Each is
recorded in more detail in `ASSUMPTIONS.md`.

### Authentication

- Incoming bearer tokens are verified as **HS256 only** — the accepted
  algorithm is fixed at decode time, so an attacker cannot downgrade or
  confuse the `alg`.
- The `exp` claim is required and enforced with **zero clock-skew leeway**;
  `sub` is required.
- Issuer and audience are **not** validated — Phase 1 has no auth-infra
  config for them. This is a documented limitation (`ASSUMPTIONS.md` §1); it
  should be closed when real Supabase / Kora App auth config lands.
- `/2fa/login` and `/health` are the only unauthenticated endpoints.

### Authorization

- **Self-only.** On every authenticated endpoint, `jwt.sub` must equal the
  `user_id` of the resource being acted on, or the request is `403`. There is
  no admin or cross-user path in Phase 1 (`ASSUMPTIONS.md` §6, §16).
- `/2fa/recovery-log` has no `user_id` parameter — the query itself is scoped
  with `WHERE user_id = jwt.sub`, so a caller can only ever see their own
  backup-code redemptions.

### Secrets at rest

- **TOTP secrets** are encrypted with **AES-256-GCM** under
  `TOTP_ENCRYPTION_KEY` (32 bytes, base64). A fresh random 96-bit nonce is
  generated per row and stored alongside the ciphertext. The plaintext secret
  exists in memory only transiently, while building the `/2fa/enable` response
  or verifying a token (`ASSUMPTIONS.md` §3).
- **Backup codes** are stored only as **Argon2id** hashes, never in
  plaintext, and are returned in cleartext exactly once from `/2fa/enable`
  (`ASSUMPTIONS.md` §13).
- `Config`'s `Debug` implementation redacts `jwt_secret` and
  `totp_encryption_key`, and strips any `user:password@` component from
  `DATABASE_URL` before logging (`src/config.rs`).

### Brute-force lockout

- After **5 consecutive failed** TOTP checks on `/2fa/verify` or `/2fa/login`,
  the account is locked for **15 minutes** (`423`).
- The failure counter is incremented in a **single atomic SQL `UPDATE`**
  (`failed_attempts = failed_attempts + 1`), never a read-then-write in
  application code, so parallel wrong guesses against one `user_id` cannot
  race past the threshold. Pinned by the regression test
  `concurrent_wrong_totp_never_loses_a_failure` (`ASSUMPTIONS.md` §8).
- `/2fa/disable` and `/2fa/recover` do not drive or read the lockout, matching
  the spec (neither lists `423`).

### Runtime hardening

`routes::hardening_layers` wraps every endpoint (`ASSUMPTIONS.md` §18):

- **Panic isolation** — a handler panic is caught
  (`tower_http::catch_panic`) and rendered as the standard
  `{ "error": "INTERNAL", "message": "An internal error occurred" }` / `500`
  body; the panic payload is logged, never returned, and the connection is
  not dropped mid-response.
- **Request-body cap — 64 KiB** (`tower_http::limit`). Over-cap requests are
  refused with `413` before a handler buffers them.
- **Request timeout — 10 s** (`tower_http::timeout`). A handler that outruns
  the budget has its response replaced with `408`, so a wedged dependency
  cannot pin a connection open indefinitely.

Both limits are hardcoded constants in Phase 1, not env vars. Covered by
`tests/hardening.rs`.

### Input handling

- Request bodies, query strings, and path parameters are parsed with typed
  extractors; malformed input is converted to the shared `400`
  `{ "error", "message" }` envelope rather than a framework-default response
  (`src/error.rs`).

### Container / supply chain

- The runtime image is `gcr.io/distroless/cc-debian12:nonroot`, **pinned by
  digest**: no shell, no package manager, runs as uid 65532. Only the
  stripped release binary is copied in (`ASSUMPTIONS.md` §17).
- **`cargo-deny`** runs in CI on every push and PR (`deny.toml` at the repo
  root), covering four checks (`ASSUMPTIONS.md` §21):
  - **advisories** — the same RUSTSEC database `cargo audit` used;
  - **licenses** — every crate must resolve to an allow-listed permissive /
    public-domain SPDX id (one scoped exception: `webpki-roots`, which carries
    Mozilla's CA bundle under `CDLA-Permissive-2.0`);
  - **bans** — one version per crate and no `version = "*"` deps; the current
    duplicate pairs are enumerated in `deny.toml`'s `skip` list with reasons;
    a *new* duplicate fails the PR that introduces it;
  - **sources** — crates.io only; no git or alternate-registry deps.
  `.cargo/audit.toml` (which previously carried a bare
  `ignore = ["RUSTSEC-2023-0071"]`) has been **removed**. RUSTSEC-2023-0071
  (`rsa` "Marvin Attack") is no longer suppressed anywhere: `rsa` sits in
  `Cargo.lock` only as an inactive transitive of `sqlx-mysql`
  (`cargo tree -i rsa` is empty in this Postgres-only build), so
  `cargo-deny`'s graph-based advisory check does not flag it. If a future
  dependency change pulls `rsa` into the real graph, re-add a **scoped**
  `ignore` in `deny.toml`'s `[advisories]` block with a written reason — not a
  blanket suppression.
- **Trivy image scan** — a CI job builds the release image and scans it for
  `HIGH,CRITICAL` OS/library CVEs (`--ignore-unfixed`), publishing a SARIF
  report to the run's artifacts and, where enabled, the Security tab. It is
  **report-only** today (`exit-code: 0`) — see `ASSUMPTIONS.md` §23 for the
  path to making it a gate. Suppressions, if any, live in `.trivyignore`
  (empty today) with a comment and expiry per entry.

## Operator Responsibilities

- `.env.example` — and therefore the `docker compose` stack — ships
  **dev-only** placeholder values for `JWT_SECRET` and `TOTP_ENCRYPTION_KEY`.
  Generate real secrets (`openssl rand -base64 32` for the encryption key) and
  override `JWT_SECRET`, `TOTP_ENCRYPTION_KEY`, and `DATABASE_URL` before
  running the service anywhere real. `Config::from_env` compares the loaded
  values against the exact placeholders and emits a loud `WARN` per hit
  (`Config::example_secrets_in_use`); it does **not** refuse to start, because
  the local compose stack and CI use the example file on purpose
  (`ASSUMPTIONS.md` §19). Treat that warning in a real deployment's logs as a
  misconfiguration to fix immediately.
- Terminate TLS at your proxy or orchestrator. The service speaks plain HTTP
  on `BIND_ADDR` and expects to sit behind one.
- Probe `GET /health` from the orchestrator — the distroless image ships no
  `HEALTHCHECK` tool of its own.

## Security Best Practices for Contributors

When contributing:

- Validate inputs at the boundary; prefer typed extractors over hand parsing.
- Preserve the self-only authorization checks — do not add a code path that
  lets one `user_id`'s token act on another's resource.
- Never log or return secret material (TOTP secrets, raw backup codes, JWT
  secret, DB credentials).
- Add tests for edge cases and error conditions, not just the happy path.
- Keep `cargo-deny` clean, or add a scoped, commented exception to `deny.toml`
  with a matching `ASSUMPTIONS.md` note.
