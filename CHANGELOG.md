# Changelog

All notable changes to the kora-backend project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CONTRIBUTING.md` — dev setup, PR process, the six CI jobs, and the `.sqlx`
  offline-cache regeneration step
- `SECURITY.md` — vulnerability reporting process and the service's security
  properties
- `CHANGELOG.md` — this file
- `LICENSE` — MIT, matching the `license = "MIT"` already declared in
  `[workspace.package]`
- `.github/PULL_REQUEST_TEMPLATE.md`

## [0.1.0] - Unreleased

Phase 1 of the `kora-2fa` service. Not yet tagged; the entries below describe
what is currently on `main`.

### Added

#### `kora-2fa` service — Phase 1 slice of `docs/openapi.yaml`

- `POST /2fa/enable` — generate a TOTP secret and 10 backup codes, store a
  pending setup
- `POST /2fa/verify` — validate a 6-digit RFC 6238 TOTP (HMAC-SHA1, 6 digits,
  30-second step, ±1 step skew); the first success activates 2FA
- `POST /2fa/disable` — clear the secret after confirming a current TOTP
- `POST /2fa/login` — second factor of a two-step login; returns a short-lived
  HS256 session token (`SESSION_TOKEN_TTL_SECS`, default 900s)
- `POST /2fa/recover` — consume a backup code and disable 2FA for re-enrolment
- `GET /2fa/recovery-log` — the caller's own backup-code redemptions, paginated
- `GET /2fa/audit-log/{user_id}` — 2FA audit events for a user, paginated
- `GET /health` — liveness probe, unauthenticated; reports `503` when the
  database is unreachable
- Shared error envelope `{ "error": <code>, "message": <detail> }` for every
  error response; malformed bodies, query strings, and path params are
  converted to the `400` form of that envelope

#### Authentication & authorization

- Bearer JWT middleware: HS256 with the accepted algorithm fixed at decode
  time, `exp` required and enforced at zero clock-skew leeway, `sub` required
- Self-only access control — `jwt.sub` must equal the target `user_id`, else
  `403`; `/2fa/recovery-log` is query-scoped to the caller
- `/2fa/login` mints its session token with the same `JWT_SECRET`

#### Storage & crypto

- TOTP secrets encrypted at rest with AES-256-GCM (`TOTP_ENCRYPTION_KEY`),
  random 96-bit nonce per row stored with the ciphertext
- Backup codes stored only as Argon2id hashes; `XXXX-XXXX` format, returned in
  plaintext exactly once from `/2fa/enable`
- Postgres-backed `pending` → `enabled` state machine; sqlx migrations;
  compile-time-checked queries with a committed `.sqlx/` offline cache
  (CI builds with `SQLX_OFFLINE=true`)

#### Router hardening (`ASSUMPTIONS.md` §18)

- Panic isolation — a handler panic is caught and rendered as the standard
  `INTERNAL` / `500` envelope instead of dropping the connection
- Request-body cap of 64 KiB (`413` when exceeded)
- Request timeout of 10 s (`408` when a handler outruns the budget)
- Covered by `tests/hardening.rs`

#### Boot behavior

- Database-connect retry — `main` retries a not-yet-ready Postgres up to 5
  times with exponential backoff (1s → 2s → 4s → 8s) before exiting non-zero
  (`ASSUMPTIONS.md` §20)
- Loud `WARN` at startup when `JWT_SECRET` or `TOTP_ENCRYPTION_KEY` is left at
  its `.env.example` placeholder value; the service still starts
  (`ASSUMPTIONS.md` §19)

#### Configuration

- Env loader for the Phase 1 subset of `docs/environment-variables.md` plus
  four added vars — `JWT_SECRET`, `TOTP_ENCRYPTION_KEY`, `BIND_ADDR`,
  `SESSION_TOKEN_TTL_SECS` — each recorded in `ASSUMPTIONS.md` (§1, §3, §4,
  §11); `Config`'s `Debug` redacts the two secrets and DB credentials
- `.env.example` listing every var, each added var cross-referenced to
  `ASSUMPTIONS.md`

#### CI/CD & tooling

- `.github/workflows/ci.yml` with six jobs: `rustfmt`, `clippy --workspace
  --all-targets -D warnings`, `test` against a Postgres 16 service container,
  `cargo-deny check`, `coverage` (report-only), and `image scan` (report-only)
- `deny.toml` — `cargo-deny` policy covering advisories, licenses, bans
  (one version per crate, no `*` deps), and sources (crates.io only); every
  current finding enumerated with a rationale (`ASSUMPTIONS.md` §21)
- `coverage` job running `cargo llvm-cov --workspace --all-targets`,
  publishing `lcov.info` + `coverage.json`; no threshold gate yet
  (`ASSUMPTIONS.md` §22)
- `image scan` job building the release image and running Trivy
  (`HIGH,CRITICAL`, `--ignore-unfixed`), SARIF to the Security tab; report-only
  (`ASSUMPTIONS.md` §23)
- `.trivyignore` (empty, documented) and least-privilege workflow
  `permissions`
- Multi-stage `Dockerfile` — cargo-chef dependency cache → `--release` build →
  `gcr.io/distroless/cc-debian12:nonroot` runtime (digest-pinned, non-root,
  ~47 MB, stripped binary only)
- `docker-compose.yml` — the service alongside Postgres 16, gated on the
  database's healthcheck
- `.dockerignore` keeping `target/`, `.git/`, secrets, and local
  coverage/scan output out of the build context
- `rust-toolchain.toml` pinned to the `stable` channel with `rustfmt` and
  `clippy`

#### Documentation

- `docs/openapi.yaml` and `docs/environment-variables.md` vendored verbatim
  from `github.com/iam-mercy/kora-app` as the authoritative contract
- `ASSUMPTIONS.md` — every Phase 1 judgment call and documented gap (§1–§23)
- `README.md` — endpoint table, security properties, layout, run/test/CI paths

### Changed

- Supply-chain policy: the `cargo audit` CI job and its bare
  `.cargo/audit.toml` suppression list were replaced by `cargo-deny` +
  `deny.toml`. `RUSTSEC-2023-0071` is no longer ignored anywhere — the
  `rsa` crate is an inactive transitive of `sqlx-mysql` and does not appear in
  this Postgres-only build's dependency graph (`ASSUMPTIONS.md` §21).

### Security

- **Brute-force lockout** — 5 consecutive failed TOTP checks on `/2fa/verify`
  or `/2fa/login` lock the account for 15 minutes. The failure counter is
  incremented in a single atomic SQL `UPDATE`, so concurrent wrong guesses
  against one `user_id` cannot race past the threshold. Regression test:
  `concurrent_wrong_totp_never_loses_a_failure` (`ASSUMPTIONS.md` §8).
- **Audit-log access closed to self only** — `/2fa/audit-log/{user_id}`
  returns `403` on any cross-user access, and `/2fa/recovery-log` filters by
  `jwt.sub` in the query rather than relying on a caller-supplied id
  (`ASSUMPTIONS.md` §6).
- **Placeholder-secret guard** — booting with the `.env.example` `JWT_SECRET`
  or `TOTP_ENCRYPTION_KEY` logs a loud `WARN` naming each offending variable
  (`ASSUMPTIONS.md` §19).
- **Supply-chain checks in CI** — `cargo-deny` enforces advisories, licenses,
  bans, and sources on every push and PR (`ASSUMPTIONS.md` §21).
- **Container image scanning** — Trivy scans the release image for fixable
  HIGH/CRITICAL CVEs in CI; report-only for now (`ASSUMPTIONS.md` §23).
- **Hardened runtime image** — distroless, non-root, base pinned by digest
  (`ASSUMPTIONS.md` §17).

[Unreleased]: https://github.com/iam-mercy/kora-backend/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/iam-mercy/kora-backend/releases/tag/v0.1.0
