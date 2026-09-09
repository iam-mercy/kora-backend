# kora-backend

Backend services for **Kora App** — a blockchain-based pet registry and
veterinary-records platform. This repo is decoupled from the Stellar/Celo
smart contracts; it is a plain Postgres-backed set of services.

## Phase 1 — `kora-2fa`

A two-factor-authentication / auth service implementing this slice of
[`docs/openapi.yaml`](docs/openapi.yaml):

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/2fa/enable` | Generate a TOTP secret + backup codes; store a pending setup |
| `POST` | `/2fa/verify` | Validate a 6-digit TOTP; first success activates 2FA |
| `POST` | `/2fa/disable` | Clear the secret after confirming a current TOTP |
| `POST` | `/2fa/login` | Second factor of a two-step login; returns a session token |
| `POST` | `/2fa/recover` | Consume a backup code and disable 2FA for re-enrolment |
| `GET`  | `/2fa/recovery-log` | This caller's backup-code redemptions, paginated |
| `GET`  | `/2fa/audit-log/{user_id}` | 2FA audit events for a user, paginated |
| `GET`  | `/health` | Liveness check, no auth |

`/admin/*`, `/tenant/provision`, and `/ws/leaderboard` from the spec are
**out of scope for Phase 1** and are intentionally not implemented — not
even as stubs.

Every error response is the shared envelope
`{ "error": "<code>", "message": "<detail>" }`.

### Security properties

- **Bearer JWT (HS256) on every endpoint except `/2fa/login` and `/health`.**
  Self-only: the token's `sub` must equal the `user_id` being acted on, or
  the request is `403`.
- **TOTP secrets are encrypted at rest** (AES-256-GCM under
  `TOTP_ENCRYPTION_KEY`); **backup codes are stored Argon2id-hashed**, never
  in plaintext, and returned once from `/2fa/enable`.
- **Lockout**: 5 consecutive failed TOTP checks on `/2fa/verify` or
  `/2fa/login` lock the account for 15 minutes. Implemented with Postgres
  columns — **no Redis** in Phase 1. The counter is incremented with a single
  atomic `UPDATE`, so parallel wrong guesses at one `user_id` can't race
  around the threshold.

The service verifies JWTs with a `JWT_SECRET` that is **not** in the
authoritative env-var doc, along with three other added vars. Every such gap
and judgment call is logged in [`ASSUMPTIONS.md`](ASSUMPTIONS.md) — read it
before extending the service.

## Layout

```
Cargo.toml                 workspace root (one member today, room for more)
crates/kora-2fa/           the service
  src/
    main.rs                thin binary: config -> pool -> migrate -> serve
    lib.rs                 library crate (everything testable)
    config.rs              env-var loading (Phase 1 subset + 4 added vars)
    error.rs               the {error, message} envelope
    crypto.rs              AES-256-GCM secret sealing, Argon2id backup codes
    totp.rs                RFC 6238 wrapper (SHA1 / 6 / 30s, skew 1)
    jwt.rs                 HS256 verify + session-token minting
    db/                    pool, migrator, request/response DTOs
    middleware/auth.rs     the AuthUser bearer extractor
    routes/                health, twofa, recovery
  tests/integration.rs     end-to-end tests against real Postgres
migrations/                sqlx migrations
docs/                      vendored openapi.yaml + environment-variables.md
Dockerfile                 multi-stage build -> distroless runtime image
docker-compose.yml         Postgres + the kora-2fa service
```

## Running locally

### Everything in containers

```sh
docker compose up --build                   # builds the image, starts Postgres + kora-2fa
curl localhost:8080/health                   # {"status":"ok"}
```

`docker compose up` builds [`Dockerfile`](Dockerfile) (multi-stage: cargo-chef
dependency cache → `--release` build → distroless runtime, non-root), waits for
Postgres to pass its healthcheck, then starts the service on `:8080` wired to
the same env as [`.env.example`](.env.example).

### Service on the host, Postgres in a container

```sh
cp .env.example .env
docker compose up -d postgres              # just Postgres 16 on :5432
cargo run -p kora-2fa                       # migrates on startup, serves :8080
curl localhost:8080/health                  # {"status":"ok"}
```

Configuration is documented in [`docs/environment-variables.md`](docs/environment-variables.md)
(Phase 1 reads a subset) and [`.env.example`](.env.example) (which also
lists the four added vars, each cross-referenced to `ASSUMPTIONS.md`).

## Tests

```sh
docker compose up -d
export DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa
cargo test -p kora-2fa                      # unit + #[sqlx::test] integration
```

Unit tests cover the TOTP and crypto primitives; the integration suite
drives the real router against a fresh per-test database and walks the full
enable → verify → login → lockout → recover → audit-log journey, plus a
concurrency regression test that fires parallel wrong-TOTP attempts at one
`user_id` and checks none are lost.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml): `cargo fmt --check`,
`cargo clippy -- -D warnings`, `cargo test` with a Postgres service
container, and `cargo audit`. `fmt` and `clippy` build offline against the
committed `.sqlx/` query cache — regenerate it with `cargo sqlx prepare
--workspace` after any query or schema change (see `ASSUMPTIONS.md` §15).
