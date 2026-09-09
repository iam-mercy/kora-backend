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
- **Router hardening** (`ASSUMPTIONS.md` §18): a caught handler panic returns
  the same `{error, message}` `500` envelope as every other error path
  instead of dropping the connection; request bodies are capped at 64 KiB
  (`413` past that); a request that runs longer than 10 s is answered with
  `408`.
- **Boot-time guards**: startup logs a loud `WARN` if `JWT_SECRET` or
  `TOTP_ENCRYPTION_KEY` still holds its `.env.example` placeholder value
  (`ASSUMPTIONS.md` §19), and an unreachable Postgres is retried 5× with
  exponential backoff before the process gives up (§20).

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
    routes/                health, twofa, recovery + the hardening layer stack
  tests/integration.rs     end-to-end tests against real Postgres
  tests/hardening.rs       panic / body-cap / timeout tests (no database)
migrations/                sqlx migrations
docs/                      vendored openapi.yaml + environment-variables.md
Dockerfile                 multi-stage build -> distroless runtime image
.dockerignore              keeps target/, .git/, secrets out of the context
docker-compose.yml         Postgres + the kora-2fa service
```

## Running locally

### Everything in containers

```sh
docker compose up --build                   # builds the image, starts Postgres + kora-2fa
curl localhost:8080/health                   # {"status":"ok"}
docker compose down                          # stop the stack (add -v to drop the DB volume)
```

Re-run `docker compose up --build` after code changes — cargo-chef keeps the
dependency layer, so only the service crate recompiles.

`docker compose up` builds [`Dockerfile`](Dockerfile) (multi-stage: cargo-chef
dependency cache → `--release` build → ~47 MB distroless runtime, non-root),
waits for Postgres to pass its healthcheck, then starts the service on `:8080`
wired to the same env as [`.env.example`](.env.example). The service talks to
Postgres over the host's published `:5432` (`host.docker.internal`), not the
compose bridge — see [`ASSUMPTIONS.md`](ASSUMPTIONS.md) §17.

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

> The compose stack feeds the service `.env.example` verbatim — including the
> **dev-only** `JWT_SECRET` and `TOTP_ENCRYPTION_KEY`. Override both (and
> `DATABASE_URL`) before running the image anywhere real.

## Tests

```sh
docker compose up -d postgres              # tests only need the database
export DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa
cargo test -p kora-2fa                      # unit + #[sqlx::test] integration
```

Unit tests cover the TOTP and crypto primitives; the integration suite
drives the real router against a fresh per-test database and walks the full
enable → verify → login → lockout → recover → audit-log journey, plus a
concurrency regression test that fires parallel wrong-TOTP attempts at one
`user_id` and checks none are lost.

### Coverage

```sh
cargo install cargo-llvm-cov                 # one-time
docker compose up -d postgres
export DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa
cargo llvm-cov --workspace --all-targets     # summary table
cargo llvm-cov --workspace --all-targets --html   # target/llvm-cov/html/index.html
```

CI's `coverage` job runs the same thing against its Postgres container and
publishes the line / function numbers to the run's summary page plus an
`lcov.info` artifact. It is **report-only** — there is no minimum-coverage
gate (`ASSUMPTIONS.md` §22).

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

| Job | What it runs |
|---|---|
| `rustfmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test` | `cargo test --workspace --all-targets` against a Postgres 16 service container |
| `cargo-deny` | [`cargo deny check`](deny.toml) — advisories, licenses, bans (duplicate versions), sources. Replaces the old `cargo audit` job (`ASSUMPTIONS.md` §21) |
| `coverage` | `cargo llvm-cov` against the Postgres service container; line / function % to the job summary, `lcov.info` + `coverage.json` as an artifact. Report-only (`ASSUMPTIONS.md` §22) |
| `image scan` | Builds [`Dockerfile`](Dockerfile) and runs a [Trivy](https://trivy.dev) vulnerability scan on the image (OS + linked libs). HIGH/CRITICAL table to the log, SARIF as an artifact + to the Security tab. Report-only, `--ignore-unfixed`, ignores in [`.trivyignore`](.trivyignore) (`ASSUMPTIONS.md` §23) |

`fmt` and `clippy` build offline against the committed `.sqlx/` query
cache — regenerate it with `cargo sqlx prepare --workspace` after any query
or schema change (see `ASSUMPTIONS.md` §15).

Every `cargo-deny` finding on today's dependency graph is written into
[`deny.toml`](deny.toml) as a commented exception, so the job is green now
and it is a *new* advisory / disallowed license / duplicate crate / git
dependency that turns it red. Run `cargo deny check` locally before changing
a dependency.

`cargo-deny` scans the source dependency graph; the `image scan` job scans
the built container — the distroless base OS packages and the libraries
linked into the release binary — which the source scan never sees. Run it
locally with:

```sh
docker build -t kora-2fa .
trivy image --ignore-unfixed --severity HIGH,CRITICAL kora-2fa
```

`coverage` and `image scan` are **report-only** today: they publish numbers
and findings but do not fail the build. `ASSUMPTIONS.md` §22 / §23 record
what it takes to promote each to a gate.
