# Contributing to kora-backend

Thanks for your interest in contributing. This repo is the backend-services
side of **Kora App** — a plain Rust / Axum / Postgres codebase, decoupled from
the Stellar/Celo smart contracts. Phase 1 is the `kora-2fa` service.

## Development Setup

### Prerequisites

- **Rust** — stable. The repo carries a `rust-toolchain.toml` pinned to the
  `stable` channel (with `rustfmt` and `clippy`); the workspace MSRV is
  `1.75` (`workspace.package.rust-version`).
- **Docker** + **Docker Compose** — for Postgres, and for the containerized
  run/build path.
- **`sqlx-cli`** — for migrations and regenerating the offline query cache:
  `cargo install sqlx-cli --no-default-features --features rustls,postgres`.
- **`cargo-deny`** — to run the supply-chain checks locally before pushing:
  `cargo install --locked cargo-deny`.
- **`cargo-llvm-cov`** *(optional)* — to reproduce the coverage job locally:
  `cargo install cargo-llvm-cov`.
- **Postgres 16** — supplied by `docker compose`; no local install needed.

### Setup

1. Fork the repository and clone your fork.
2. `cd kora-backend`
3. `cp .env.example .env`
   The example file carries **dev-only** placeholder secrets (`JWT_SECRET`,
   `TOTP_ENCRYPTION_KEY`) and four vars not in `docs/environment-variables.md`,
   each cross-referenced to `ASSUMPTIONS.md`. Booting with either placeholder
   still works but logs a loud `WARN` (`ASSUMPTIONS.md` §19).

Then pick one of the two run paths from the README:

**Service on the host, Postgres in a container**

```sh
docker compose up -d postgres            # Postgres 16 on :5432
cargo run -p kora-2fa                     # migrates on startup, serves :8080
curl localhost:8080/health               # {"status":"ok"}
```

**Everything in containers**

```sh
docker compose up --build                # builds the image, starts Postgres + kora-2fa
curl localhost:8080/health               # {"status":"ok"}
docker compose down                       # add -v to drop the DB volume
```

`docker compose up --build` builds the multi-stage `Dockerfile` (cargo-chef
dependency cache → `--release` build → distroless non-root runtime). Re-run it
after code changes — the dependency layer is cached, so only the service crate
recompiles. See `ASSUMPTIONS.md` §17 for the image and compose-stack details.

## Code Style

- Run `cargo fmt --all` before committing. CI enforces `cargo fmt --all --check`.
- `cargo clippy --workspace --all-targets -- -D warnings` must be clean. The
  workspace sets `clippy::all = "warn"` and CI upgrades warnings to errors.
- Follow Rust naming conventions (`snake_case` functions, `PascalCase` types).
- Keep doc comments on public items — the existing modules document every
  public type and function, and why a judgment call was made.
- All error responses go through the shared `{ "error": <code>, "message":
  <detail> }` envelope in `src/error.rs`. Don't return ad-hoc bodies.
- Every judgment call, and every env var not in
  `docs/environment-variables.md`, is recorded in `ASSUMPTIONS.md` (§1–§23
  today). If you add one, add a numbered section there in the same PR.

## Pull Request Process

1. **Reference an issue.** Comment on it first so work isn't duplicated.
2. **Branch:** `git checkout -b feature/<issue-number>-<short-description>`.
3. **Implement** against `docs/openapi.yaml` — it is the contract. Preserve the
   self-only authorization rule (`jwt.sub` must equal the target `user_id`;
   see `ASSUMPTIONS.md` §6).
4. **Test** — see below. Add tests for new behavior, success and failure paths.
5. **Document** — update `docs/` and/or `ASSUMPTIONS.md` when behavior or
   configuration changes.
6. **Open the PR**, fill in `.github/PULL_REQUEST_TEMPLATE.md`, reference the
   issue.

### CI must pass

`.github/workflows/ci.yml` runs six jobs on every push to `main` and every PR:

| Job | What it runs |
|---|---|
| `rustfmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test` | `cargo test --workspace --all-targets` against a Postgres 16 service container |
| `cargo-deny` | `cargo-deny check` — advisories, bans, licenses, sources — against `deny.toml` (`ASSUMPTIONS.md` §21) |
| `coverage` | `cargo llvm-cov --workspace --all-targets`, **report-only**; publishes `lcov.info` + `coverage.json` (`ASSUMPTIONS.md` §22) |
| `image scan` | builds the release image and runs **Trivy** (`HIGH,CRITICAL`, `--ignore-unfixed`), **report-only** (`ASSUMPTIONS.md` §23) |

`rustfmt` and `clippy` build with `SQLX_OFFLINE=true` against the committed
`.sqlx/` cache, so they need no database. `coverage` and `image scan` are not
gates yet — they establish a baseline first (see the §22 / §23 notes).

If you changed any `sqlx::query!` / `sqlx::query_as!` invocation or a
migration, regenerate the offline cache and commit the diff (`ASSUMPTIONS.md`
§15):

```sh
docker compose up -d postgres
DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa \
  cargo sqlx migrate run
DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa \
  cargo sqlx prepare --workspace
```

If a dependency change makes `cargo-deny` fail — a new advisory, a
non-allow-listed license, a duplicate crate version, a non-crates.io source —
fix it, or add a scoped, commented exception to `deny.toml` (a
`{ id = "...", reason = "..." }` entry under `[advisories]` for an advisory;
the matching `skip` / `exceptions` list for the others). See `ASSUMPTIONS.md`
§21 for the expected form. `.cargo/audit.toml` no longer exists — the policy
lives entirely in `deny.toml`.

## Testing

```sh
docker compose up -d postgres            # tests only need the database
export DATABASE_URL=postgresql://kora:kora@localhost:5432/kora_2fa
cargo test -p kora-2fa                    # unit + #[sqlx::test] integration
```

- **Unit tests** cover the TOTP (`totp.rs`), crypto (`crypto.rs`), JWT
  (`jwt.rs`), config (`config.rs`, incl. the §19 placeholder-secret guard),
  and DB-retry (`db`, §20) primitives.
- **Integration tests** (`tests/integration.rs`) drive the real router with
  `#[sqlx::test]`, each against a fresh isolated database, and walk the full
  enable → verify → login → lockout → recover → audit-log journey.
- **Hardening tests** (`tests/hardening.rs`) pin the router hardening layers
  from `ASSUMPTIONS.md` §18 — panic-to-envelope, the 64 KiB body cap (up front
  and mid-read), the request timeout `408`, and pass-through of ordinary
  responses.
- `concurrent_wrong_totp_never_loses_a_failure` is a regression test for the
  atomic lockout counter (`ASSUMPTIONS.md` §8) — keep it green.

Regenerate `.sqlx/` (commands above) whenever a query or the schema changes,
or the offline `fmt`/`clippy` builds in CI will drift from the code.

To reproduce the coverage job locally:

```sh
cargo llvm-cov --workspace --all-targets --summary-only
```

## Code Review

Maintainers look for:

- Correct implementation of the `docs/openapi.yaml` slice, including the
  status codes the spec assigns.
- The self-only authorization rule preserved on every authenticated endpoint.
- No secret material logged or returned (TOTP secrets stay AES-GCM-sealed at
  rest; backup codes stay Argon2id-hashed).
- Tests for new success and failure paths; `.sqlx/` regenerated if needed.
- `ASSUMPTIONS.md` updated for any new judgment call or added env var.

## Getting Help

- Open an issue or a discussion on this repository.
- The wider Kora App community is on
  [Telegram](https://t.me/+Jw8HkvUhinw2YjE0).

## Code of Conduct

- Be respectful and inclusive.
- Help others learn and grow.
- Focus on constructive feedback.
- Follow [GitHub's community guidelines](https://docs.github.com/en/site-policy/github-terms/github-community-guidelines).

Thank you for contributing to Kora App.
