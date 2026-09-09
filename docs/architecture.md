# Architecture

This document exists to make one boundary unambiguous: **what Phase 1 of
kora-backend (`kora-2fa`) is and is not responsible for.** If you are
reviewing this repo — as a contributor or a Drips reviewer — the short version
is that this service does not talk to a blockchain, does not hold a wallet
key, and does not call a smart contract. It is an HTTP API in front of a
Postgres database. Everything below expands on that.

For the file-by-file breakdown, see the
[**Layout** section of `README.md`](../README.md#layout) — this document
describes the *shape* and the *decisions*, not the tree.

## Repository shape

- A **Cargo workspace** with a single member today, `crates/kora-2fa`. The
  workspace root is set up for more members later; nothing requires one yet.
- Inside the crate, a **thin binary over a library**: `main.rs` only loads
  config, opens the pool, runs migrations, and serves; everything with
  behavior worth testing lives in `lib.rs` and its modules, so the integration
  tests build the exact same router the binary does.
- **Module boundaries** follow responsibilities, not layers: configuration
  loading, the shared `{ error, message }` envelope, the crypto primitives
  (AES-256-GCM sealing, Argon2id hashing), the RFC 6238 TOTP wrapper, HS256
  JWT verify/mint, the database (pool, migrator, DTOs), the bearer-token
  extractor, and the route handlers plus the router-level hardening stack.
- **Two test suites** with different needs: the integration suite drives the
  real router against a per-test Postgres database; the hardening suite
  (`tests/hardening.rs`) needs no database and pins the router layers from
  §18.
- The **`docs/` directory is a vendored contract**, not local design:
  `openapi.yaml` and `environment-variables.md` are copied verbatim from
  `github.com/iam-mercy/kora-app` and are authoritative over anything the code
  or this repo's other docs say.
- **Container and compose files** sit at the repo root (`Dockerfile`,
  `.dockerignore`, `docker-compose.yml`).

## Decoupling from the chain

From `README.md`:

> This repo is decoupled from the Stellar/Celo smart contracts; it is a plain
> Postgres-backed set of services.

Concretely, in Phase 1:

- **No chain client.** There is no Soroban / Stellar SDK, no Celo or
  general-purpose web3 library, and no JSON-RPC client in the dependency
  graph. `crates/kora-2fa/Cargo.toml` is `axum` + `tokio` + `sqlx` (Postgres
  only) + `serde` + `tracing` + `totp-rs` + `jsonwebtoken` + `aes-gcm` +
  `argon2` + small helpers. Nothing else.
- **No contract calls, addresses, or signing keys.** The service never
  constructs, simulates, submits, or signs a transaction. It holds no
  Stellar/Celo secret key material of any kind.
- **The only external system it talks to is its own Postgres database.** State
  — 2FA records, backup codes, audit rows — lives in Postgres and nowhere
  else.
- **It does not even call the auth provider.** Incoming bearer tokens are
  verified locally as opaque HS256 JWTs against a shared `JWT_SECRET`; there is
  no callout to Supabase / Kora App, no JWKS fetch, no issuer or audience
  check (a documented limitation — `ASSUMPTIONS.md` §1).

Where the `user_id` in a request ultimately comes from a chain-linked
identity in the wider Kora App product is **not this service's concern in
Phase 1**. It receives a `user_id`, checks the caller is that user, and
operates on its own tables.

## Production readiness (deployment & CI posture)

"Production readiness" for this service means the following are in place. It
does **not** mean the service is wired to real Kora App auth infrastructure —
see the caveats at the end of this section.

### Container

- Multi-stage `Dockerfile`: a `cargo-chef` dependency-cache stage, a
  `--release` build, and a runtime stage on
  `gcr.io/distroless/cc-debian12:nonroot` — **pinned by digest**, no shell, no
  package manager, running as uid 65532, ~47 MB, carrying only the stripped
  binary. Details and rationale in `ASSUMPTIONS.md` §17.
- `docker-compose.yml` runs the service alongside Postgres 16 for local use;
  it is not a production topology.
- No in-image `HEALTHCHECK` (distroless has nothing to run one with) — probe
  `GET /health` from the orchestrator.

### Runtime and boot hardening

- **Router layers** (`ASSUMPTIONS.md` §18), applied to every endpoint and
  non-configurable in Phase 1: a caught handler panic is rendered as the
  standard `{ "error": "INTERNAL", ... }` / `500` envelope instead of dropping
  the connection; request bodies are capped at 64 KiB (`413` past that); a
  request exceeding 10 s is answered `408`.
- **Placeholder-secret guard** (§19): startup emits a loud `WARN` naming
  `JWT_SECRET` and/or `TOTP_ENCRYPTION_KEY` if either still holds its
  `.env.example` value. It is a warning, not a refusal — the local compose
  stack and CI use the example file deliberately — to be promoted to a hard
  stop once real auth infra lands.
- **Database-connect retry** (§20): an unreachable Postgres at boot is retried
  5× with exponential backoff (1s → 2s → 4s → 8s) before the process exits
  non-zero.

### Supply-chain and scanning

`.github/workflows/ci.yml` runs six jobs in parallel on every push and PR.
Three are the ordinary Rust gates (`rustfmt`, `clippy -D warnings`, `test`
against Postgres 16). The other three are the supply-chain posture:

| Job | Enforcement | Reference |
|---|---|---|
| `cargo-deny` | **Gate.** Advisories, licenses, bans (one version per crate, no `*` deps), sources (crates.io only), against `deny.toml`. Replaced the old `cargo audit` job. | §21 |
| `coverage` | **Report-only.** `cargo llvm-cov` line/function numbers to the run summary + an `lcov.info` artifact. No minimum-coverage gate yet. | §22 |
| `image scan` | **Report-only.** Trivy scans the built image (`HIGH,CRITICAL`, `--ignore-unfixed`); SARIF to the Security tab. | §23 |

Every current `cargo-deny` finding is written into `deny.toml` as a commented
exception, so the job is green today and a *new* advisory / disallowed
license / duplicate crate / git dependency is what turns it red. §22 and §23
record what each report-only job needs before it can become a gate.

### What production readiness does not yet include

- **Real authentication infrastructure.** HS256 shared secret, no JWKS, no
  issuer/audience validation, self-minted `/2fa/login` session tokens
  (`ASSUMPTIONS.md` §1, §5).
- **A secret manager.** `SECRET_PROVIDER` / `AWS_SECRETS_JSON` are documented
  but unimplemented (§3, §14); secrets come from the environment.
- **TLS.** The service speaks plain HTTP on `BIND_ADDR` and expects a proxy
  to terminate TLS.
- **A general rate limiter.** Only the documented 5-strike account lockout
  exists; there is no Redis-backed per-request limiter (§8).
- **A filled-in security contact.** `SECURITY.md` still carries a
  `[security contact needed]` placeholder.

## Deliberately unbuilt (decision record)

`docs/openapi.yaml` is vendored whole from kora-app and describes a surface
larger than Phase 1. The following are **absent by decision, not by
oversight** — no route, no table, no stub (`ASSUMPTIONS.md` §14). Their
schemas remain in the vendored spec, unmodified.

- **Admin endpoints** — `/admin/quota`, `/admin/quota/unlimited`,
  `/admin/canary`, `/admin/flagged`, `/admin/flagged/{user_id}`,
  `/admin/users/{user_id}/2fa-summary`.
- **`/tenant/provision`** — per-tenant onboarding.
- **`/ws/leaderboard`** — the websocket leaderboard feed.
- **Env vars for the above** — `SECRET_PROVIDER`, `AWS_SECRETS_JSON`,
  `LEADERBOARD_DECAY_LAMBDA`, `WEBHOOK_LOG_MAX_ENTRIES`, `REDIS_URL`.

Related deferrals, each recorded where the judgment was made:

- **Broader-than-self access / RBAC** and the `X-User-Id` service-to-service
  path — deferred until the admin surface exists (`ASSUMPTIONS.md` §2, §6).
- **Delegated session issuance** — minting our own HS256 session token in
  `/2fa/login` is a stand-in for a call/redirect to the real auth service
  (§5).
- **Per-tenant TOTP parameters** (algorithm / digits / period — kora-app's
  "cryptographic agility") — most likely belongs with `/tenant/provision`,
  which already carries a per-tenant `issuer` (§12).

## Future phases

**Phase 2 is undecided.** This repository does not contain a Phase 2 design, a
timeline, or a scope, and this document will not invent one.

A future service — working name **`contract-gateway`** — that would connect
kora-backend to the on-chain Kora App registry is *anticipated* at the product
level, but as of this repository's current state it is **not started, not
scoped, and not designed**. Nothing in this codebase depends on it, references
it, or assumes it will exist in any particular form. The decoupling described
above is the current reality, not a temporary state with a known end.

If and when that work begins, the decision to start it — and the boundary it
would draw with `kora-2fa` — should be recorded in a dedicated issue on this
repository and reflected back into this document. Until such an issue exists,
treat any assumption that this service will "eventually talk to the chain" as
unfounded.
