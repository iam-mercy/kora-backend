# syntax=docker/dockerfile:1

# Multi-stage build for the kora-2fa service.
#
# Stages:
#   chef     — base image: C toolchain + cargo-chef
#   planner  — emits recipe.json (the dependency graph)
#   builder  — cooks deps from the recipe, then builds the release binary
#   runtime  — distroless/cc image carrying only the stripped binary
#
# Build:  docker build -t kora-2fa .
# Run:    docker compose up   (brings up postgres + this service)
#
# rust-toolchain.toml tracks the `stable` channel; this pins the build image to
# a concrete minor for reproducibility. Bump it when CI's stable moves ahead.
ARG RUST_VERSION=1.98

# ── base ──────────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-slim-bookworm AS chef
WORKDIR /app

# Resolve rust-toolchain.toml's `stable` channel once here, in a cached layer,
# so neither `cargo chef cook` nor the release build stops to re-sync it.
COPY rust-toolchain.toml .
RUN rustup show

# `rust:slim` ships no C toolchain; `ring` (pulled in via sqlx' rustls TLS)
# needs a C compiler and linker to build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

# cargo-chef turns the dependency graph into a cacheable layer so day-to-day
# source edits don't trigger a full rebuild of every crate.
ARG CARGO_CHEF_VERSION=0.1.68
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-chef --locked --version ${CARGO_CHEF_VERSION}

# ── planner ───────────────────────────────────────────────────────────────────
# Distil the workspace down to a dependency recipe. Only Cargo.* manifests
# affect the output, so this layer is cheap to recompute.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── builder ───────────────────────────────────────────────────────────────────
FROM chef AS builder

# Compile every dependency first, from the recipe alone. This layer only busts
# when the dependency set changes.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --package kora-2fa --recipe-path recipe.json

# No database at build time: the query!/query_as! macros resolve against the
# committed .sqlx cache instead of a live connection.
ENV SQLX_OFFLINE=true

# Now the real sources. migrations/ is embedded into the binary by
# sqlx::migrate! here, so the runtime image won't need it.
COPY . .
# Build, then strip debug symbols in the same layer so they never land in an
# intermediate image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --package kora-2fa --locked \
    && strip target/release/kora-2fa

# ── runtime ───────────────────────────────────────────────────────────────────
# distroless/cc carries glibc + libgcc + ca-certificates and nothing else — no
# shell, no package manager. The :nonroot tag runs as uid 65532; pinned by
# digest so the runtime base can't drift under us.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

LABEL org.opencontainers.image.title="kora-2fa" \
      org.opencontainers.image.description="Kora App Backend 2FA / auth service (Phase 1)" \
      org.opencontainers.image.source="https://github.com/iam-mercy/kora-backend" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12:nonroot"

WORKDIR /app
COPY --from=builder /app/target/release/kora-2fa /usr/local/bin/kora-2fa

# Explicit even though :nonroot already defaults to it.
USER nonroot:nonroot

# The service reads BIND_ADDR (config.rs default is 0.0.0.0:8080). Set it here
# so the container listens on all interfaces without needing compose to pass it.
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

# No HEALTHCHECK: distroless has no shell or curl/wget to run one. Probe the
# unauthenticated GET /health endpoint from the orchestrator instead.

ENTRYPOINT ["/usr/local/bin/kora-2fa"]
