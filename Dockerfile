# syntax=docker/dockerfile:1

# Multi-stage build for the kora-2fa service.
#
# rust-toolchain.toml tracks the `stable` channel, so the build image follows
# the latest stable 1.x. Pin RUST_VERSION to a specific minor (e.g. 1.90) for
# byte-for-byte reproducible builds.
ARG RUST_VERSION=1

# ── base ──────────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-slim-bookworm AS chef
WORKDIR /app

# `rust:slim` ships no C toolchain; `ring` (pulled in via sqlx' rustls TLS)
# needs a C compiler and linker to build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

# cargo-chef turns the dependency graph into a cacheable layer so day-to-day
# source edits don't trigger a full rebuild of every crate.
ARG CARGO_CHEF_VERSION=0.1.68
RUN cargo install cargo-chef --locked --version ${CARGO_CHEF_VERSION}

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
RUN cargo chef cook --release --package kora-2fa --recipe-path recipe.json

# No database at build time: the query!/query_as! macros resolve against the
# committed .sqlx cache instead of a live connection.
ENV SQLX_OFFLINE=true

# Now the real sources. migrations/ is embedded into the binary by
# sqlx::migrate! here, so the runtime image won't need it.
COPY . .
RUN cargo build --release --package kora-2fa --locked

# Drop debug symbols before the binary is carried into the runtime image.
RUN strip target/release/kora-2fa
