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
