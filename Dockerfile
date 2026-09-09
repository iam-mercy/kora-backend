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
