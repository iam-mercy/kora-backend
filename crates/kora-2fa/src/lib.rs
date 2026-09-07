//! Kora App Backend 2FA service — Phase 1 library crate.
//!
//! The binary (`main.rs`) is a thin wrapper that loads [`config::Config`],
//! opens the pool, runs migrations, and serves [`routes::router`]. Everything
//! testable lives here so integration tests can build the same router.

pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod jwt;
pub mod middleware;
pub mod routes;
pub mod totp;
