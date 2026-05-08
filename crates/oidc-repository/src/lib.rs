//! # oidc-repository
//!
//! PostgreSQL repository implementations using `pg_client`.
//!
//! Each request opens a fresh connection (no pooling) — pgbouncer handles
//! connection management externally.

#![allow(missing_docs)]

pub mod connection;
pub mod mapper;
pub mod repositories;

pub use connection::Connection;
