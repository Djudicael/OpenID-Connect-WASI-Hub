//! # oidc-repository
//!
//! PostgreSQL repository implementations using `pg_client`.

#![allow(missing_docs)]

pub mod connection;
pub mod mapper;
pub mod repositories;

pub use connection::Connection;
