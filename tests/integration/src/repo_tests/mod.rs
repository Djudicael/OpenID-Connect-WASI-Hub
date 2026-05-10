//! Comprehensive repository integration tests.
//!
//! These tests exercise the repository layer against a real PostgreSQL database,
//! covering scenarios that the basic CRUD tests in `db_tests` don't:
//!
//! - Multi-step operations on a single connection (the `query_one_params` hang scenario)
//! - Transaction support via `with_transaction!` macro
//! - Edge cases: empty results, null optional fields, concurrent operations
//! - `list` and `count` methods with various filter combinations
//! - Full lifecycle tests for sessions, API keys, signing keys, auth codes, audit events
//! - Connection wrapper direct method tests

mod connection_wrapper;
mod lifecycle;
mod transaction;
