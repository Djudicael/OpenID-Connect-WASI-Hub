//! Connection pool wrapper.

use tracing::debug;

/// A PostgreSQL connection pool.
#[derive(Debug, Clone)]
pub struct PgPool {
    #[cfg(target_arch = "wasm32")]
    inner: wasi_pg_pool::Pool,
    #[cfg(not(target_arch = "wasm32"))]
    inner: deadpool_postgres::Pool,
}

impl PgPool {
    /// Create a new pool (WASM).
    #[cfg(target_arch = "wasm32")]
    pub fn from_wasi(pool: wasi_pg_pool::Pool) -> Self {
        debug!("created WASM pg_client pool");
        Self { inner: pool }
    }

    /// Create a new pool (native).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_native(pool: deadpool_postgres::Pool) -> Self {
        debug!("created native deadpool-postgres pool");
        Self { inner: pool }
    }
}
