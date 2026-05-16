//! Database connection abstraction.

use tracing::debug;
use wasi_pg_client::ToSql;
use wasi_pg_client::{PgError, QueryResult, Row};

/// A database connection wrapper.
/// Uses `wasi-pg-client` on both native (via tokio-transport) and WASM.
pub struct Connection {
    inner: wasi_pg_client::Connection,
}

impl Connection {
    /// Create a new connection from a `pg_client` connection.
    pub fn from_pg_client(conn: wasi_pg_client::Connection) -> Self {
        debug!("created pg_client connection");
        Self { inner: conn }
    }

    /// Access the underlying connection.
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &wasi_pg_client::Connection {
        &self.inner
    }

    /// Access the underlying connection mutably.
    #[allow(dead_code)]
    pub(crate) fn inner_mut(&mut self) -> &mut wasi_pg_client::Connection {
        &mut self.inner
    }

    /// Execute a simple query and return all rows.
    pub async fn query(&mut self, sql: &str) -> Result<QueryResult, PgError> {
        self.inner.query(sql).await
    }

    /// Execute a parameterized query and return all rows.
    pub async fn query_params(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<QueryResult, PgError> {
        self.inner.query_params(sql, params).await
    }

    /// Execute a query returning at most one row.
    pub async fn query_one(&mut self, sql: &str) -> Result<Option<Row>, PgError> {
        self.inner.query_one(sql).await
    }

    /// Execute a parameterized query returning at most one row.
    pub async fn query_one_params(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<Option<Row>, PgError> {
        let result = self.inner.query_params(sql, params).await?;
        Ok(result.into_rows().into_iter().next())
    }

    /// Execute a statement (INSERT/UPDATE/DELETE) and return the command tag.
    pub async fn execute(&mut self, sql: &str) -> Result<wasi_pg_client::ExecuteResult, PgError> {
        self.inner.execute(sql).await
    }

    /// Execute a batch of SQL statements (multi-statement simple query).
    ///
    /// Unlike `query`, this method properly handles multi-statement batches
    /// and reports errors from any statement in the batch. Use this for
    /// migration files that contain multiple DDL statements.
    pub async fn batch_execute(
        &mut self,
        sql: &str,
    ) -> Result<Vec<wasi_pg_client::QueryResult>, PgError> {
        self.inner.batch_execute(sql).await
    }

    /// Begin a database transaction.
    pub async fn begin(&mut self) -> Result<(), PgError> {
        self.inner.execute("BEGIN").await?;
        Ok(())
    }

    /// Commit the current transaction.
    pub async fn commit(&mut self) -> Result<(), PgError> {
        self.inner.execute("COMMIT").await?;
        Ok(())
    }

    /// Rollback the current transaction.
    pub async fn rollback(&mut self) -> Result<(), PgError> {
        self.inner.execute("ROLLBACK").await?;
        Ok(())
    }

    /// Execute a parameterized statement and return rows affected.
    pub async fn execute_params(
        &mut self,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Result<u64, PgError> {
        let result = self.inner.query_params(sql, params).await?;
        Ok(result.rows_affected().unwrap_or(0))
    }

    /// Gracefully close the connection.
    ///
    /// Sends a `Terminate` message to the PostgreSQL server and shuts down
    /// the transport. After calling this, the connection cannot be used for
    /// further operations.
    ///
    /// If you simply drop the connection, the underlying `wasi_pg_client`
    /// `Drop` impl will close the TCP socket synchronously (without sending
    /// `Terminate`). Calling `close()` explicitly is preferred because it
    /// lets the server release the backend process immediately rather than
    /// waiting for the TCP keep-alive timeout.
    pub async fn close(&mut self) -> Result<(), PgError> {
        debug!("closing pg_client connection");
        self.inner.close().await
    }
}

/// Execute an async block inside a database transaction.
///
/// - Begins a transaction on `$conn`
/// - Runs the block (which can use `$conn` via `&mut`)
/// - Commits on `Ok`, rolls back on `Err`
///
/// `$map_err` is an expression `impl Fn(PgError) -> E` that converts
/// transaction-level errors (begin/commit failures) into the caller's
/// error type.
///
/// # Example
///
/// ```ignore
/// with_transaction!(conn, pg_err, {
///     let user = UserRepo.find_by_email(conn, realm_id, email).await?;
///     Ok(user)
/// })
/// ```
#[macro_export]
macro_rules! with_transaction {
    ($conn:expr, $map_err:expr, $body:block) => {{
        $conn.begin().await.map_err(&$map_err)?;
        let result = async $body.await;
        match result {
            Ok(value) => {
                $conn.commit().await.map_err($map_err)?;
                Ok(value)
            }
            Err(user_err) => {
                let _ = $conn.rollback().await;
                Err(user_err)
            }
        }
    }};
}
