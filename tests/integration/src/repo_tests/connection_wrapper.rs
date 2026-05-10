//! Tests for the `oidc_repository::Connection` wrapper methods directly.
//!
//! These tests specifically exercise the `query_one_params` method that was
//! reported to hang after a prior `query_params` call on the same connection.

use crate::harness::{clean_database, test_conn};

#[tokio::test]
async fn test_wrapper_query_one_params_returns_row() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // The simplest possible query_one_params
    let result = conn
        .query_one_params("SELECT $1::text AS val", &[&"hello"])
        .await
        .expect("query_one_params failed");
    assert!(result.is_some());
    let row = result.unwrap();
    let val: String = row.get(0).expect("failed to get value");
    assert_eq!(val, "hello");
}

#[tokio::test]
async fn test_wrapper_query_one_params_returns_none() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // A query that returns no rows
    let result = conn
        .query_one_params("SELECT 1 WHERE $1::text = 'nonexistent'", &[&"no_match"])
        .await
        .expect("query_one_params with no rows failed");
    assert!(result.is_none());
}

#[tokio::test]
async fn test_wrapper_query_one_params_after_query_params() {
    // This is the exact scenario that was reported to hang:
    // 1. Call query_params on the connection
    // 2. Call query_one_params on the same connection
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // Step 1: query_params
    let result = conn
        .query_params("SELECT $1::int AS num", &[&42i32])
        .await
        .expect("query_params failed");
    assert_eq!(result.len(), 1);

    // Step 2: query_one_params (this was reported to hang)
    let result = conn
        .query_one_params("SELECT $1::text AS val", &[&"after_query_params"])
        .await
        .expect("query_one_params after query_params failed");
    assert!(result.is_some());
    let val: String = result.unwrap().get(0).expect("get failed");
    assert_eq!(val, "after_query_params");
}

#[tokio::test]
async fn test_wrapper_query_one_params_after_query() {
    // query (simple protocol) then query_one_params (extended protocol)
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // Step 1: simple query
    let result = conn.query("SELECT 1").await.expect("query failed");
    assert_eq!(result.len(), 1);

    // Step 2: query_one_params
    let result = conn
        .query_one_params("SELECT $1::text", &[&"after_simple_query"])
        .await
        .expect("query_one_params after simple query failed");
    assert!(result.is_some());
}

#[tokio::test]
async fn test_wrapper_mixed_operations_sequence() {
    // The most thorough test: mix of all connection methods in sequence
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // 1. Simple query
    let result = conn.query("SELECT 1").await.expect("query failed");
    assert_eq!(result.len(), 1);

    // 2. Parameterized query
    let result = conn
        .query_params("SELECT $1::int", &[&42i32])
        .await
        .expect("query_params failed");
    assert_eq!(result.len(), 1);

    // 3. query_one (simple)
    let result = conn.query_one("SELECT 1").await.expect("query_one failed");
    assert!(result.is_some());

    // 4. query_one_params (the problematic method)
    let result = conn
        .query_one_params("SELECT $1::int WHERE $1::int > $2::int", &[&10i32, &5i32])
        .await
        .expect("query_one_params failed");
    assert!(result.is_some());

    // 5. query_one_params returning None
    let result = conn
        .query_one_params("SELECT $1::int WHERE $1::int > $2::int", &[&3i32, &5i32])
        .await
        .expect("query_one_params failed");
    assert!(result.is_none());

    // 6. execute (DDL)
    conn.execute("CREATE TEMP TABLE test_wrapper (id INT, name TEXT)")
        .await
        .expect("execute DDL failed");

    // 7. execute_params (DML)
    conn.execute_params(
        "INSERT INTO test_wrapper (id, name) VALUES ($1, $2)",
        &[&1i32, &"test"],
    )
    .await
    .expect("execute_params failed");

    // 8. Verify with query_params
    let result = conn
        .query_params("SELECT name FROM test_wrapper WHERE id = $1", &[&1i32])
        .await
        .expect("query_params after execute_params failed");
    assert_eq!(result.len(), 1);

    // 9. Verify with query_one_params
    let result = conn
        .query_one_params("SELECT name FROM test_wrapper WHERE id = $1", &[&1i32])
        .await
        .expect("query_one_params after execute_params failed");
    assert!(result.is_some());
    let name: String = result.unwrap().get(0).expect("get name failed");
    assert_eq!(name, "test");

    // 10. Multiple query_one_params in a row
    for i in 0..5 {
        let result = conn
            .query_one_params("SELECT $1::int AS n", &[&i])
            .await
            .expect("repeated query_one_params failed");
        assert!(result.is_some());
    }
}

#[tokio::test]
async fn test_wrapper_begin_commit_rollback() {
    let mut conn = test_conn().await;
    clean_database(&mut conn).await.unwrap();

    // Test begin + commit
    conn.begin().await.expect("begin failed");
    conn.execute("CREATE TEMP TABLE txn_wrapper (id INT)")
        .await
        .expect("create table failed");
    conn.commit().await.expect("commit failed");

    // Table should exist after commit
    let result = conn.query("SELECT * FROM txn_wrapper").await;
    assert!(result.is_ok());

    // Test begin + rollback
    conn.begin().await.expect("begin failed");
    conn.execute_params("INSERT INTO txn_wrapper (id) VALUES ($1)", &[&99i32])
        .await
        .expect("insert failed");
    conn.rollback().await.expect("rollback failed");

    // The row should not exist after rollback
    let result = conn
        .query_params("SELECT id FROM txn_wrapper WHERE id = $1", &[&99i32])
        .await
        .expect("query failed");
    assert_eq!(result.len(), 0);
}
