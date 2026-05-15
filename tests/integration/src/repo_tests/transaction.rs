//! Tests for the `with_transaction!` macro with repository operations.

use crate::harness::test_conn;
use oidc_core::OidcError;
use oidc_core::models::{Realm, User};
use oidc_repository::repositories::{realm_repo::RealmRepo, user_repo::UserRepo};
use oidc_repository::with_transaction;
use uuid::Uuid;

fn make_realm(name: &str) -> Realm {
    Realm {
        id: Uuid::new_v4(),
        name: name.to_string(),
        display_name: name.to_string(),
        enabled: true,
        config: serde_json::Value::Object(serde_json::Map::new()),
        deleted_at: None,
    }
}

fn make_user(realm_id: Uuid, email: &str) -> User {
    User {
        id: Uuid::new_v4(),
        realm_id,
        email: email.to_string(),
        email_verified: true,
        username: None,
        password_hash: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        preferred_username: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        phone_number: None,
        phone_number_verified: None,
        locale: "en".into(),
        attributes: serde_json::Value::Object(serde_json::Map::new()),
        enabled: true,
        deleted_at: None,
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn test_with_transaction_commit() -> Result<(), OidcError> {
    let mut conn = test_conn().await;
    

    let realm = make_realm("txn-commit-realm");
    let user = make_user(realm.id, "txn@example.com");

    // Create realm first (outside transaction, since user references it)
    RealmRepo.create(&mut conn, &realm).await?;

    // Use with_transaction! to create user inside a transaction
    let result: Result<(), OidcError> = with_transaction!(conn, oidc_repository::mapper::pg_err, {
        UserRepo.create(&mut conn, &user).await?;
        Ok(())
    });

    assert!(result.is_ok(), "transaction should commit successfully");

    // Verify the user was committed
    let found = UserRepo.find_by_id(&mut conn, user.id).await?;
    assert!(found.is_some(), "user should exist after commit");
    Ok(())
}

#[tokio::test]
async fn test_with_transaction_rollback() -> Result<(), OidcError> {
    let mut conn = test_conn().await;
    

    let realm = make_realm("txn-rollback-realm");
    RealmRepo.create(&mut conn, &realm).await?;

    let user = make_user(realm.id, "rollback@example.com");

    // Use with_transaction! but return an error to trigger rollback
    let result: Result<(), OidcError> = with_transaction!(conn, oidc_repository::mapper::pg_err, {
        UserRepo.create(&mut conn, &user).await?;
        Err(OidcError::AuthenticationFailed("test rollback".into()))
    });

    assert!(result.is_err(), "transaction should return the error");

    // Verify the user was rolled back
    let found = UserRepo.find_by_id(&mut conn, user.id).await?;
    assert!(found.is_none(), "user should NOT exist after rollback");
    Ok(())
}

#[tokio::test]
async fn test_with_transaction_multi_operation() -> Result<(), OidcError> {
    let mut conn = test_conn().await;
    

    let realm = make_realm("txn-multi-realm");
    RealmRepo.create(&mut conn, &realm).await?;

    let user1 = make_user(realm.id, "multi1@example.com");
    let user2 = make_user(realm.id, "multi2@example.com");

    // Create two users in a single transaction
    let result: Result<(), OidcError> = with_transaction!(conn, oidc_repository::mapper::pg_err, {
        UserRepo.create(&mut conn, &user1).await?;
        UserRepo.create(&mut conn, &user2).await?;
        Ok(())
    });

    assert!(result.is_ok());

    // Both users should exist
    assert!(UserRepo.find_by_id(&mut conn, user1.id).await?.is_some());
    assert!(UserRepo.find_by_id(&mut conn, user2.id).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn test_with_transaction_rollback_partial() -> Result<(), OidcError> {
    // Create first user, then fail — first should be rolled back too
    let mut conn = test_conn().await;
    

    let realm = make_realm("txn-partial-realm");
    RealmRepo.create(&mut conn, &realm).await?;

    let user1 = make_user(realm.id, "partial1@example.com");

    let result: Result<(), OidcError> = with_transaction!(conn, oidc_repository::mapper::pg_err, {
        UserRepo.create(&mut conn, &user1).await?;
        // First user created, but then we fail
        Err(OidcError::Internal("simulated failure".into()))
    });

    assert!(result.is_err());

    // Neither user should exist (atomic rollback)
    assert!(UserRepo.find_by_id(&mut conn, user1.id).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn test_with_transaction_with_query_one_params() -> Result<(), OidcError> {
    // Test that query_one_params works correctly inside a transaction
    let mut conn = test_conn().await;
    

    let realm = make_realm("txn-qop-realm");
    RealmRepo.create(&mut conn, &realm).await?;

    let user = make_user(realm.id, "txnqop@example.com");

    let result: Result<(), OidcError> = with_transaction!(conn, oidc_repository::mapper::pg_err, {
        UserRepo.create(&mut conn, &user).await?;

        // Now look up the user inside the same transaction
        let found = UserRepo
            .find_by_email(&mut conn, realm.id, "txnqop@example.com")
            .await?;
        assert!(found.is_some(), "user should be visible inside transaction");

        Ok(())
    });

    assert!(result.is_ok());
    Ok(())
}
