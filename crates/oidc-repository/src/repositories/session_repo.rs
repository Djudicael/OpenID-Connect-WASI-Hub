use async_trait::async_trait;
use oidc_core::models::Session;
use oidc_core::traits::Repository;
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the Session repository.
pub struct SessionRepo;

#[async_trait]
impl Repository<Session> for SessionRepo {
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<Session>, OidcError> {
        todo!("implement session find_by_id")
    }

    async fn create(&self, _entity: &Session) -> Result<(), OidcError> {
        todo!("implement session create")
    }

    async fn update(&self, _entity: &Session) -> Result<(), OidcError> {
        todo!("implement session update")
    }

    async fn delete(&self, _id: Uuid) -> Result<(), OidcError> {
        todo!("implement session delete")
    }
}
