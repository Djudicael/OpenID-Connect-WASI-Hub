use async_trait::async_trait;
use oidc_core::models::Client;
use oidc_core::traits::Repository;
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the Client repository.
pub struct ClientRepo;

#[async_trait]
impl Repository<Client> for ClientRepo {
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<Client>, OidcError> {
        todo!("implement client find_by_id")
    }

    async fn create(&self, _entity: &Client) -> Result<(), OidcError> {
        todo!("implement client create")
    }

    async fn update(&self, _entity: &Client) -> Result<(), OidcError> {
        todo!("implement client update")
    }

    async fn delete(&self, _id: Uuid) -> Result<(), OidcError> {
        todo!("implement client delete")
    }
}
