use async_trait::async_trait;
use oidc_core::models::ApiKey;
use oidc_core::traits::Repository;
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the API Key repository.
pub struct ApiKeyRepo;

#[async_trait]
impl Repository<ApiKey> for ApiKeyRepo {
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<ApiKey>, OidcError> {
        todo!("implement api_key find_by_id")
    }

    async fn create(&self, _entity: &ApiKey) -> Result<(), OidcError> {
        todo!("implement api_key create")
    }

    async fn update(&self, _entity: &ApiKey) -> Result<(), OidcError> {
        todo!("implement api_key update")
    }

    async fn delete(&self, _id: Uuid) -> Result<(), OidcError> {
        todo!("implement api_key delete")
    }
}
