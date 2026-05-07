use async_trait::async_trait;
use oidc_core::models::User;
use oidc_core::traits::Repository;
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the User repository.
pub struct UserRepo;

#[async_trait]
impl Repository<User> for UserRepo {
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<User>, OidcError> {
        todo!("implement user find_by_id")
    }

    async fn create(&self, _entity: &User) -> Result<(), OidcError> {
        todo!("implement user create")
    }

    async fn update(&self, _entity: &User) -> Result<(), OidcError> {
        todo!("implement user update")
    }

    async fn delete(&self, _id: Uuid) -> Result<(), OidcError> {
        todo!("implement user delete")
    }
}
