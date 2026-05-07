use async_trait::async_trait;
use oidc_core::models::Realm;
use oidc_core::traits::Repository;
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the Realm repository.
pub struct RealmRepo;

#[async_trait]
impl Repository<Realm> for RealmRepo {
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<Realm>, OidcError> {
        todo!("implement realm find_by_id")
    }

    async fn create(&self, _entity: &Realm) -> Result<(), OidcError> {
        todo!("implement realm create")
    }

    async fn update(&self, _entity: &Realm) -> Result<(), OidcError> {
        todo!("implement realm update")
    }

    async fn delete(&self, _id: Uuid) -> Result<(), OidcError> {
        todo!("implement realm delete")
    }
}
