use crate::errors::OidcError;
use async_trait::async_trait;

/// Generic repository trait for domain entities.
#[async_trait]
pub trait Repository<T>: Send + Sync {
    /// Find an entity by its primary key.
    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<T>, OidcError>;

    /// Insert a new entity.
    async fn create(&self, entity: &T) -> Result<(), OidcError>;

    /// Update an existing entity.
    async fn update(&self, entity: &T) -> Result<(), OidcError>;

    /// Soft-delete an entity by ID.
    async fn delete(&self, id: uuid::Uuid) -> Result<(), OidcError>;
}
