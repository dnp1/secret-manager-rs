mod backend;
mod manager;
#[cfg(feature = "postgres")]
mod diesel_pg_backend;
#[cfg(feature = "postgres")]
mod sqlx_pg_backend;
#[cfg(feature = "postgres")]
mod pg_queries;
mod rotator;
mod secret_rotation;
mod syncer;

pub use backend::{KeyRecord, SecretBackend};
pub use manager::SecretManager;
#[cfg(feature = "postgres")]
pub use diesel_pg_backend::{DieselPgSecretBackend, DieselPgSecretBackendError};
#[cfg(feature = "postgres")]
pub use sqlx_pg_backend::{SqlxPgSecretBackend, SqlxPgSecretBackendError};
pub use rotator::{KeyRotator, SecretRotationBackend};
pub use secret_rotation::SecretGroup;
pub use syncer::SecretSyncer;
