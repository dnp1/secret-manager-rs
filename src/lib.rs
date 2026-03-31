mod backend;
mod manager;
#[cfg(feature = "pg-diesel-async")]
mod diesel_pg_backend;
#[cfg(feature = "pg-sqlx")]
mod sqlx_pg_backend;
#[cfg(any(feature = "pg-diesel-async", feature = "pg-sqlx"))]
mod pg_queries;
mod rotator;
mod secret_rotation;
mod syncer;

pub use backend::{KeyRecord, SecretBackend};
pub use manager::SecretManager;
#[cfg(feature = "pg-diesel-async")]
pub use diesel_pg_backend::{DieselPgSecretBackend, DieselPgSecretBackendError};
#[cfg(feature = "pg-sqlx")]
pub use sqlx_pg_backend::{SqlxPgSecretBackend, SqlxPgSecretBackendError};
pub use rotator::{KeyRotator, SecretRotationBackend};
pub use secret_rotation::SecretGroup;
pub use syncer::SecretSyncer;
