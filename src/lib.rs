mod backend;
#[cfg(feature = "pg-diesel-async")]
mod diesel_pg_backend;
mod manager;
#[cfg(any(feature = "pg-diesel-async", feature = "pg-sqlx"))]
mod pg_queries;
mod rotator;
mod secret_rotation;
#[cfg(feature = "pg-sqlx")]
mod sqlx_pg_backend;
mod syncer;
mod util;

pub use backend::{KeyRecord, SecretBackend};
#[cfg(any(test, feature = "pg-diesel-async"))]
pub use diesel_pg_backend::{DieselPgSecretBackend, DieselPgSecretBackendError};
pub use manager::SecretManager;
pub use rotator::{KeyRotator, SecretRotationBackend};
pub use secret_rotation::{InMemorySecretGroup, SecretGroup};
#[cfg(any(test, feature = "pg-sqlx"))]
pub use sqlx_pg_backend::{SqlxPgSecretBackend, SqlxPgSecretBackendError};
pub use syncer::SecretSyncer;
