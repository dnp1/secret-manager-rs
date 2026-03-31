mod backend;
mod manager;
#[cfg(feature = "postgres")]
mod pg_backend;
mod rotator;
mod secret_rotation;
mod syncer;

pub use backend::{KeyRecord, SecretBackend};
pub use manager::SecretManager;
#[cfg(feature = "postgres")]
pub use pg_backend::{PgSecretBackend, PgSecretBackendError};
pub use rotator::{KeyRotator, SecretRotationBackend};
pub use secret_rotation::SecretGroup;
pub use syncer::SecretSyncer;
