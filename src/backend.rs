use async_trait::async_trait;
use std::time::SystemTime;
use uuid::Uuid;

/// The minimum representable timestamp — used as the initial poll cursor
/// when no keys have been loaded yet.
pub(super) const EPOCH_CURSOR: SystemTime = SystemTime::UNIX_EPOCH;

/// A versioned secret key record as returned by a `SecretBackend`.
#[derive(Clone)]
pub struct KeyRecord {
    /// Monotonic database ID, used as a tie-breaker for polling cursors.
    pub id: i64,
    /// Ring-buffer slot index (fits in `u8` for the default 256-slot ring).
    pub version: u8,
    /// Raw key bytes. The consumer is responsible for validating the length.
    pub key_bytes: Vec<u8>,
    /// When this key became (or will become) active.
    pub activated_at: SystemTime,
}

/// Storage backend for key rotation.
///
/// Implementors provide two operations:
/// - `load_all` — full scan used for initial hydration at startup.
/// - `poll_new` — incremental check used by the background syncer.
///
/// The trait is intentionally minimal: it does not expose key creation or
/// deletion, which are administrative operations performed out-of-band.
///
/// # Implementations provided
/// - [`PgSecretBackend`](crate::PgSecretBackend) (feature `postgres`) — PostgreSQL via diesel-async.
#[async_trait]
pub trait SecretBackend: Send + Sync + 'static {
    /// The error type returned on backend failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load **all** active keys for `group_id`, ordered by `activated_at` ascending.
    /// Used once at startup to hydrate the in-memory ring buffer.
    async fn load_all(&self, group_id: Uuid) -> Result<Vec<KeyRecord>, Self::Error>;

    /// Return all keys newer than the provided cursor, ordered by
    /// `activated_at` ascending.
    ///
    /// `(since_time, since_id)` forms a stable cursor that avoids skipping keys
    /// if multiple records share the exact same `activated_at` timestamp.
    async fn poll_new(
        &self,
        group_id: Uuid,
        since_time: SystemTime,
        since_id: i64,
    ) -> Result<Vec<KeyRecord>, Self::Error>;
}
