use crate::backend::SecretBackend;
use crate::rotator::{KeyRotator, SecretRotationBackend};
use crate::secret_rotation::SecretGroup;
use crate::syncer::SecretSyncer;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// SecretManager
// ---------------------------------------------------------------------------

/// Combined facade for [`SecretSyncer`] + [`KeyRotator`].
///
/// For the common deployment case where you want both a reader (syncer) and a
/// writer (rotator) wired to the same `SecretGroup`, `SecretManager` collapses
/// the boilerplate — constructing the group, sharing an `Arc`, cloning the
/// backend, calling `initial_load`, and spawning two tasks — into a single
/// `new` + `start` pair.
///
/// Both components remain individually usable when needed (e.g. a read-only
/// replica that only runs the syncer, or a custom key generation strategy that
/// wraps `KeyRotator` directly).
pub struct SecretManager<B, const V: usize = 256, const S: usize = 32>
where
    B: SecretBackend + SecretRotationBackend + Clone,
{
    group_id: Uuid,
    group: Arc<SecretGroup<V, S>>,
    backend: B,
    rotation_interval: Duration,
    propagation_delay: Duration,
    poll_interval: Option<Duration>,
    generate_key: Arc<dyn Fn() -> [u8; S] + Send + Sync + 'static>,
}

impl<B, const V: usize, const S: usize> SecretManager<B, V, S>
where
    B: SecretBackend + SecretRotationBackend + Clone,
{
    /// Create a new `SecretManager`.
    ///
    /// - `poll_interval` — how often the syncer polls in the steady state.
    ///   Pass `None` to use the 5-second default.
    /// - `generate_key` — closure that produces a fresh `[u8; S]`. Called
    ///   inside `KeyRotator` on each rotation cycle.
    pub fn new(
        group_id: Uuid,
        group: Arc<SecretGroup<V, S>>,
        backend: B,
        rotation_interval: Duration,
        propagation_delay: Duration,
        poll_interval: Option<Duration>,
        generate_key: impl Fn() -> [u8; S] + Send + Sync + 'static,
    ) -> Self {
        Self {
            group_id,
            group,
            backend,
            rotation_interval,
            propagation_delay,
            poll_interval,
            generate_key: Arc::new(generate_key),
        }
    }

    /// Returns a clone of the shared [`SecretGroup`].
    pub fn group(&self) -> Arc<SecretGroup<V, S>> {
        Arc::clone(&self.group)
    }

    /// Hydrate the key ring, then spawn the syncer and rotator background tasks.
    ///
    /// Returns only after both tasks have been spawned. The tasks run until
    /// `token` is cancelled.
    ///
    /// # Errors
    /// Returns `Err` if `SecretSyncer::initial_load` fails (backend query error).
    pub async fn start(
        self,
        token: CancellationToken,
    ) -> Result<(), <B as SecretBackend>::Error> {
        let generate_key = Arc::clone(&self.generate_key);

        // Build syncer with a clone of the backend (read-only path).
        let syncer = SecretSyncer::new(
            self.group_id,
            Arc::clone(&self.group),
            self.backend.clone(),
            self.rotation_interval,
            self.poll_interval,
        );

        // Initial load — only fallible step; propagate as fatal startup error.
        let cursor = syncer.initial_load(&token).await?;

        // Build rotator with the original backend (write path).
        let rotator = KeyRotator::new(
            self.group_id,
            self.backend,
            self.rotation_interval,
            self.propagation_delay,
            move || (generate_key)(),
        );

        tokio::spawn(syncer.run(token.clone(), cursor));
        tokio::spawn(rotator.run(token));

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KeyRecord;
    use crate::rotator::SecretRotationBackend;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::SystemTime;

    #[derive(Debug)]
    struct MockError;
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }
    impl std::error::Error for MockError {}

    #[derive(Clone)]
    struct MockBackend {
        load_response: Vec<KeyRecord>,
        poll_responses: Arc<Mutex<VecDeque<Vec<KeyRecord>>>>,
        latest_responses: Arc<Mutex<VecDeque<Option<(u8, SystemTime)>>>>,
    }

    impl MockBackend {
        fn new(load_response: Vec<KeyRecord>) -> Self {
            Self {
                load_response,
                poll_responses: Arc::new(Mutex::new(VecDeque::new())),
                latest_responses: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn push_latest(&self, v: Option<(u8, SystemTime)>) {
            self.latest_responses.lock().unwrap().push_back(v);
        }
    }

    #[async_trait]
    impl SecretBackend for MockBackend {
        type Error = MockError;

        async fn load_all(&self, _group_id: Uuid) -> Result<Vec<KeyRecord>, MockError> {
            Ok(self.load_response.clone())
        }

        async fn poll_new(
            &self,
            _group_id: Uuid,
            _since_time: SystemTime,
            _since_id: i64,
        ) -> Result<Vec<KeyRecord>, MockError> {
            Ok(self.poll_responses.lock().unwrap().pop_front().unwrap_or_default())
        }
    }

    #[async_trait]
    impl SecretRotationBackend for MockBackend {
        type Error = MockError;

        async fn latest_key_info(
            &self,
            _group_id: Uuid,
        ) -> Result<Option<(u8, SystemTime)>, MockError> {
            Ok(self.latest_responses.lock().unwrap().pop_front().unwrap_or(None))
        }

        async fn try_insert_key(
            &self,
            _group_id: Uuid,
            _expected_version: Option<u8>,
            _new_version: u8,
            _key_bytes: &[u8],
            _activated_at: SystemTime,
        ) -> Result<bool, MockError> {
            Ok(false)
        }
    }

    fn key_record(version: u8, fill: u8, offset_secs: i64) -> KeyRecord {
        let now = SystemTime::now();
        let activated_at = if offset_secs >= 0 {
            now + Duration::from_secs(offset_secs as u64)
        } else {
            now - Duration::from_secs((-offset_secs) as u64)
        };
        KeyRecord { id: 1, version, key_bytes: vec![fill; 32], activated_at }
    }

    #[tokio::test]
    async fn start_hydrates_group_and_returns_ok() {
        let t_past = SystemTime::now() - Duration::from_secs(300);
        let backend = MockBackend::new(vec![key_record(0, 0xAA, -300)]);
        backend.push_latest(Some((0, t_past)));

        let group = Arc::new(SecretGroup::<256, 32>::new(0, [0u8; 32]));
        let manager = SecretManager::new(
            Uuid::nil(),
            Arc::clone(&group),
            backend,
            Duration::from_secs(3600),
            Duration::from_secs(10),
            Some(Duration::from_millis(50)),
            || [0xFFu8; 32],
        );

        let token = CancellationToken::new();
        manager.start(token.clone()).await.expect("start should succeed");

        tokio::time::sleep(Duration::from_millis(20)).await;

        let (v, k) = group.current();
        assert_eq!(v, 0);
        assert_eq!(k, [0xAAu8; 32]);

        token.cancel();
    }
}
