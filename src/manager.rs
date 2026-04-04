use crate::backend::SecretBackend;
use crate::rotator::{KeyRotator, SecretRotationBackend};
use crate::secret_rotation::{InMemorySecretGroup, SecretGroup};
use crate::syncer::SecretSyncer;

use crate::util::generate_secret;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct SecretManager<B, const V: usize = 256, const S: usize = 32>
where
    B: SecretBackend + SecretRotationBackend + Clone,
{
    group_id: Uuid,
    group: Arc<InMemorySecretGroup<V, S>>,
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
    pub fn new(
        group_id: Uuid,
        group: Arc<InMemorySecretGroup<V, S>>,
        backend: B,
        rotation_interval: Duration,
        propagation_delay: Duration,
        poll_interval: Option<Duration>,
        generate_key: Option<fn() -> [u8; S]>,
    ) -> Self {
        let generate_key = generate_key.unwrap_or(generate_secret::<S>);
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

    pub async fn start(self, token: CancellationToken) -> Result<(), <B as SecretBackend>::Error> {
        let generate_key = Arc::clone(&self.generate_key);

        let syncer = SecretSyncer::new(
            self.group_id,
            Arc::clone(&self.group),
            self.backend.clone(),
            self.rotation_interval,
            self.poll_interval,
        );

        let cursor = syncer.initial_load(&token).await?;

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

impl<B, const V: usize, const S: usize> SecretGroup<V, S> for SecretManager<B, V, S>
where
    B: SecretBackend + SecretRotationBackend + Clone,
{
    fn current(&self) -> (u8, [u8; S]) {
        self.group.current()
    }

    fn resolve(&self, version: u8) -> Option<[u8; S]> {
        self.group.resolve(version)
    }
}

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
            Ok(self
                .poll_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default())
        }
    }

    #[async_trait]
    impl SecretRotationBackend for MockBackend {
        type Error = MockError;
        async fn latest_key_info(
            &self,
            _group_id: Uuid,
        ) -> Result<Option<(u8, SystemTime)>, MockError> {
            Ok(self
                .latest_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(None))
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

    #[tokio::test]
    async fn start_hydrates_group_and_returns_ok() {
        let backend = MockBackend {
            load_response: vec![KeyRecord {
                id: 1,
                version: 0,
                key_bytes: vec![0xAA; 32],
                activated_at: SystemTime::now() - Duration::from_secs(300),
            }],
            poll_responses: Arc::new(Mutex::new(VecDeque::new())),
            latest_responses: Arc::new(Mutex::new(VecDeque::new())),
        };
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(0, [0u8; 32]));
        let manager = SecretManager::new(
            Uuid::nil(),
            Arc::clone(&group),
            backend,
            Duration::from_secs(3600),
            Duration::from_secs(10),
            None,
            Some(|| [0xFFu8; 32]),
        );
        manager
            .start(CancellationToken::new())
            .await
            .expect("start should succeed");
        let (v, _) = group.current();
        assert_eq!(v, 0);
    }

    #[test]
    fn manager_implements_secret_group() {
        let backend = MockBackend {
            load_response: vec![],
            poll_responses: Arc::new(Mutex::new(VecDeque::new())),
            latest_responses: Arc::new(Mutex::new(VecDeque::new())),
        };
        let group = Arc::new(InMemorySecretGroup::<256, 32>::new(42, [0xEEu8; 32]));
        let manager = SecretManager::new(
            Uuid::nil(),
            group,
            backend,
            Duration::from_secs(3600),
            Duration::from_secs(10),
            None,
            Some(|| [0u8; 32]),
        );

        // Treat it as a SecretGroup trait object
        let sg: &dyn SecretGroup<256, 32> = &manager;
        let (v, k) = sg.current();
        assert_eq!(v, 42);
        assert_eq!(k, [0xEEu8; 32]);
    }
}
