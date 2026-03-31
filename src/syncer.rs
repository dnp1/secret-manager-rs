use crate::backend::{SecretBackend, EPOCH_CURSOR};
use crate::secret_rotation::SecretGroup;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const ROTATION_POLL_BUFFER: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// SecretSyncer
// ---------------------------------------------------------------------------

pub struct SecretSyncer<B: SecretBackend, const V: usize = 256, const S: usize = 32> {
    group_id: Uuid,
    secret: Arc<SecretGroup<V, S>>,
    backend: B,
    rotation_interval: Duration,
    poll_interval: Duration,
}

impl<B: SecretBackend, const V: usize, const S: usize> SecretSyncer<B, V, S> {
    pub fn new(
        group_id: Uuid,
        secret: Arc<SecretGroup<V, S>>,
        backend: B,
        rotation_interval: Duration,
        poll_interval: Option<Duration>,
    ) -> Self {
        Self {
            group_id,
            secret,
            backend,
            rotation_interval,
            poll_interval: poll_interval.unwrap_or(DEFAULT_POLL_INTERVAL),
        }
    }

    pub async fn initial_load(&self, token: &CancellationToken) -> Result<(SystemTime, i64), B::Error> {
        let records = self.backend.load_all(self.group_id).await?;
        let count = records.len();
        let mut max_time = EPOCH_CURSOR;
        let mut max_id = 0i64;
        let mut latest_active_version: Option<u8> = None;
        let mut latest_active_at = EPOCH_CURSOR;

        let now = SystemTime::now();

        for record in records {
            if (record.activated_at, record.id) > (max_time, max_id) {
                max_time = record.activated_at;
                max_id = record.id;
            }

            if let Ok(key) = <[u8; S]>::try_from(record.key_bytes) {
                self.secret.store_key(record.version, key);
                if record.activated_at <= now {
                    if record.activated_at >= latest_active_at {
                        latest_active_at = record.activated_at;
                        latest_active_version = Some(record.version);
                    }
                } else {
                    self.schedule_promotion(record.version, record.activated_at, token.clone());
                }
            }
        }

        if let Some(v) = latest_active_version {
            self.secret.promote(v);
        }

        info!(group_id = %self.group_id, count, "SecretSyncer initial load complete");
        Ok((max_time, max_id))
    }

    pub async fn run(self, token: CancellationToken, mut cursor: (SystemTime, i64)) {
        loop {
            let now = SystemTime::now();
            let next_expected = cursor.0.checked_add(self.rotation_interval).unwrap_or(now);

            let sleep_dur = next_expected
                .duration_since(now)
                .ok()
                .map(|d| d + ROTATION_POLL_BUFFER)
                .filter(|&smart| smart < self.poll_interval)
                .unwrap_or(self.poll_interval);

            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    info!(group_id = %self.group_id, "SecretSyncer shutting down");
                    break;
                }
                _ = tokio::time::sleep(sleep_dur) => {
                    match self.backend.poll_new(self.group_id, cursor.0, cursor.1).await {
                        Ok(records) => {
                            for record in records {
                                if (record.activated_at, record.id) > cursor {
                                    cursor = (record.activated_at, record.id);
                                }
                                if let Ok(key) = <[u8; S]>::try_from(record.key_bytes) {
                                    self.secret.store_key(record.version, key);
                                    let now = SystemTime::now();
                                    if record.activated_at <= now {
                                        self.secret.promote(record.version);
                                    } else {
                                        self.schedule_promotion(record.version, record.activated_at, token.clone());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(group_id = %self.group_id, error = %e, "SecretSyncer poll failed");
                            if self.sleep_or_cancel(Duration::from_secs(30), &token).await { break; }
                        }
                    }
                }
            }
        }
    }

    fn schedule_promotion(&self, version: u8, activated_at: SystemTime, token: CancellationToken) {
        let secret = Arc::clone(&self.secret);
        tokio::spawn(async move {
            if let Ok(sleep_dur) = activated_at.duration_since(SystemTime::now()) {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(sleep_dur) => {}
                }
            }
            secret.promote(version);
        });
    }

    async fn sleep_or_cancel(&self, duration: Duration, token: &CancellationToken) -> bool {
        tokio::select! {
            biased;
            _ = token.cancelled() => true,
            _ = tokio::time::sleep(duration) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KeyRecord;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct MockError;
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "mock error") }
    }
    impl std::error::Error for MockError {}

    struct MockBackend {
        load_response: Vec<KeyRecord>,
        poll_responses: Mutex<VecDeque<Vec<KeyRecord>>>,
    }

    impl MockBackend {
        fn with_load(records: Vec<KeyRecord>) -> Self {
            Self { load_response: records, poll_responses: Mutex::new(VecDeque::new()) }
        }
    }

    #[async_trait]
    impl SecretBackend for MockBackend {
        type Error = MockError;
        async fn load_all(&self, _group_id: Uuid) -> Result<Vec<KeyRecord>, MockError> { Ok(self.load_response.clone()) }
        async fn poll_new(&self, _group_id: Uuid, _since_time: SystemTime, _since_id: i64) -> Result<Vec<KeyRecord>, MockError> {
            Ok(self.poll_responses.lock().unwrap().pop_front().unwrap_or_default())
        }
    }

    #[tokio::test]
    async fn initial_load_applies_all_keys_and_promotes_latest_active() {
        let now = SystemTime::now();
        let backend = MockBackend::with_load(vec![
            KeyRecord { id: 1, version: 0, key_bytes: vec![0xAA; 32], activated_at: now - Duration::from_secs(600) },
            KeyRecord { id: 2, version: 1, key_bytes: vec![0xBB; 32], activated_at: now - Duration::from_secs(300) },
        ]);
        let group = Arc::new(SecretGroup::<256, 32>::new(0, [0u8; 32]));
        let syncer = SecretSyncer::new(Uuid::nil(), Arc::clone(&group), backend, Duration::from_secs(3600), None);
        syncer.initial_load(&CancellationToken::new()).await.unwrap();
        let (v, _) = group.current();
        assert_eq!(v, 1);
    }
}
