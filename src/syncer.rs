use crate::backend::{SecretBackend, EPOCH_CURSOR};
use crate::secret_rotation::SecretGroup;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const ROTATION_POLL_BUFFER: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// SecretSyncer
// ---------------------------------------------------------------------------

/// Background task that polls a `SecretBackend` for new key versions and
/// applies them to a shared `SecretGroup`.
pub struct SecretSyncer<B: SecretBackend, const V: usize = 256, const S: usize = 32> {
    group_id: Uuid,
    secret: Arc<SecretGroup<V, S>>,
    backend: B,
    rotation_interval: Duration,
    poll_interval: Duration,
}

impl<B: SecretBackend, const V: usize, const S: usize> SecretSyncer<B, V, S> {
    /// `poll_interval` — how often to poll in the steady state. Pass `None`
    /// to use the 5-second default.
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

    /// Hydrate the ring buffer by loading all keys from the backend.
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

            match <[u8; S]>::try_from(record.key_bytes) {
                Ok(key) => {
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
                Err(_) => warn!(
                    group_id = %self.group_id,
                    version = record.version,
                    expected_len = S,
                    "key_bytes length mismatch during initial_load — skipping"
                ),
            }
        }

        if let Some(v) = latest_active_version {
            self.secret.promote(v);
        }

        info!(
            group_id = %self.group_id,
            count,
            "SecretSyncer initial load complete"
        );
        Ok((max_time, max_id))
    }

    /// Run the polling loop until `token` is cancelled.
    pub async fn run(self, token: CancellationToken, mut cursor: (SystemTime, i64)) {
        loop {
            let now = SystemTime::now();
            let next_expected = cursor.0
                .checked_add(self.rotation_interval)
                .unwrap_or(now);

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

                                match <[u8; S]>::try_from(record.key_bytes) {
                                    Ok(key) => {
                                        self.secret.store_key(record.version, key);
                                        
                                        let now = SystemTime::now();
                                        if record.activated_at <= now {
                                            self.secret.promote(record.version);
                                            info!(
                                                group_id = %self.group_id,
                                                version = record.version,
                                                "key rotated (immediate)"
                                            );
                                        } else {
                                            self.schedule_promotion(record.version, record.activated_at, token.clone());
                                            info!(
                                                group_id = %self.group_id,
                                                version = record.version,
                                                activated_at = ?record.activated_at,
                                                "key rotated (scheduled)"
                                            );
                                        }
                                    }
                                    Err(_) => warn!(
                                        group_id = %self.group_id,
                                        version = record.version,
                                        expected_len = S,
                                        "key_bytes length mismatch during poll — skipping"
                                    ),
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                group_id = %self.group_id,
                                error = %e,
                                "SecretSyncer poll failed"
                            );
                            if self.sleep_or_cancel(Duration::from_secs(30), &token).await {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    fn schedule_promotion(&self, version: u8, activated_at: SystemTime, token: CancellationToken) {
        let secret = Arc::clone(&self.secret);
        let group_id = self.group_id;

        tokio::spawn(async move {
            let now = SystemTime::now();
            if let Ok(sleep_dur) = activated_at.duration_since(now) {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(sleep_dur) => {}
                }
            }
            secret.promote(version);
            info!(
                group_id = %group_id,
                version = version,
                "key promoted to current"
            );
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
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }
    impl std::error::Error for MockError {}

    struct MockBackend {
        load_response: Vec<KeyRecord>,
        poll_responses: Mutex<VecDeque<Vec<KeyRecord>>>,
    }

    impl MockBackend {
        fn with_load(records: Vec<KeyRecord>) -> Self {
            Self {
                load_response: records,
                poll_responses: Mutex::new(VecDeque::new()),
            }
        }

        fn push_poll(&self, records: Vec<KeyRecord>) {
            self.poll_responses.lock().unwrap().push_back(records);
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

    fn key_record_at(id: i64, version: u8, fill: u8, activated_at: SystemTime) -> KeyRecord {
        KeyRecord {
            id,
            version,
            key_bytes: vec![fill; 32],
            activated_at,
        }
    }

    #[tokio::test]
    async fn initial_load_applies_all_keys_and_promotes_latest_active() {
        let now = SystemTime::now();
        let t0 = now - Duration::from_secs(600);
        let t1 = now - Duration::from_secs(300);
        let t2 = now + Duration::from_secs(300); // Future key
        
        let backend = MockBackend::with_load(vec![
            key_record_at(1, 0, 0xAA, t0),
            key_record_at(2, 1, 0xBB, t1),
            key_record_at(3, 2, 0xCC, t2),
        ]);
        let group = Arc::new(SecretGroup::<256, 32>::new(0, [0u8; 32]));
        let syncer = SecretSyncer::new(
            Uuid::nil(),
            Arc::clone(&group),
            backend,
            Duration::from_secs(3600),
            None,
        );

        let token = CancellationToken::new();
        let cursor = syncer.initial_load(&token).await.unwrap();

        let (v, k) = group.current();
        assert_eq!(v, 1);
        assert_eq!(k, [0xBBu8; 32]);
        assert_eq!(group.resolve(2), Some([0xCCu8; 32]));
        assert_eq!(cursor, (t2, 3));
    }
}
