use parking_lot::RwLock;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Internal ring-buffer state
// ---------------------------------------------------------------------------

struct SecretInner<const V: usize, const S: usize> {
    /// Indexed by version (u8 cast to usize). Slot is `None` until first written.
    keys: [Option<[u8; S]>; V],
    current_version: u8,
}

// ---------------------------------------------------------------------------
// Public thread-safe wrapper
// ---------------------------------------------------------------------------

/// An in-memory ring buffer of versioned secret keys, safe for concurrent use.
pub struct SecretGroup<const V: usize = 256, const S: usize = 32> {
    inner: RwLock<SecretInner<V, S>>,
    /// Broadcasts the new `current_version` whenever `apply` is called.
    rotation_tx: watch::Sender<u8>,
}

impl<const V: usize, const S: usize> SecretGroup<V, S> {
    /// Create a new `SecretGroup` pre-populated with one key at `version`.
    pub fn new(version: u8, initial_key: [u8; S]) -> Self {
        assert!(
            (version as usize) < V,
            "version {} out of range for ring buffer of size {V}",
            version
        );
        let (rotation_tx, _initial_rx) = watch::channel(version);

        let mut keys: [Option<[u8; S]>; V] = std::array::from_fn(|_| None);
        keys[version as usize] = Some(initial_key);

        Self {
            inner: RwLock::new(SecretInner { keys, current_version: version }),
            rotation_tx,
        }
    }

    /// Return `(current_version, key_bytes)`.
    pub fn current(&self) -> (u8, [u8; S]) {
        let inner = self.inner.read();
        let v = inner.current_version;
        let key = inner.keys[v as usize]
            .expect("current_version slot must always be populated");
        (v, key)
    }

    /// Look up a key by version. Returns `None` for slots that have never been written.
    pub fn resolve(&self, version: u8) -> Option<[u8; S]> {
        self.inner.read().keys[version as usize]
    }

    /// Subscribe to rotation events.
    pub fn subscribe(&self) -> watch::Receiver<u8> {
        self.rotation_tx.subscribe()
    }

    /// Install a key at `version` without making it the `current` signing key.
    pub fn store_key(&self, version: u8, key: [u8; S]) {
        assert!(
            (version as usize) < V,
            "version {} out of range for ring buffer of size {V}",
            version
        );
        let mut inner = self.inner.write();
        inner.keys[version as usize] = Some(key);
    }

    /// Advance the `current_version` to `version` and notify subscribers.
    pub fn promote(&self, version: u8) {
        assert!(
            (version as usize) < V,
            "version {} out of range for ring buffer of size {V}",
            version
        );
        {
            let mut inner = self.inner.write();
            if inner.keys[version as usize].is_none() {
                panic!("cannot promote version {version} before it is stored");
            }
            inner.current_version = version;
        } // release write lock before notifying subscribers
        let _ = self.rotation_tx.send(version);
    }

    /// Combined operation: store the key and immediately promote it to current.
    pub fn apply(&self, version: u8, key: [u8; S]) {
        self.store_key(version, key);
        self.promote(version);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const KEY_A: [u8; 32] = [1u8; 32];
    const KEY_B: [u8; 32] = [2u8; 32];

    #[test]
    fn new_returns_initial_key_as_current() {
        let sg = SecretGroup::<256, 32>::new(0, KEY_A);
        let (v, k) = sg.current();
        assert_eq!(v, 0);
        assert_eq!(k, KEY_A);
    }

    #[test]
    fn resolve_returns_none_for_unpopulated_slot() {
        let sg = SecretGroup::<256, 32>::new(0, KEY_A);
        assert!(sg.resolve(1).is_none());
        assert!(sg.resolve(255).is_none());
    }

    #[test]
    fn resolve_returns_some_for_populated_slot() {
        let sg = SecretGroup::<256, 32>::new(0, KEY_A);
        assert_eq!(sg.resolve(0), Some(KEY_A));
    }

    #[test]
    fn apply_updates_current_and_ring() {
        let sg = SecretGroup::<256, 32>::new(0, KEY_A);
        sg.apply(1, KEY_B);
        let (v, k) = sg.current();
        assert_eq!(v, 1);
        assert_eq!(k, KEY_B);
        assert_eq!(sg.resolve(0), Some(KEY_A));
        assert_eq!(sg.resolve(1), Some(KEY_B));
    }

    #[tokio::test]
    async fn concurrent_reads_during_apply_are_safe() {
        let sg = Arc::new(SecretGroup::<256, 32>::new(0, KEY_A));
        let sg2 = Arc::clone(&sg);

        let reader = tokio::spawn(async move {
            for _ in 0..1000 {
                let _ = sg2.current();
                let _ = sg2.resolve(0);
                let _ = sg2.resolve(1);
                tokio::task::yield_now().await;
            }
        });

        for i in 0u8..10 {
            sg.apply(i, KEY_B);
        }

        reader.await.expect("reader must not panic");
    }
}
