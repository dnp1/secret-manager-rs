# Secret Manager Library Context

This crate was migrated from `backend/crates/shared/util/key_rotation`.

### Key Architectural Decisions:
- **Standard Library First:** Use `std::time::SystemTime` and `std::time::Duration` for all internal logic. `chrono` is restricted to `pg_backend.rs` for DB compatibility.
- **Stable Polling Cursor:** `poll_new` must use the `(activated_at, id)` tuple to prevent skipping keys with identical timestamps.
- **Two-Phase Activation:** Keys are `store_key`ed immediately for validation but `promote`d only at `activated_at` for signing.
- **Distributed Safety:** Coordination is handled via PostgreSQL advisory locks and `ON CONFLICT DO UPDATE` for version bucket reuse.
- **Feature Flags:** `postgres` feature enables Diesel/Diesel-Async support.
- **Version Wrapping:** Logic is temporally ordered (`activated_at ASC`), making `u8` version wrap-arounds (255 -> 0) transparent and safe.
- **Dynamic Polling:** Syncer uses a scheduling model: `max((latest_activated_at + rotation_interval) - now + 2s, 5s)` to adapt to rotation frequency.
