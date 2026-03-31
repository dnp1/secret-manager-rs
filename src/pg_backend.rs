//! PostgreSQL-backed `SecretBackend` implementation.
//!
//! ## Expected table schema
//!
//! Each consuming crate must add a migration creating this table in **its own schema**:
//!
//! ```sql
//! CREATE TABLE {schema}.secret_keys (
//!     id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
//!     key_group      UUID        NOT NULL,
//!     version        SMALLINT    NOT NULL,
//!     key_bytes      BYTEA       NOT NULL,
//!     activated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
//!     CONSTRAINT uq_secret_keys_group_version UNIQUE (key_group, version)
//! );
//!
//! CREATE INDEX idx_secret_keys_group_activation ON {schema}.secret_keys (key_group, activated_at ASC);
//! ```

use crate::backend::{KeyRecord, SecretBackend};
use crate::rotator::SecretRotationBackend;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::sql_types::{Bytea, SmallInt, Timestamptz};
use diesel::{sql_query, QueryableByName};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use std::time::SystemTime;
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PgSecretBackendError {
    #[error("connection pool error: {0}")]
    Pool(String),
    #[error("query error: {0}")]
    Query(#[from] diesel::result::Error),
}

// ---------------------------------------------------------------------------
// Internal query result row
// ---------------------------------------------------------------------------

#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    id: i64,
    #[diesel(sql_type = SmallInt)]
    version: i16,
    #[diesel(sql_type = Bytea)]
    key_bytes: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DateTime<Utc>,
}

impl From<KeyRow> for KeyRecord {
    fn from(r: KeyRow) -> Self {
        KeyRecord {
            id: r.id,
            version: r.version as u8,
            key_bytes: r.key_bytes,
            activated_at: SystemTime::from(r.activated_at),
        }
    }
}

// ---------------------------------------------------------------------------
// PgSecretBackend
// ---------------------------------------------------------------------------

/// A `SecretBackend` backed by a PostgreSQL connection pool (diesel-async / bb8).
#[derive(Clone)]
pub struct PgSecretBackend {
    pool: Pool<AsyncPgConnection>,
}

impl PgSecretBackend {
    pub fn new(pool: Pool<AsyncPgConnection>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecretBackend for PgSecretBackend {
    type Error = PgSecretBackendError;

    async fn load_all(&self, group_id: Uuid) -> Result<Vec<KeyRecord>, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("SecretBackend pool error: {e}");
            PgSecretBackendError::Pool(e.to_string())
        })?;

        let rows: Vec<KeyRow> = sql_query(
            "SELECT id, version, key_bytes, activated_at \
             FROM secret_keys \
             WHERE key_group = $1 \
             ORDER BY activated_at ASC, id ASC",
        )
        .bind::<diesel::sql_types::Uuid, _>(group_id)
        .get_results(&mut conn)
        .await?;

        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }

    async fn poll_new(
        &self,
        group_id: Uuid,
        since_time: SystemTime,
        since_id: i64,
    ) -> Result<Vec<KeyRecord>, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("SecretBackend pool error: {e}");
            PgSecretBackendError::Pool(e.to_string())
        })?;

        let rows: Vec<KeyRow> = sql_query(
            "SELECT id, version, key_bytes, activated_at \
             FROM secret_keys \
             WHERE key_group = $1 AND (activated_at, id) > ($2, $3) \
             ORDER BY activated_at ASC, id ASC",
        )
        .bind::<diesel::sql_types::Uuid, _>(group_id)
        .bind::<Timestamptz, _>(DateTime::<Utc>::from(since_time))
        .bind::<diesel::sql_types::BigInt, _>(since_id)
        .get_results(&mut conn)
        .await?;

        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }
}

// ---------------------------------------------------------------------------
// SecretRotationBackend — write-side impl
// ---------------------------------------------------------------------------

/// Lightweight row for queries that only need `version` + `activated_at`.
#[derive(QueryableByName)]
struct KeyInfoRow {
    #[diesel(sql_type = SmallInt)]
    version: i16,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DateTime<Utc>,
}

#[async_trait]
impl SecretRotationBackend for PgSecretBackend {
    type Error = PgSecretBackendError;

    async fn latest_key_info(
        &self,
        group_id: Uuid,
    ) -> Result<Option<(u8, SystemTime)>, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("SecretRotationBackend pool error: {e}");
            PgSecretBackendError::Pool(e.to_string())
        })?;

        let rows: Vec<KeyInfoRow> = sql_query(
            "SELECT version, activated_at \
             FROM secret_keys \
             WHERE key_group = $1 \
             ORDER BY activated_at DESC \
             LIMIT 1",
        )
        .bind::<diesel::sql_types::Uuid, _>(group_id)
        .get_results(&mut conn)
        .await?;

        Ok(rows.into_iter().next().map(|r| (r.version as u8, SystemTime::from(r.activated_at))))
    }

    async fn try_insert_key(
        &self,
        group_id: Uuid,
        expected_version: Option<u8>,
        new_version: u8,
        key_bytes: &[u8],
        activated_at: SystemTime,
    ) -> Result<bool, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("SecretRotationBackend pool error: {e}");
            PgSecretBackendError::Pool(e.to_string())
        })?;

        let key_bytes_owned = key_bytes.to_vec();

        let inserted = conn
            .transaction(|conn| {
                Box::pin(async move {
                    sql_query(
                        "SELECT pg_advisory_xact_lock(hashtext($1::text)::bigint)",
                    )
                    .bind::<diesel::sql_types::Uuid, _>(group_id)
                    .execute(conn)
                    .await?;

                    let rows: Vec<KeyInfoRow> = sql_query(
                        "SELECT version, activated_at \
                         FROM secret_keys \
                         WHERE key_group = $1 \
                         ORDER BY activated_at DESC \
                         LIMIT 1",
                    )
                    .bind::<diesel::sql_types::Uuid, _>(group_id)
                    .get_results(conn)
                    .await?;

                    let current_version = rows.into_iter().next().map(|r| r.version as u8);

                    if current_version != expected_version {
                        return Ok::<bool, diesel::result::Error>(false);
                    }

                    let rows_affected = sql_query(
                        "INSERT INTO secret_keys \
                         (key_group, version, key_bytes, activated_at) \
                         VALUES ($1, $2, $3, $4) \
                         ON CONFLICT (key_group, version) DO UPDATE SET \
                            key_bytes = EXCLUDED.key_bytes, \
                            activated_at = EXCLUDED.activated_at",
                    )
                    .bind::<diesel::sql_types::Uuid, _>(group_id)
                    .bind::<SmallInt, _>(new_version as i16)
                    .bind::<Bytea, _>(key_bytes_owned.as_slice())
                    .bind::<Timestamptz, _>(DateTime::<Utc>::from(activated_at))
                    .execute(conn)
                    .await?;

                    Ok(rows_affected > 0)
                })
            })
            .await?;

        Ok(inserted)
    }
}
