//! PostgreSQL-backed `SecretBackend` implementation using SQLx.

use crate::backend::{KeyRecord, SecretBackend};
use crate::rotator::SecretRotationBackend;
use crate::pg_queries::*;
use async_trait::async_trait;
use std::time::SystemTime;
use jiff::Timestamp;
use jiff_sqlx::{Timestamp as SqlxTimestamp, ToSqlx};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SqlxPgSecretBackendError {
    #[error("query error: {0}")]
    Query(#[from] sqlx::Error),
    #[error("timestamp conversion error: {0}")]
    Timestamp(String),
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    id: i64,
    version: i16,
    key_bytes: Vec<u8>,
    activated_at: SqlxTimestamp,
}

impl From<KeyRow> for KeyRecord {
    fn from(r: KeyRow) -> Self {
        KeyRecord {
            id: r.id,
            version: r.version as u8,
            key_bytes: r.key_bytes,
            activated_at: r.activated_at.to_jiff().into(),
        }
    }
}

#[derive(Clone)]
pub struct SqlxPgSecretBackend {
    pool: PgPool,
}

impl SqlxPgSecretBackend {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecretBackend for SqlxPgSecretBackend {
    type Error = SqlxPgSecretBackendError;

    async fn load_all(&self, group_id: Uuid) -> Result<Vec<KeyRecord>, Self::Error> {
        let rows = sqlx::query_as::<_, KeyRow>(LOAD_ALL_QUERY).bind(group_id).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }

    async fn poll_new(&self, group_id: Uuid, since_time: SystemTime, since_id: i64) -> Result<Vec<KeyRecord>, Self::Error> {
        let since_jiff = Timestamp::try_from(since_time).map_err(|e| SqlxPgSecretBackendError::Timestamp(e.to_string()))?;
        let rows = sqlx::query_as::<_, KeyRow>(POLL_NEW_QUERY).bind(group_id).bind(since_jiff.to_sqlx()).bind(since_id).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }
}

#[derive(sqlx::FromRow)]
struct KeyInfoRow {
    version: i16,
    activated_at: SqlxTimestamp,
}

#[async_trait]
impl SecretRotationBackend for SqlxPgSecretBackend {
    type Error = SqlxPgSecretBackendError;

    async fn latest_key_info(&self, group_id: Uuid) -> Result<Option<(u8, SystemTime)>, Self::Error> {
        let row = sqlx::query_as::<_, KeyInfoRow>(LATEST_KEY_INFO_QUERY).bind(group_id).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| (r.version as u8, r.activated_at.to_jiff().into())))
    }

    async fn try_insert_key(&self, group_id: Uuid, expected_version: Option<u8>, new_version: u8, key_bytes: &[u8], activated_at: SystemTime) -> Result<bool, Self::Error> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        sqlx::query(ADVISORY_LOCK_QUERY).bind(group_id).execute(&mut *tx).await?;
        let row = sqlx::query_as::<_, KeyInfoRow>(LATEST_KEY_INFO_QUERY).bind(group_id).fetch_optional(&mut *tx).await?;
        let current_version = row.map(|r| r.version as u8);
        if current_version != expected_version { return Ok(false); }
        let activated_at_jiff = Timestamp::try_from(activated_at).map_err(|e| SqlxPgSecretBackendError::Timestamp(e.to_string()))?;
        sqlx::query(INSERT_KEY_QUERY).bind(group_id).bind(new_version as i16).bind(key_bytes).bind(activated_at_jiff.to_sqlx()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
}
