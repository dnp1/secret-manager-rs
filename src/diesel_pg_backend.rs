//! PostgreSQL-backed `SecretBackend` implementation using Diesel.

use crate::backend::{KeyRecord, SecretBackend};
use crate::rotator::SecretRotationBackend;
use crate::pg_queries::*;
use async_trait::async_trait;
use diesel::sql_types::{Bytea, SmallInt, Timestamptz};
use diesel::{sql_query, QueryableByName};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use std::time::SystemTime;
use jiff::Timestamp;
use jiff_diesel::{Timestamp as DieselTimestamp, ToDiesel};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DieselPgSecretBackendError {
    #[error("connection pool error: {0}")]
    Pool(String),
    #[error("query error: {0}")]
    Query(#[from] diesel::result::Error),
}

#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    id: i64,
    #[diesel(sql_type = SmallInt)]
    version: i16,
    #[diesel(sql_type = Bytea)]
    key_bytes: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DieselTimestamp,
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
pub struct DieselPgSecretBackend {
    pool: Pool<AsyncPgConnection>,
}

impl DieselPgSecretBackend {
    pub fn new(pool: Pool<AsyncPgConnection>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecretBackend for DieselPgSecretBackend {
    type Error = DieselPgSecretBackendError;

    async fn load_all(&self, group_id: Uuid) -> Result<Vec<KeyRecord>, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let rows: Vec<KeyRow> = sql_query(LOAD_ALL_QUERY)
            .bind::<diesel::sql_types::Uuid, _>(group_id)
            .get_results(&mut conn)
            .await?;
        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }

    async fn poll_new(&self, group_id: Uuid, since_time: SystemTime, since_id: i64) -> Result<Vec<KeyRecord>, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let since_jiff = Timestamp::try_from(since_time).map_err(|e| diesel::result::Error::SerializationError(Box::new(e)))?;
        let rows: Vec<KeyRow> = sql_query(POLL_NEW_QUERY)
            .bind::<diesel::sql_types::Uuid, _>(group_id)
            .bind::<Timestamptz, _>(since_jiff.to_diesel())
            .bind::<diesel::sql_types::BigInt, _>(since_id)
            .get_results(&mut conn)
            .await?;
        Ok(rows.into_iter().map(KeyRecord::from).collect())
    }
}

#[derive(QueryableByName)]
struct KeyInfoRow {
    #[diesel(sql_type = SmallInt)]
    version: i16,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DieselTimestamp,
}

#[async_trait]
impl SecretRotationBackend for DieselPgSecretBackend {
    type Error = DieselPgSecretBackendError;

    async fn latest_key_info(&self, group_id: Uuid) -> Result<Option<(u8, SystemTime)>, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let rows: Vec<KeyInfoRow> = sql_query(LATEST_KEY_INFO_QUERY)
            .bind::<diesel::sql_types::Uuid, _>(group_id)
            .get_results(&mut conn)
            .await?;
        Ok(rows.into_iter().next().map(|r| (r.version as u8, r.activated_at.to_jiff().into())))
    }

    async fn try_insert_key(&self, group_id: Uuid, expected_version: Option<u8>, new_version: u8, key_bytes: &[u8], activated_at: SystemTime) -> Result<bool, Self::Error> {
        let mut conn = self.pool.get().await.map_err(|e| DieselPgSecretBackendError::Pool(e.to_string()))?;
        let key_bytes_owned = key_bytes.to_vec();
        let activated_at_jiff = Timestamp::try_from(activated_at).map_err(|e| diesel::result::Error::SerializationError(Box::new(e)))?;
        let activated_at_diesel = activated_at_jiff.to_diesel();

        let inserted = conn.transaction(|conn| {
            Box::pin(async move {
                sql_query(ADVISORY_LOCK_QUERY).bind::<diesel::sql_types::Uuid, _>(group_id).execute(conn).await?;
                let rows: Vec<KeyInfoRow> = sql_query(LATEST_KEY_INFO_QUERY).bind::<diesel::sql_types::Uuid, _>(group_id).get_results(conn).await?;
                let current_version = rows.into_iter().next().map(|r| r.version as u8);
                if current_version != expected_version { return Ok::<bool, diesel::result::Error>(false); }
                let rows_affected = sql_query(INSERT_KEY_QUERY)
                    .bind::<diesel::sql_types::Uuid, _>(group_id)
                    .bind::<SmallInt, _>(new_version as i16)
                    .bind::<Bytea, _>(key_bytes_owned.as_slice())
                    .bind::<Timestamptz, _>(activated_at_diesel)
                    .execute(conn)
                    .await?;
                Ok(rows_affected > 0)
            })
        }).await?;
        Ok(inserted)
    }
}
