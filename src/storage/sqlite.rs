use super::{InjectRule, RateLimitConfig, TenantConfigStore, UpstreamConfig};
use crate::error::StoreError;
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Row, Sqlite};
use std::str::FromStr;
use url::Url;

/// SQLite-based implementation of `TenantConfigStore`.
#[derive(Debug, Clone)]
pub struct SqliteTenantStore {
    pool: Pool<Sqlite>,
    allow_insecure: bool,
}

impl SqliteTenantStore {
    /// Connect to SQLite and initialize tables.
    pub async fn new(db_path: &str, allow_insecure: bool) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(db_path)
            .map_err(|e| StoreError::Database(format!("invalid sqlite path '{db_path}': {e}")))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| StoreError::Database(format!("failed to connect to sqlite: {e}")))?;

        let store = Self {
            pool,
            allow_insecure,
        };
        store.init_schema().await?;
        Ok(store)
    }

    async fn init_schema(&self) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS upstreams (
                tenant_id TEXT NOT NULL,
                upstream TEXT NOT NULL,
                base_url TEXT NOT NULL,
                inject_json TEXT NOT NULL,
                rate_limit_rpm INTEGER NOT NULL,
                rate_limit_burst INTEGER NOT NULL,
                timeout_secs INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, upstream)
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(format!("failed to create upstreams table: {e}")))?;

        Ok(())
    }

    /// Insert or update an upstream config.
    pub async fn upsert(&self, config: &UpstreamConfig) -> Result<(), StoreError> {
        config
            .validate(self.allow_insecure)
            .map_err(|e| StoreError::Database(format!("validation failed: {e}")))?;

        let inject_json = serde_json::to_string(&config.inject)
            .map_err(|e| StoreError::Database(format!("failed to serialize inject: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO upstreams (
                tenant_id, upstream, base_url, inject_json,
                rate_limit_rpm, rate_limit_burst, timeout_secs
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, upstream) DO UPDATE SET
                base_url = excluded.base_url,
                inject_json = excluded.inject_json,
                rate_limit_rpm = excluded.rate_limit_rpm,
                rate_limit_burst = excluded.rate_limit_burst,
                timeout_secs = excluded.timeout_secs;
            "#,
        )
        .bind(&config.tenant_id)
        .bind(&config.upstream)
        .bind(config.base_url.as_str())
        .bind(inject_json)
        .bind(config.rate_limit.rpm as i64)
        .bind(config.rate_limit.burst as i64)
        .bind(config.timeout_secs as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Database(format!("failed to upsert upstream: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl TenantConfigStore for SqliteTenantStore {
    async fn get_upstream(
        &self,
        tenant_id: &str,
        upstream: &str,
    ) -> Result<Option<UpstreamConfig>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT base_url, inject_json, rate_limit_rpm, rate_limit_burst, timeout_secs
            FROM upstreams
            WHERE tenant_id = ? AND upstream = ?;
            "#,
        )
        .bind(tenant_id)
        .bind(upstream)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Database(format!("failed to fetch upstream from sqlite: {e}")))?;

        match row {
            Some(r) => {
                let base_url_str: String = r.get(0);
                let inject_json_str: String = r.get(1);
                let rpm: i64 = r.get(2);
                let burst: i64 = r.get(3);
                let timeout_secs: i64 = r.get(4);

                let base_url = Url::parse(&base_url_str).map_err(|e| {
                    StoreError::Database(format!("corrupt base_url in sqlite: {e}"))
                })?;

                let inject: Vec<InjectRule> =
                    serde_json::from_str(&inject_json_str).map_err(|e| {
                        StoreError::Database(format!("corrupt inject_json in sqlite: {e}"))
                    })?;

                let config = UpstreamConfig {
                    tenant_id: tenant_id.to_string(),
                    upstream: upstream.to_string(),
                    base_url,
                    inject,
                    rate_limit: RateLimitConfig {
                        rpm: rpm as u32,
                        burst: burst as u32,
                    },
                    timeout_secs: timeout_secs as u64,
                };

                config
                    .validate(self.allow_insecure)
                    .map_err(|e| StoreError::Database(format!("invalid stored config: {e}")))?;

                Ok(Some(config))
            }
            None => Ok(None),
        }
    }
}
