use crate::error::StoreError;
use crate::storage::{TenantConfigStore, UpstreamConfig};
use async_trait::async_trait;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

/// Cached wrapper around `TenantConfigStore`.
#[derive(Clone)]
pub struct CachedTenantStore {
    inner: Arc<dyn TenantConfigStore>,
    cache: Cache<(String, String), Option<UpstreamConfig>>,
}

impl CachedTenantStore {
    pub fn new(inner: Arc<dyn TenantConfigStore>, ttl_secs: u64, max_entries: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_entries)
            .build();

        Self { inner, cache }
    }
}

#[async_trait]
impl TenantConfigStore for CachedTenantStore {
    async fn get_upstream(
        &self,
        tenant_id: &str,
        upstream: &str,
    ) -> Result<Option<UpstreamConfig>, StoreError> {
        let key = (tenant_id.to_string(), upstream.to_string());

        let inner = self.inner.clone();
        let t_id = tenant_id.to_string();
        let u_str = upstream.to_string();

        let result = self
            .cache
            .try_get_with(key, async move { inner.get_upstream(&t_id, &u_str).await })
            .await;

        match result {
            Ok(opt) => Ok(opt),
            Err(e) => Err(StoreError::Database(format!("{e}"))),
        }
    }
}
