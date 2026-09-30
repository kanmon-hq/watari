use super::SecretStore;
use crate::error::SecretError;
use crate::storage::SecretVersion;
use async_trait::async_trait;
use moka::future::Cache;
use secrecy::SecretString;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached wrapper around any SecretStore with single-flight retrieval and stale fallback.
#[derive(Clone)]
pub struct CachedSecretStore {
    inner: Arc<dyn SecretStore>,
    primary_cache: Cache<(String, SecretVersion), SecretString>,
    stale_cache: Cache<(String, SecretVersion), (SecretString, Instant)>,
    max_stale_duration: Duration,
}

impl CachedSecretStore {
    pub fn new(inner: Arc<dyn SecretStore>, ttl_secs: u64, max_stale_secs: u64) -> Self {
        let primary_cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(10000)
            .build();

        let stale_cache = Cache::builder()
            .time_to_live(Duration::from_secs(max_stale_secs))
            .max_capacity(10000)
            .build();

        Self {
            inner,
            primary_cache,
            stale_cache,
            max_stale_duration: Duration::from_secs(max_stale_secs),
        }
    }
}

#[async_trait]
impl SecretStore for CachedSecretStore {
    async fn get(
        &self,
        reference: &str,
        version: &SecretVersion,
    ) -> Result<SecretString, SecretError> {
        let key = (reference.to_string(), version.clone());

        // 1. Check primary cache
        if let Some(cached) = self.primary_cache.get(&key).await {
            return Ok(cached);
        }

        // 2. Single-flight retrieval via try_get_with
        let inner = self.inner.clone();
        let ref_str = reference.to_string();
        let ver_cloned = version.clone();

        let result = self
            .primary_cache
            .try_get_with(key.clone(), async move {
                inner.get(&ref_str, &ver_cloned).await
            })
            .await;

        match result {
            Ok(secret) => {
                // Update stale fallback cache
                self.stale_cache
                    .insert(key, (secret.clone(), Instant::now()))
                    .await;
                Ok(secret)
            }
            Err(err_arc) => {
                // Check stale fallback cache
                if let Some((stale_secret, cached_at)) = self.stale_cache.get(&key).await {
                    if cached_at.elapsed() <= self.max_stale_duration {
                        tracing::warn!(
                            secret_ref = %reference,
                            elapsed_secs = cached_at.elapsed().as_secs(),
                            "failed to fetch secret from backend, using stale cached secret as fallback"
                        );
                        return Ok(stale_secret);
                    }
                }
                Err(SecretError::Backend(format!("{err_arc}")))
            }
        }
    }
}
