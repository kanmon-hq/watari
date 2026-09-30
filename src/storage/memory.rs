use super::{InjectRule, RateLimitConfig, TenantConfigStore, UpstreamConfig};
use crate::error::StoreError;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize)]
struct YamlFileStructure {
    tenants: HashMap<String, YamlTenantEntry>,
}

#[derive(Debug, Deserialize)]
struct YamlTenantEntry {
    #[serde(default)]
    upstreams: HashMap<String, YamlUpstreamEntry>,
}

#[derive(Debug, Deserialize)]
struct YamlUpstreamEntry {
    base_url: Url,
    #[serde(default)]
    inject: Vec<InjectRule>,
    #[serde(default)]
    rate_limit: RateLimitConfig,
    #[serde(default = "super::default_timeout_secs")]
    timeout_secs: u64,
}

/// In-memory implementation of `TenantConfigStore`.
#[derive(Debug, Clone)]
pub struct MemoryTenantStore {
    configs: Arc<HashMap<(String, String), UpstreamConfig>>,
}

impl MemoryTenantStore {
    /// Create empty store.
    pub fn new() -> Self {
        Self {
            configs: Arc::new(HashMap::new()),
        }
    }

    /// Load store from a YAML file.
    pub fn from_yaml_file<P: AsRef<Path>>(
        path: P,
        allow_insecure: bool,
    ) -> Result<Self, StoreError> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref).map_err(|e| {
            StoreError::Io(format!(
                "failed to read seed file {}: {e}",
                path_ref.display()
            ))
        })?;

        Self::from_yaml_str(&content, allow_insecure)
    }

    /// Load store from a YAML string.
    pub fn from_yaml_str(yaml_str: &str, allow_insecure: bool) -> Result<Self, StoreError> {
        let parsed: YamlFileStructure = serde_yaml::from_str(yaml_str)
            .map_err(|e| StoreError::Parse(format!("failed to parse tenants yaml: {e}")))?;

        let mut configs = HashMap::new();
        for (tenant_id, tenant_entry) in parsed.tenants {
            for (upstream_name, upstream_entry) in tenant_entry.upstreams {
                let config = UpstreamConfig {
                    tenant_id: tenant_id.clone(),
                    upstream: upstream_name.clone(),
                    base_url: upstream_entry.base_url,
                    inject: upstream_entry.inject,
                    rate_limit: upstream_entry.rate_limit,
                    timeout_secs: upstream_entry.timeout_secs,
                };

                config.validate(allow_insecure).map_err(|e| {
                    StoreError::Parse(format!(
                        "invalid config for {tenant_id}/{upstream_name}: {e}"
                    ))
                })?;

                configs.insert((tenant_id.clone(), upstream_name), config);
            }
        }

        Ok(Self {
            configs: Arc::new(configs),
        })
    }

    /// Insert or overwrite an upstream config (useful for testing).
    pub fn insert(&mut self, config: UpstreamConfig) {
        let mut map = (*self.configs).clone();
        map.insert((config.tenant_id.clone(), config.upstream.clone()), config);
        self.configs = Arc::new(map);
    }
}

impl Default for MemoryTenantStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TenantConfigStore for MemoryTenantStore {
    async fn get_upstream(
        &self,
        tenant_id: &str,
        upstream: &str,
    ) -> Result<Option<UpstreamConfig>, StoreError> {
        let key = (tenant_id.to_string(), upstream.to_string());
        Ok(self.configs.get(&key).cloned())
    }
}
