pub mod memory;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use crate::error::StoreError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretVersion {
    #[default]
    Latest,
    Id(String),
}

/// Rule for injecting secrets into outbound request headers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InjectRule {
    /// Target header name to set/overwrite (e.g. "Authorization").
    pub header: String,
    /// Template for header value (e.g. "Bearer {secret}").
    pub template: String,
    /// Identifier or key reference in the SecretStore.
    pub secret_ref: String,
    /// Version of secret to request.
    #[serde(default)]
    pub version: SecretVersion,
}

/// Rate limit parameters for an upstream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Requests per minute.
    pub rpm: u32,
    /// Allowed burst size.
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rpm: 600,
            burst: 50,
        }
    }
}

/// Configuration for an upstream alias of a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub tenant_id: String,
    pub upstream: String,
    pub base_url: Url,
    pub inject: Vec<InjectRule>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Explicit domain allowlist (FQDNs). If None, defaults to base_url host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
}

fn default_timeout_secs() -> u64 {
    30
}

impl UpstreamConfig {
    /// Validate upstream configuration according to security constraints.
    pub fn validate(&self, allow_insecure: bool) -> Result<(), String> {
        if !allow_insecure && self.base_url.scheme() != "https" {
            return Err(format!(
                "upstream '{}' scheme must be https (got '{}')",
                self.upstream,
                self.base_url.scheme()
            ));
        }

        if !self.base_url.username().is_empty() || self.base_url.password().is_some() {
            return Err(format!(
                "upstream '{}' base_url must not contain userinfo",
                self.upstream
            ));
        }

        let host = self
            .base_url
            .host_str()
            .ok_or_else(|| format!("upstream '{}' base_url missing host", self.upstream))?;

        if !allow_insecure && host.parse::<std::net::IpAddr>().is_ok() {
            return Err(format!(
                "upstream '{}' host must not be raw IP literal ('{}')",
                self.upstream, host
            ));
        }

        if let Some(domains) = &self.allowed_domains {
            for domain in domains {
                if domain.trim().is_empty() {
                    return Err(format!(
                        "upstream '{}' contains empty domain in allowed_domains",
                        self.upstream
                    ));
                }
            }
        }

        for rule in &self.inject {
            if axum::http::HeaderName::from_bytes(rule.header.as_bytes()).is_err() {
                return Err(format!(
                    "upstream '{}' has invalid header name '{}'",
                    self.upstream, rule.header
                ));
            }
            if !rule.template.contains("{secret}") {
                return Err(format!(
                    "upstream '{}' inject template for '{}' missing {{secret}} placeholder",
                    self.upstream, rule.header
                ));
            }
        }

        Ok(())
    }

    /// Check if target host is allowed by this upstream config.
    pub fn is_domain_allowed(&self, host: &str) -> bool {
        if let Some(allowed) = &self.allowed_domains {
            allowed.iter().any(|d| d.eq_ignore_ascii_case(host))
        } else if let Some(base_host) = self.base_url.host_str() {
            base_host.eq_ignore_ascii_case(host)
        } else {
            false
        }
    }
}

/// Trait for retrieving tenant upstream configurations.
#[async_trait]
pub trait TenantConfigStore: Send + Sync {
    async fn get_upstream(
        &self,
        tenant_id: &str,
        upstream: &str,
    ) -> Result<Option<UpstreamConfig>, StoreError>;

    async fn list_upstreams(&self) -> Result<Vec<UpstreamConfig>, StoreError> {
        Ok(Vec::new())
    }

    async fn upsert_upstream(&self, _config: UpstreamConfig) -> Result<(), StoreError> {
        Err(StoreError::Io("Upsert not supported on this store".into()))
    }

    async fn delete_upstream(&self, _tenant_id: &str, _upstream: &str) -> Result<bool, StoreError> {
        Err(StoreError::Io("Delete not supported on this store".into()))
    }
}
