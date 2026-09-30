use crate::cache::CachedTenantStore;
use crate::config::{Config, SecretBackendKind, StorageBackendKind};
use crate::error::AppError;
use crate::proxy::client::create_proxy_client;
use crate::proxy::proxy_handler;
use crate::ratelimit::{GovernorRateLimiter, RateLimiter};
use crate::secrets::cached::CachedSecretStore;
use crate::secrets::env::EnvSecretStore;
use crate::secrets::file::FileSecretStore;
use crate::secrets::SecretStore;
use crate::storage::memory::MemoryTenantStore;
use crate::storage::TenantConfigStore;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::{Json, Router};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;

/// Global application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub tenant_store: Arc<dyn TenantConfigStore>,
    pub secret_store: Arc<dyn SecretStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub client: Client,
}

/// Health check handler.
pub async fn healthz_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// Build the Axum Router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/u/{upstream}/{*path}", any(proxy_handler))
        .with_state(state)
}

/// Initialize application state from configuration.
pub async fn init_app_state(config: Config) -> Result<AppState, AppError> {
    if config.allow_private_ips {
        tracing::warn!(
            "ALLOW_PRIVATE_IPS is enabled. SSRF guard is permissive (dev/testing mode only)."
        );
    }
    if config.allow_insecure_upstream {
        tracing::warn!("ALLOW_INSECURE_UPSTREAM is enabled. HTTP upstreams are permitted (dev/testing mode only).");
    }

    // 1. Initialize Tenant Storage Backend
    let base_tenant_store: Arc<dyn TenantConfigStore> = match config.storage_backend {
        StorageBackendKind::Memory => {
            let store = if config.memory_seed_file.exists() {
                MemoryTenantStore::from_yaml_file(
                    &config.memory_seed_file,
                    config.allow_insecure_upstream,
                )?
            } else {
                tracing::info!(
                    path = %config.memory_seed_file.display(),
                    "Memory seed file not found, starting with empty store"
                );
                MemoryTenantStore::new()
            };
            Arc::new(store)
        }
        StorageBackendKind::Sqlite => {
            #[cfg(feature = "sqlite")]
            {
                let store = crate::storage::sqlite::SqliteTenantStore::new(
                    &config.sqlite_path,
                    config.allow_insecure_upstream,
                )
                .await?;
                Arc::new(store)
            }
            #[cfg(not(feature = "sqlite"))]
            {
                return Err(AppError::Config(crate::error::ConfigError::InvalidValue(
                    "SQLite feature not compiled in".into(),
                )));
            }
        }
    };

    // Wrap with Tenant Config Cache
    let tenant_store: Arc<dyn TenantConfigStore> = Arc::new(CachedTenantStore::new(
        base_tenant_store,
        config.tenant_cache_ttl_secs,
        config.tenant_cache_max_entries,
    ));

    // 2. Initialize Secret Store Backend
    let base_secret_store: Arc<dyn SecretStore> = match config.secret_backend {
        SecretBackendKind::Env => Arc::new(EnvSecretStore::new()),
        SecretBackendKind::File => {
            let dir = config.secret_file_dir.clone().ok_or_else(|| {
                crate::error::ConfigError::MissingRequired(
                    "SECRET_FILE_DIR is required for file backend".into(),
                )
            })?;
            Arc::new(FileSecretStore::new(dir))
        }
        SecretBackendKind::Aws => {
            #[cfg(feature = "aws")]
            {
                Arc::new(crate::secrets::aws::AwsSecretStore::new().await)
            }
            #[cfg(not(feature = "aws"))]
            {
                return Err(crate::error::SecretError::NotSupported(
                    "AWS feature not compiled in".into(),
                )
                .into());
            }
        }
        SecretBackendKind::Gcp => {
            return Err(crate::error::SecretError::NotSupported(
                "GCP Secret Manager backend is not implemented in MVP (Phase 4)".into(),
            )
            .into());
        }
        SecretBackendKind::Azure => {
            return Err(crate::error::SecretError::NotSupported(
                "Azure Key Vault backend is not implemented in MVP (Phase 4)".into(),
            )
            .into());
        }
    };

    // Wrap with Secret Cache
    let secret_store: Arc<dyn SecretStore> = Arc::new(CachedSecretStore::new(
        base_secret_store,
        config.secret_cache_ttl_secs,
        config.secret_max_stale_secs,
    ));

    // 3. Initialize Rate Limiter
    let rate_limiter: Arc<dyn RateLimiter> = Arc::new(GovernorRateLimiter::new());

    // 4. Initialize HTTP Proxy Client
    let client = create_proxy_client(config.allow_private_ips)
        .map_err(|e| AppError::Internal(format!("failed to initialize reqwest client: {e}")))?;

    Ok(AppState {
        config,
        tenant_store,
        secret_store,
        rate_limiter,
        client,
    })
}
