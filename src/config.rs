use secrecy::SecretString;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Storage backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageBackendKind {
    #[default]
    Memory,
    Sqlite,
    Dynamodb,
}

impl std::str::FromStr for StorageBackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "memory" => Ok(Self::Memory),
            "sqlite" => Ok(Self::Sqlite),
            "dynamodb" => Ok(Self::Dynamodb),
            other => Err(format!("unknown storage backend: {other}")),
        }
    }
}

/// Secret backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretBackendKind {
    #[default]
    Env,
    File,
    Aws,
    Gcp,
    Azure,
}

impl std::str::FromStr for SecretBackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "env" => Ok(Self::Env),
            "file" => Ok(Self::File),
            "aws" => Ok(Self::Aws),
            "gcp" => Ok(Self::Gcp),
            "azure" => Ok(Self::Azure),
            other => Err(format!("unknown secret backend: {other}")),
        }
    }
}

/// Log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            other => Err(format!("unknown log format: {other}")),
        }
    }
}

/// Application configuration loaded from environment variables.
#[derive(Clone)]
pub struct Config {
    /// Address to listen on. Default: 0.0.0.0:8080 (or HTTP_PORT)
    pub listen_addr: SocketAddr,
    /// Shared secret for verifying X-Gateway-Secret header.
    pub gateway_shared_secret: Option<SecretString>,
    /// Previous shared secret for graceful rotation.
    pub gateway_shared_secret_previous: Option<SecretString>,
    /// Insecure flag to skip gateway shared secret verification. Default: false
    pub insecure_no_gateway_auth: bool,
    /// Admin API key for managing providers/tenants.
    pub admin_api_key: Option<SecretString>,
    /// Storage backend to use. Default: memory
    pub storage_backend: StorageBackendKind,
    /// Path to sqlite database file if storage_backend is sqlite. Default: /data/watari.db
    pub sqlite_path: String,
    /// DynamoDB table name if storage_backend is dynamodb. Default: watari_configs
    pub dynamodb_table_name: String,
    /// Path to seed YAML file for memory storage backend. Default: ./examples/tenants.yaml
    pub memory_seed_file: PathBuf,
    /// Secret store backend to use. Default: env
    pub secret_backend: SecretBackendKind,
    /// Directory containing secret files if secret_backend is file.
    pub secret_file_dir: Option<PathBuf>,
    /// Secret cache TTL in seconds. Default: 300
    pub secret_cache_ttl_secs: u64,
    /// Secret max stale duration in seconds. Default: 900
    pub secret_max_stale_secs: u64,
    /// Tenant config cache TTL in seconds. Default: 60
    pub tenant_cache_ttl_secs: u64,
    /// Tenant config cache max entries. Default: 10000
    pub tenant_cache_max_entries: u64,
    /// Log level string (e.g., info, debug). Default: info
    pub log_level: String,
    /// Log format. Default: json
    pub log_format: LogFormat,
    /// Allow private IPs in SSRF resolver (Dev/Testing only). Default: false
    pub allow_private_ips: bool,
    /// Allow insecure HTTP upstreams (Dev/Testing only). Default: false
    pub allow_insecure_upstream: bool,
    /// Maximum in-flight retry attempts for upstream 429/503. Default: 3
    pub max_retries: usize,
    /// Base backoff duration in milliseconds for retries. Default: 100
    pub retry_base_backoff_ms: u64,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, crate::error::ConfigError> {
        let listen_addr_str = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| {
            let port = std::env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string());
            format!("0.0.0.0:{port}")
        });
        let listen_addr: SocketAddr = listen_addr_str.parse().map_err(|e| {
            crate::error::ConfigError::InvalidValue(format!("LISTEN_ADDR/HTTP_PORT invalid: {e}"))
        })?;

        let insecure_no_gateway_auth = std::env::var("INSECURE_NO_GATEWAY_AUTH")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let gateway_shared_secret = match std::env::var("GATEWAY_SHARED_SECRET") {
            Ok(val) if !val.trim().is_empty() => Some(SecretString::new(val.into())),
            _ => {
                if !insecure_no_gateway_auth {
                    return Err(crate::error::ConfigError::MissingRequired(
                        "GATEWAY_SHARED_SECRET (or set INSECURE_NO_GATEWAY_AUTH=true for testing)"
                            .to_string(),
                    ));
                }
                None
            }
        };

        let gateway_shared_secret_previous = std::env::var("GATEWAY_SHARED_SECRET_PREVIOUS")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|v| SecretString::new(v.into()));

        let admin_api_key = std::env::var("ADMIN_API_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|v| SecretString::new(v.into()));

        let storage_backend_str =
            std::env::var("STORAGE_BACKEND").unwrap_or_else(|_| "memory".to_string());
        let storage_backend: StorageBackendKind = storage_backend_str.parse().map_err(|e| {
            crate::error::ConfigError::InvalidValue(format!("STORAGE_BACKEND invalid: {e}"))
        })?;

        let sqlite_path =
            std::env::var("SQLITE_PATH").unwrap_or_else(|_| "/data/watari.db".to_string());
        let dynamodb_table_name =
            std::env::var("DYNAMODB_TABLE_NAME").unwrap_or_else(|_| "watari_configs".to_string());

        let memory_seed_file = PathBuf::from(
            std::env::var("MEMORY_SEED_FILE")
                .unwrap_or_else(|_| "./examples/tenants.yaml".to_string()),
        );

        let secret_backend_str =
            std::env::var("SECRET_BACKEND").unwrap_or_else(|_| "env".to_string());
        let secret_backend: SecretBackendKind = secret_backend_str.parse().map_err(|e| {
            crate::error::ConfigError::InvalidValue(format!("SECRET_BACKEND invalid: {e}"))
        })?;

        let secret_file_dir = std::env::var("SECRET_FILE_DIR").ok().map(PathBuf::from);

        let secret_cache_ttl_secs = std::env::var("SECRET_CACHE_TTL_SECS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u64>()
            .map_err(|e| {
                crate::error::ConfigError::InvalidValue(format!(
                    "SECRET_CACHE_TTL_SECS invalid: {e}"
                ))
            })?;

        let secret_max_stale_secs = std::env::var("SECRET_MAX_STALE_SECS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<u64>()
            .map_err(|e| {
                crate::error::ConfigError::InvalidValue(format!(
                    "SECRET_MAX_STALE_SECS invalid: {e}"
                ))
            })?;

        let tenant_cache_ttl_secs = std::env::var("TENANT_CACHE_TTL_SECS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .map_err(|e| {
                crate::error::ConfigError::InvalidValue(format!(
                    "TENANT_CACHE_TTL_SECS invalid: {e}"
                ))
            })?;

        let tenant_cache_max_entries = std::env::var("TENANT_CACHE_MAX_ENTRIES")
            .unwrap_or_else(|_| "10000".to_string())
            .parse::<u64>()
            .map_err(|e| {
                crate::error::ConfigError::InvalidValue(format!(
                    "TENANT_CACHE_MAX_ENTRIES invalid: {e}"
                ))
            })?;

        let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let log_format_str = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());
        let log_format: LogFormat = log_format_str.parse().map_err(|e| {
            crate::error::ConfigError::InvalidValue(format!("LOG_FORMAT invalid: {e}"))
        })?;

        let allow_private_ips = std::env::var("ALLOW_PRIVATE_IPS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let allow_insecure_upstream = std::env::var("ALLOW_INSECURE_UPSTREAM")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let max_retries = std::env::var("MAX_RETRIES")
            .unwrap_or_else(|_| "3".to_string())
            .parse::<usize>()
            .unwrap_or(3);

        let retry_base_backoff_ms = std::env::var("RETRY_BASE_BACKOFF_MS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u64>()
            .unwrap_or(100);

        Ok(Self {
            listen_addr,
            gateway_shared_secret,
            gateway_shared_secret_previous,
            insecure_no_gateway_auth,
            admin_api_key,
            storage_backend,
            sqlite_path,
            dynamodb_table_name,
            memory_seed_file,
            secret_backend,
            secret_file_dir,
            secret_cache_ttl_secs,
            secret_max_stale_secs,
            tenant_cache_ttl_secs,
            tenant_cache_max_entries,
            log_level,
            log_format,
            allow_private_ips,
            allow_insecure_upstream,
            max_retries,
            retry_base_backoff_ms,
        })
    }
}
