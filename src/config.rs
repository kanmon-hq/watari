use secrecy::SecretString;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Storage backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageBackendKind {
    #[default]
    Memory,
    Sqlite,
}

impl std::str::FromStr for StorageBackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "memory" => Ok(Self::Memory),
            "sqlite" => Ok(Self::Sqlite),
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
    /// Address to listen on. Default: 0.0.0.0:8080
    pub listen_addr: SocketAddr,
    /// Shared secret for verifying X-Gateway-Secret header.
    pub gateway_shared_secret: SecretString,
    /// Storage backend to use. Default: memory
    pub storage_backend: StorageBackendKind,
    /// Path to sqlite database file if storage_backend is sqlite. Default: ./watari.db
    pub sqlite_path: String,
    /// Path to seed YAML file for memory storage backend. Default: ./tenants.yaml
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
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, crate::error::ConfigError> {
        let listen_addr_str =
            std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let listen_addr: SocketAddr = listen_addr_str.parse().map_err(|e| {
            crate::error::ConfigError::InvalidValue(format!("LISTEN_ADDR invalid: {e}"))
        })?;

        let secret_raw = std::env::var("GATEWAY_SHARED_SECRET").map_err(|_| {
            crate::error::ConfigError::MissingRequired("GATEWAY_SHARED_SECRET".to_string())
        })?;
        if secret_raw.trim().is_empty() {
            return Err(crate::error::ConfigError::MissingRequired(
                "GATEWAY_SHARED_SECRET cannot be empty".to_string(),
            ));
        }
        let gateway_shared_secret = SecretString::new(secret_raw.into());

        let storage_backend_str =
            std::env::var("STORAGE_BACKEND").unwrap_or_else(|_| "memory".to_string());
        let storage_backend: StorageBackendKind = storage_backend_str.parse().map_err(|e| {
            crate::error::ConfigError::InvalidValue(format!("STORAGE_BACKEND invalid: {e}"))
        })?;

        let sqlite_path =
            std::env::var("SQLITE_PATH").unwrap_or_else(|_| "./watari.db".to_string());
        let memory_seed_file = PathBuf::from(
            std::env::var("MEMORY_SEED_FILE").unwrap_or_else(|_| "./tenants.yaml".to_string()),
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

        Ok(Self {
            listen_addr,
            gateway_shared_secret,
            storage_backend,
            sqlite_path,
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
        })
    }
}
