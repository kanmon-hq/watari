use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// Top-level application errors.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Missing required configuration: {0}")]
    Config(#[from] ConfigError),

    #[error("Missing X-Tenant-ID header")]
    MissingTenant,

    #[error("Unauthorized: invalid or missing gateway secret")]
    Unauthorized,

    #[error("Upstream forbidden or not registered")]
    UpstreamForbidden,

    #[error("Rate limit exceeded")]
    RateLimited { retry_after_secs: u64 },

    #[error("Egress blocked by SSRF guard")]
    EgressBlocked,

    #[error("Upstream unreachable")]
    UpstreamUnreachable,

    #[error("Upstream timeout")]
    UpstreamTimeout,

    #[error("Secret retrieval failed")]
    SecretError(#[from] SecretError),

    #[error("Storage error")]
    StoreError(#[from] StoreError),

    #[error("Internal server error")]
    Internal(String),
}

/// Configuration loading errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingRequired(String),

    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}

/// Secret store errors.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Secret backend error")]
    Backend(String),

    #[error("Secret backend not supported: {0}")]
    NotSupported(String),
}

/// Storage errors.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Storage I/O error")]
    Io(String),

    #[error("Storage parsing error")]
    Parse(String),

    #[error("Database error")]
    Database(String),
}

#[derive(Serialize)]
struct ErrorResponseBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MissingTenant => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::UpstreamForbidden => StatusCode::FORBIDDEN,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::EgressBlocked => StatusCode::BAD_GATEWAY,
            Self::UpstreamUnreachable => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::SecretError(_) => StatusCode::BAD_GATEWAY,
            Self::StoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn to_response_with_request_id(&self, request_id: Option<String>) -> Response {
        let (status, code, message, retry_after) = match self {
            Self::Config(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                e.to_string(),
                None,
            ),
            Self::MissingTenant => (
                StatusCode::BAD_REQUEST,
                "missing_tenant",
                "X-Tenant-ID header is required".to_string(),
                None,
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Unauthorized".to_string(),
                None,
            ),
            Self::UpstreamForbidden => (
                StatusCode::FORBIDDEN,
                "upstream_forbidden",
                "Upstream not found or forbidden for tenant".to_string(),
                None,
            ),
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Rate limit exceeded".to_string(),
                Some(*retry_after_secs),
            ),
            Self::EgressBlocked => (
                StatusCode::BAD_GATEWAY,
                "egress_blocked",
                "Egress destination is blocked".to_string(),
                None,
            ),
            Self::UpstreamUnreachable => (
                StatusCode::BAD_GATEWAY,
                "upstream_unreachable",
                "Failed to connect to upstream server".to_string(),
                None,
            ),
            Self::UpstreamTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                "Upstream request timed out".to_string(),
                None,
            ),
            Self::SecretError(e) => match e {
                SecretError::NotFound(_) => (
                    StatusCode::BAD_GATEWAY,
                    "upstream_unreachable",
                    "Failed to resolve required credentials".to_string(),
                    None,
                ),
                _ => (
                    StatusCode::BAD_GATEWAY,
                    "upstream_unreachable",
                    "Secret provider error".to_string(),
                    None,
                ),
            },
            Self::StoreError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Storage error".to_string(),
                None,
            ),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error".to_string(),
                None,
            ),
        };

        let body = ErrorResponseBody {
            error: ErrorDetail {
                code,
                message,
                request_id,
            },
        };

        let mut builder = Response::builder()
            .status(status)
            .header(axum::http::header::CONTENT_TYPE, "application/json");

        if let Some(retry) = retry_after {
            builder = builder.header(axum::http::header::RETRY_AFTER, retry.to_string());
        }

        let body_str = serde_json::to_string(&body).unwrap_or_else(|_| {
            r#"{"error":{"code":"internal_error","message":"Failed to serialize error"}}"#
                .to_string()
        });

        builder
            .body(axum::body::Body::from(body_str))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from("Internal Server Error"))
                    .unwrap()
            })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.to_response_with_request_id(None)
    }
}
