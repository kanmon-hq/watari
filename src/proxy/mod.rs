pub mod client;
pub mod headers;
pub mod url;

use crate::app::AppState;
use crate::auth::verify_gateway_auth;
use crate::error::AppError;
use crate::proxy::headers::{sanitize_and_inject_request_headers, sanitize_response_headers};
use crate::proxy::url::build_upstream_url;
use crate::ratelimit::{RateDecision, RateKey};
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use futures_util::TryStreamExt;
use secrecy::SecretString;
use std::error::Error;
use std::time::{Duration, Instant};
use uuid::Uuid;

struct ProxyRequestContext<'a> {
    state: &'a AppState,
    upstream_name: &'a str,
    subpath: &'a str,
    method: Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body_bytes: Bytes,
    request_id: &'a str,
}

/// Main proxy handler for ANY /v1/providers/{provider_id}/*path and /u/{upstream}/{*path}
pub async fn proxy_handler(
    State(state): State<AppState>,
    Path((upstream_name, subpath)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    let start_time = Instant::now();

    // 1. Extract or generate Request ID
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Buffer body to allow in-flight retry
    let body_bytes = match to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return AppError::Internal(format!("failed to buffer request body: {e}"))
                .to_response_with_request_id(Some(request_id));
        }
    };

    let ctx = ProxyRequestContext {
        state: &state,
        upstream_name: &upstream_name,
        subpath: &subpath,
        method,
        uri: &uri,
        headers: &headers,
        body_bytes,
        request_id: &request_id,
    };

    // Inner handler to capture AppError and format error responses with request_id
    match execute_proxy_request(ctx).await {
        Ok(resp) => {
            let latency = start_time.elapsed();
            let latency_ms = latency.as_millis();
            let status = resp.status().as_u16();
            let status_str = status.to_string();
            let tenant_id = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");

            metrics::counter!(
                "watari_requests_total",
                "upstream" => upstream_name.clone(),
                "tenant_id" => tenant_id.to_string(),
                "status" => status_str
            )
            .increment(1);

            metrics::histogram!(
                "watari_request_duration_seconds",
                "upstream" => upstream_name.clone()
            )
            .record(latency.as_secs_f64());

            tracing::info!(
                request_id = %request_id,
                tenant_id = %tenant_id,
                upstream = %upstream_name,
                status = %status,
                latency_ms = %latency_ms,
                "proxy request completed"
            );
            resp
        }
        Err(err) => {
            let latency = start_time.elapsed();
            let latency_ms = latency.as_millis();
            let tenant_id = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            let status_code = err.status_code().as_u16();
            let status_str = status_code.to_string();

            metrics::counter!(
                "watari_requests_total",
                "upstream" => upstream_name.clone(),
                "tenant_id" => tenant_id.to_string(),
                "status" => status_str
            )
            .increment(1);

            metrics::histogram!(
                "watari_request_duration_seconds",
                "upstream" => upstream_name.clone()
            )
            .record(latency.as_secs_f64());

            if matches!(err, AppError::RateLimited { .. }) {
                metrics::counter!(
                    "watari_rate_limited_total",
                    "upstream" => upstream_name.clone(),
                    "tenant_id" => tenant_id.to_string()
                )
                .increment(1);
            }

            if matches!(err, AppError::EgressBlocked) {
                metrics::counter!(
                    "watari_egress_blocked_total",
                    "upstream" => upstream_name.clone()
                )
                .increment(1);
            }

            tracing::warn!(
                request_id = %request_id,
                tenant_id = %tenant_id,
                upstream = %upstream_name,
                error = %err,
                latency_ms = %latency_ms,
                "proxy request failed"
            );

            err.to_response_with_request_id(Some(request_id))
        }
    }
}

async fn execute_proxy_request(ctx: ProxyRequestContext<'_>) -> Result<Response<Body>, AppError> {
    // 1. Verify Gateway Secret
    let gateway_secret_hdr = ctx
        .headers
        .get("x-gateway-secret")
        .and_then(|v| v.to_str().ok());
    verify_gateway_auth(
        gateway_secret_hdr,
        ctx.state.config.gateway_shared_secret.as_ref(),
        ctx.state.config.gateway_shared_secret_previous.as_ref(),
        ctx.state.config.insecure_no_gateway_auth,
    )?;

    // 2. Extract Tenant ID
    let tenant_id = ctx
        .headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingTenant)?;

    if tenant_id.trim().is_empty() {
        return Err(AppError::MissingTenant);
    }

    // 3. Fetch Upstream Configuration
    let upstream_config = ctx
        .state
        .tenant_store
        .get_upstream(tenant_id, ctx.upstream_name)
        .await?
        .ok_or(AppError::UpstreamForbidden)?;

    // 4. Rate Limiting Check with Micro-delay smoothing
    let rate_key = RateKey {
        tenant_id: tenant_id.to_string(),
        upstream: ctx.upstream_name.to_string(),
    };
    match ctx
        .state
        .rate_limiter
        .check(&rate_key, &upstream_config.rate_limit)
        .await
    {
        RateDecision::Allow => {}
        RateDecision::Deny { retry_after_secs } => {
            return Err(AppError::RateLimited { retry_after_secs });
        }
    }

    // 5. Build Upstream Destination URL
    let query = ctx.uri.query();
    let target_url = build_upstream_url(&upstream_config.base_url, ctx.subpath, query)
        .map_err(|_| AppError::UpstreamForbidden)?;

    // 5.1 Domain Allowlist verification
    let target_host = target_url.host_str().unwrap_or("");
    if !upstream_config.is_domain_allowed(target_host) {
        tracing::warn!(
            host = %target_host,
            upstream = %ctx.upstream_name,
            "Target domain is not allowed by upstream allowlist"
        );
        return Err(AppError::UpstreamForbidden);
    }

    // 6. Fetch Secrets for Injection
    let mut resolved_secrets: Vec<(crate::storage::InjectRule, SecretString)> = Vec::new();
    for rule in &upstream_config.inject {
        let secret = ctx
            .state
            .secret_store
            .get(&rule.secret_ref, &rule.version)
            .await?;
        resolved_secrets.push((rule.clone(), secret));
    }

    // 7. Sanitize and Inject Request Headers
    let outgoing_headers =
        sanitize_and_inject_request_headers(ctx.headers, ctx.request_id, &resolved_secrets);

    // 8. In-flight Retry Loop with Exponential Backoff and Retry-After
    let max_retries = ctx.state.config.max_retries;
    let base_backoff_ms = ctx.state.config.retry_base_backoff_ms;
    let mut attempt = 0;

    loop {
        attempt += 1;

        let req_builder = ctx
            .state
            .client
            .request(ctx.method.clone(), target_url.as_str())
            .headers(outgoing_headers.clone())
            .body(ctx.body_bytes.clone())
            .timeout(Duration::from_secs(upstream_config.timeout_secs));

        let send_result = req_builder.send().await;

        match send_result {
            Ok(upstream_response) => {
                let status_code = upstream_response.status();

                // Check for retryable status codes (429 Too Many Requests, 503 Service Unavailable)
                if (status_code == StatusCode::TOO_MANY_REQUESTS
                    || status_code == StatusCode::SERVICE_UNAVAILABLE)
                    && attempt <= max_retries
                {
                    let backoff_duration = if let Some(retry_after) = upstream_response
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        Duration::from_secs(retry_after.min(10))
                    } else {
                        // Exponential backoff: base * 2^(attempt - 1) with simple jitter
                        let factor = 1u64.checked_shl((attempt - 1) as u32).unwrap_or(16);
                        let backoff_ms = (base_backoff_ms * factor).min(5000);
                        Duration::from_millis(backoff_ms)
                    };

                    tracing::warn!(
                        attempt = attempt,
                        max_retries = max_retries,
                        status = %status_code.as_u16(),
                        backoff_ms = backoff_duration.as_millis(),
                        "Upstream returned retryable status, retrying in-flight..."
                    );

                    tokio::time::sleep(backoff_duration).await;
                    continue;
                }

                // Non-retryable or success
                let sanitized_resp_headers = sanitize_response_headers(upstream_response.headers());
                let resp_stream = upstream_response
                    .bytes_stream()
                    .map_err(|e| std::io::Error::other(format!("stream error: {e}")));
                let response_body = Body::from_stream(resp_stream);

                let mut response_builder = Response::builder().status(status_code);
                for (k, v) in sanitized_resp_headers.iter() {
                    response_builder = response_builder.header(k, v);
                }

                if let Ok(req_id_val) = axum::http::HeaderValue::from_str(ctx.request_id) {
                    response_builder = response_builder.header("x-request-id", req_id_val);
                }

                let response = response_builder.body(response_body).unwrap_or_else(|_| {
                    AppError::Internal("failed to build response".into()).into_response()
                });

                return Ok(response);
            }
            Err(err) => {
                if attempt <= max_retries && !err.is_timeout() {
                    let backoff_ms = (base_backoff_ms * (1 << (attempt - 1))).min(5000);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }

                if err.is_timeout() {
                    return Err(AppError::UpstreamTimeout);
                } else if let Some(io_err) = err
                    .source()
                    .and_then(|s| s.downcast_ref::<std::io::Error>())
                {
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                        return Err(AppError::EgressBlocked);
                    } else {
                        return Err(AppError::UpstreamUnreachable);
                    }
                } else {
                    return Err(AppError::UpstreamUnreachable);
                }
            }
        }
    }
}
