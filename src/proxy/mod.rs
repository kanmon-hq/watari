pub mod client;
pub mod headers;
pub mod url;

use crate::app::AppState;
use crate::auth::verify_gateway_secret;
use crate::error::AppError;
use crate::proxy::headers::{sanitize_and_inject_request_headers, sanitize_response_headers};
use crate::proxy::url::build_upstream_url;
use crate::ratelimit::{RateDecision, RateKey};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Response, Uri};
use axum::response::IntoResponse;
use futures_util::TryStreamExt;
use secrecy::SecretString;
use std::error::Error;
use std::time::Instant;
use uuid::Uuid;

struct ProxyRequestContext<'a> {
    state: &'a AppState,
    upstream_name: &'a str,
    subpath: &'a str,
    method: Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body: Body,
    request_id: &'a str,
}

/// Main proxy handler for ANY /u/{upstream}/{*path}
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

    let ctx = ProxyRequestContext {
        state: &state,
        upstream_name: &upstream_name,
        subpath: &subpath,
        method,
        uri: &uri,
        headers: &headers,
        body,
        request_id: &request_id,
    };

    // Inner handler to capture AppError and format error responses with request_id
    match execute_proxy_request(ctx).await {
        Ok(resp) => {
            let latency_ms = start_time.elapsed().as_millis();
            let tenant_id = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");

            tracing::info!(
                request_id = %request_id,
                tenant_id = %tenant_id,
                upstream = %upstream_name,
                status = %resp.status().as_u16(),
                latency_ms = %latency_ms,
                "proxy request completed"
            );
            resp
        }
        Err(err) => {
            let latency_ms = start_time.elapsed().as_millis();
            let tenant_id = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");

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
    verify_gateway_secret(gateway_secret_hdr, &ctx.state.config.gateway_shared_secret)?;

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

    // 4. Rate Limiting Check
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

    // 8. Prepare reqwest Streaming Request
    let reqwest_body = reqwest::Body::wrap_stream(ctx.body.into_data_stream());
    let req_builder = ctx
        .state
        .client
        .request(ctx.method, target_url.as_str())
        .headers(outgoing_headers)
        .body(reqwest_body)
        .timeout(std::time::Duration::from_secs(upstream_config.timeout_secs));

    // 9. Forward Request and Stream Response
    let upstream_response = req_builder.send().await.map_err(|err| {
        if err.is_timeout() {
            AppError::UpstreamTimeout
        } else if let Some(io_err) = err
            .source()
            .and_then(|s| s.downcast_ref::<std::io::Error>())
        {
            if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                AppError::EgressBlocked
            } else {
                AppError::UpstreamUnreachable
            }
        } else {
            AppError::UpstreamUnreachable
        }
    })?;

    // 10. Process Response Headers and Stream Body
    let status_code = upstream_response.status();
    let sanitized_resp_headers = sanitize_response_headers(upstream_response.headers());
    let resp_stream = upstream_response
        .bytes_stream()
        .map_err(|e| std::io::Error::other(format!("stream error: {e}")));
    let response_body = Body::from_stream(resp_stream);

    let mut response_builder = Response::builder().status(status_code);
    for (k, v) in sanitized_resp_headers.iter() {
        response_builder = response_builder.header(k, v);
    }

    // Ensure X-Request-ID is in response
    if let Ok(req_id_val) = axum::http::HeaderValue::from_str(ctx.request_id) {
        response_builder = response_builder.header("x-request-id", req_id_val);
    }

    let response = response_builder
        .body(response_body)
        .unwrap_or_else(|_| AppError::Internal("failed to build response".into()).into_response());

    Ok(response)
}
