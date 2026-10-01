use crate::app::AppState;
use crate::auth::verify_admin_key;
use crate::error::AppError;
use crate::storage::UpstreamConfig;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

/// Helper to authenticate admin requests
fn authenticate_admin(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let header_val = headers
        .get("x-admin-api-key")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok());

    verify_admin_key(header_val, state.config.admin_api_key.as_ref())
}

/// GET /admin/v1/providers - List all provider/upstream configurations
pub async fn list_providers_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    authenticate_admin(&state, &headers)?;
    let providers = state.tenant_store.list_upstreams().await?;
    Ok((StatusCode::OK, Json(providers)))
}

/// POST /admin/v1/providers - Upsert a provider/upstream configuration
pub async fn upsert_provider_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpstreamConfig>,
) -> Result<impl IntoResponse, AppError> {
    authenticate_admin(&state, &headers)?;

    payload
        .validate(state.config.allow_insecure_upstream)
        .map_err(|e| AppError::Internal(format!("validation failed: {e}")))?;

    state.tenant_store.upsert_upstream(payload.clone()).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "provider configured successfully",
            "provider": payload
        })),
    ))
}

/// DELETE /admin/v1/providers/{tenant_id}/{provider_id} - Delete a provider configuration
pub async fn delete_provider_handler(
    State(state): State<AppState>,
    Path((tenant_id, provider_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    authenticate_admin(&state, &headers)?;

    let removed = state
        .tenant_store
        .delete_upstream(&tenant_id, &provider_id)
        .await?;

    if removed {
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "message": format!("provider '{provider_id}' for tenant '{tenant_id}' deleted")
            })),
        ))
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "message": "provider not found"
            })),
        ))
    }
}
