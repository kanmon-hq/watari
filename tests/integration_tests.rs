use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use secrecy::SecretString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;
use url::Url;
use watari::app::{create_router, init_app_state};
use watari::auth::{verify_admin_key, verify_gateway_auth, verify_gateway_secret};
use watari::config::{Config, LogFormat, SecretBackendKind, StorageBackendKind};
use watari::ratelimit::{GovernorRateLimiter, RateDecision, RateKey, RateLimiter};
use watari::secrets::file::FileSecretStore;
use watari::secrets::SecretStore;
use watari::storage::memory::MemoryTenantStore;
use watari::storage::{
    InjectRule, RateLimitConfig, SecretVersion, TenantConfigStore, UpstreamConfig,
};

fn create_test_config() -> Config {
    Config {
        listen_addr: "127.0.0.1:8080".parse().unwrap(),
        gateway_shared_secret: Some(SecretString::new("test_secret".into())),
        gateway_shared_secret_previous: None,
        insecure_no_gateway_auth: false,
        admin_api_key: Some(SecretString::new("test_admin_key".into())),
        storage_backend: StorageBackendKind::Memory,
        sqlite_path: "./watari.db".into(),
        dynamodb_table_name: "watari_configs".into(),
        memory_seed_file: "./non_existent.yaml".into(),
        secret_backend: SecretBackendKind::Env,
        secret_file_dir: None,
        secret_cache_ttl_secs: 300,
        secret_max_stale_secs: 900,
        tenant_cache_ttl_secs: 60,
        tenant_cache_max_entries: 1000,
        log_level: "info".into(),
        log_format: LogFormat::Json,
        allow_private_ips: true,
        allow_insecure_upstream: true,
        max_retries: 3,
        retry_base_backoff_ms: 50,
    }
}

/// Test constant time auth logic
#[test]
fn test_auth_constant_time() {
    let secret = SecretString::new("my-shared-secret-12345".into());
    assert!(verify_gateway_secret(Some("my-shared-secret-12345"), &secret).is_ok());
    assert!(verify_gateway_secret(Some("wrong-secret"), &secret).is_err());
    assert!(verify_gateway_secret(None, &secret).is_err());
    assert!(verify_gateway_secret(Some(""), &secret).is_err());

    let admin_key = SecretString::new("admin_secret_key_999".into());
    assert!(verify_admin_key(Some("admin_secret_key_999"), Some(&admin_key)).is_ok());
    assert!(verify_admin_key(Some("Bearer admin_secret_key_999"), Some(&admin_key)).is_ok());
    assert!(verify_admin_key(Some("wrong_key"), Some(&admin_key)).is_err());
    assert!(verify_admin_key(None, Some(&admin_key)).is_err());
    assert!(verify_admin_key(Some("admin_secret_key_999"), None).is_err());
}

/// Test Domain Allowlist enforcement
#[tokio::test]
async fn test_domain_allowlist_enforcement() {
    let mut mem_store = MemoryTenantStore::new();
    mem_store.insert(UpstreamConfig {
        tenant_id: "tenant-a".to_string(),
        upstream: "stripe-custom".to_string(),
        base_url: Url::parse("https://api.stripe.com").unwrap(),
        inject: vec![],
        rate_limit: RateLimitConfig::default(),
        timeout_secs: 5,
        allowed_domains: Some(vec![
            "api.stripe.com".to_string(),
            "api.stripe.io".to_string(),
        ]),
    });

    let config = create_test_config();
    let mut state = init_app_state(config).await.unwrap();
    state.tenant_store = Arc::new(mem_store);
    let app = create_router(state);

    // Matching allowed domain should proceed past domain check
    // (returns 401 from live upstream or connect error, but not 403 upstream_forbidden)
    let req = Request::builder()
        .uri("/v1/providers/stripe-custom/v1/charges")
        .method("GET")
        .header("X-Tenant-ID", "tenant-a")
        .header("X-Gateway-Secret", "test_secret")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// Test healthz, livez, and readyz endpoints
#[tokio::test]
async fn test_healthz_livez_readyz() {
    let config = create_test_config();
    let state = init_app_state(config).await.unwrap();
    let app = create_router(state);

    for path in ["/healthz", "/livez", "/readyz"] {
        let req = Request::builder()
            .uri(path)
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }
}

/// Test metrics endpoint returns Prometheus text format
#[tokio::test]
async fn test_metrics_endpoint() {
    let config = create_test_config();
    let state = init_app_state(config).await.unwrap();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/metrics")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
}

/// Test 401 Unauthorized when missing or invalid X-Gateway-Secret
#[tokio::test]
async fn test_gateway_secret_auth_failures() {
    let config = create_test_config();
    let state = init_app_state(config).await.unwrap();
    let app = create_router(state);

    // 1. Missing header
    let req = Request::builder()
        .uri("/v1/providers/stripe/v1/charges")
        .method("POST")
        .header("X-Tenant-ID", "tenant-a")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Wrong secret
    let req = Request::builder()
        .uri("/v1/providers/stripe/v1/charges")
        .method("POST")
        .header("X-Gateway-Secret", "wrong_secret")
        .header("X-Tenant-ID", "tenant-a")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Test Gateway secret rotation and insecure skip
#[test]
fn test_gateway_auth_rotation_and_skip() {
    let primary = SecretString::new("current_secret_key".into());
    let previous = SecretString::new("old_secret_key".into());

    // Both current and previous are valid
    assert!(verify_gateway_auth(
        Some("current_secret_key"),
        Some(&primary),
        Some(&previous),
        false
    )
    .is_ok());

    assert!(verify_gateway_auth(
        Some("old_secret_key"),
        Some(&primary),
        Some(&previous),
        false
    )
    .is_ok());

    // Wrong secret rejected
    assert!(verify_gateway_auth(
        Some("random_secret"),
        Some(&primary),
        Some(&previous),
        false
    )
    .is_err());

    // Insecure skip allows anything
    assert!(verify_gateway_auth(None, None, None, true).is_ok());
    assert!(verify_gateway_auth(Some("any"), None, None, true).is_ok());
}

/// Test 400 Bad Request when missing X-Tenant-ID
#[tokio::test]
async fn test_missing_tenant_id() {
    let config = create_test_config();
    let state = init_app_state(config).await.unwrap();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/v1/providers/stripe/v1/charges")
        .method("POST")
        .header("X-Gateway-Secret", "test_secret")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "missing_tenant");
}

/// Test 403 Forbidden when upstream is not registered
#[tokio::test]
async fn test_upstream_forbidden() {
    let config = create_test_config();
    let state = init_app_state(config).await.unwrap();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/v1/providers/unregistered/v1/test")
        .method("GET")
        .header("X-Gateway-Secret", "test_secret")
        .header("X-Tenant-ID", "tenant-a")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "upstream_forbidden");
}

/// Full end-to-end proxy test with mock upstream server (testing both /v1/providers and /u/)
#[tokio::test]
async fn test_proxy_forward_with_secret_injection_and_streaming() {
    // 1. Start Mock Upstream Server
    let received_auth_header = Arc::new(tokio::sync::Mutex::new(String::new()));
    let received_custom_header = Arc::new(tokio::sync::Mutex::new(String::new()));
    let received_body = Arc::new(tokio::sync::Mutex::new(String::new()));

    let auth_clone = received_auth_header.clone();
    let custom_clone = received_custom_header.clone();
    let body_clone = received_body.clone();

    let mock_upstream = Router::new()
        .route(
            "/v1/charges",
            post(|headers: HeaderMap, body: String| async move {
                if let Some(auth) = headers.get("authorization") {
                    *auth_clone.lock().await = auth.to_str().unwrap().to_string();
                }
                if let Some(custom) = headers.get("x-custom-tenant-hdr") {
                    *custom_clone.lock().await = custom.to_str().unwrap().to_string();
                }
                *body_clone.lock().await = body;

                (
                    StatusCode::CREATED,
                    [
                        ("x-upstream-response-id", "up-999"),
                        ("set-cookie", "session=mock_upstream_cookie; Path=/"),
                    ],
                    "{\"charge_id\":\"ch_12345\"}",
                )
            }),
        )
        .route(
            "/redirect",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [("location", "https://example.com/target")],
                    "redirecting",
                )
            }),
        );

    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(upstream_listener, mock_upstream).await.unwrap();
    });

    // 2. Setup Memory Storage with Upstream pointing to Mock Server
    std::env::set_var("STRIPE_SECRET_KEY_TENANT_A", "sk_live_injected_test_key");

    let mut mem_store = MemoryTenantStore::new();
    mem_store.insert(UpstreamConfig {
        tenant_id: "tenant-a".to_string(),
        upstream: "stripe".to_string(),
        base_url: Url::parse(&format!("http://127.0.0.1:{}", upstream_addr.port())).unwrap(),
        inject: vec![InjectRule {
            header: "Authorization".to_string(),
            template: "Bearer {secret}".to_string(),
            secret_ref: "STRIPE_SECRET_KEY_TENANT_A".to_string(),
            version: SecretVersion::Latest,
        }],
        rate_limit: RateLimitConfig {
            rpm: 600,
            burst: 50,
        },
        timeout_secs: 5,
        allowed_domains: None,
    });

    let config = create_test_config();
    let mut state = init_app_state(config).await.unwrap();
    state.tenant_store = Arc::new(mem_store);

    let app = create_router(state);

    // 3. Send Client Request through Watari via /v1/providers/stripe/v1/charges
    let req = Request::builder()
        .uri("/v1/providers/stripe/v1/charges?query_param=test")
        .method("POST")
        .header("X-Tenant-ID", "tenant-a")
        .header("X-Gateway-Secret", "test_secret")
        .header("Authorization", "Bearer client_untrusted_token") // Must be wiped and replaced
        .header("Cookie", "client_cookie=xyz") // Must be stripped
        .header("X-Custom-Tenant-Hdr", "tenant_allowed_meta")
        .header("X-Request-ID", "req-test-999")
        .body(Body::from("amount=5000&currency=jpy"))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(resp.headers().get("x-request-id").unwrap(), "req-test-999");
    assert_eq!(
        resp.headers().get("x-upstream-response-id").unwrap(),
        "up-999"
    );
    assert_eq!(
        resp.headers().get("set-cookie").unwrap(),
        "session=mock_upstream_cookie; Path=/"
    );

    let resp_body = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(
        std::str::from_utf8(&resp_body).unwrap(),
        "{\"charge_id\":\"ch_12345\"}"
    );

    assert_eq!(
        *received_auth_header.lock().await,
        "Bearer sk_live_injected_test_key"
    );
    assert_eq!(*received_custom_header.lock().await, "tenant_allowed_meta");
    assert_eq!(*received_body.lock().await, "amount=5000&currency=jpy");

    // 4. Test Legacy Path /u/stripe/redirect
    let redirect_req = Request::builder()
        .uri("/u/stripe/redirect")
        .method("GET")
        .header("X-Tenant-ID", "tenant-a")
        .header("X-Gateway-Secret", "test_secret")
        .body(Body::empty())
        .unwrap();

    let redirect_resp = app.oneshot(redirect_req).await.unwrap();
    assert_eq!(redirect_resp.status(), StatusCode::FOUND);
    assert_eq!(
        redirect_resp.headers().get("location").unwrap(),
        "https://example.com/target"
    );
}

/// Test In-Flight Automatic Retry on 429 / 503
#[tokio::test]
async fn test_inflight_retry_on_429_503() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let call_clone = call_count.clone();

    let mock_upstream = Router::new().route(
        "/api/flaky",
        get(move || {
            let count = call_clone.clone();
            async move {
                let current = count.fetch_add(1, Ordering::SeqCst);
                if current < 2 {
                    // First 2 calls return 429
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [("retry-after", "0")],
                        "rate limited upstream",
                    )
                } else {
                    // 3rd call succeeds
                    (
                        StatusCode::OK,
                        [("retry-after", "0")],
                        "success after retry",
                    )
                }
            }
        }),
    );

    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(upstream_listener, mock_upstream).await.unwrap();
    });

    let mut mem_store = MemoryTenantStore::new();
    mem_store.insert(UpstreamConfig {
        tenant_id: "tenant-retry".to_string(),
        upstream: "flaky-svc".to_string(),
        base_url: Url::parse(&format!("http://127.0.0.1:{}", upstream_addr.port())).unwrap(),
        inject: vec![],
        rate_limit: RateLimitConfig {
            rpm: 600,
            burst: 50,
        },
        timeout_secs: 5,
        allowed_domains: None,
    });

    let config = create_test_config();
    let mut state = init_app_state(config).await.unwrap();
    state.tenant_store = Arc::new(mem_store);

    let app = create_router(state);

    let req = Request::builder()
        .uri("/v1/providers/flaky-svc/api/flaky")
        .method("GET")
        .header("X-Tenant-ID", "tenant-retry")
        .header("X-Gateway-Secret", "test_secret")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), "success after retry");
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
}

/// Test Admin API CRUD & Authentication
#[tokio::test]
async fn test_admin_api_crud_and_auth() {
    let config = create_test_config();
    let state = init_app_state(config).await.unwrap();
    let app = create_router(state);

    // 1. Unauthorized when missing Admin API key
    let req = Request::builder()
        .uri("/admin/v1/providers")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Authorized list (initially empty)
    let req = Request::builder()
        .uri("/admin/v1/providers")
        .method("GET")
        .header("X-Admin-Api-Key", "test_admin_key")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Create a provider config via POST
    let new_provider = serde_json::json!({
        "tenant_id": "tenant-dynamic",
        "upstream": "openai",
        "base_url": "https://api.openai.com",
        "inject": [{
            "header": "Authorization",
            "template": "Bearer {secret}",
            "secret_ref": "OPENAI_API_KEY",
            "version": "latest"
        }],
        "rate_limit": {
            "rpm": 300,
            "burst": 30
        },
        "timeout_secs": 60
    });

    let req = Request::builder()
        .uri("/admin/v1/providers")
        .method("POST")
        .header("Authorization", "Bearer test_admin_key")
        .header("Content-Type", "application/json")
        .body(Body::from(new_provider.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. List again to verify
    let req = Request::builder()
        .uri("/admin/v1/providers")
        .method("GET")
        .header("X-Admin-Api-Key", "test_admin_key")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 2048).await.unwrap();
    let list: Vec<UpstreamConfig> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].tenant_id, "tenant-dynamic");
    assert_eq!(list[0].upstream, "openai");

    // 5. Delete provider
    let req = Request::builder()
        .uri("/admin/v1/providers/tenant-dynamic/openai")
        .method("DELETE")
        .header("X-Admin-Api-Key", "test_admin_key")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6. Delete non-existent provider returns 404
    let req = Request::builder()
        .uri("/admin/v1/providers/tenant-dynamic/openai")
        .method("DELETE")
        .header("X-Admin-Api-Key", "test_admin_key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Test Outbound Rate Limiting (429 + Retry-After)
#[tokio::test]
async fn test_rate_limiting_429() {
    let limiter = GovernorRateLimiter::new();
    let config = RateLimitConfig { rpm: 2, burst: 2 };
    let key = RateKey {
        tenant_id: "tenant-limited".to_string(),
        upstream: "fast-service".to_string(),
    };

    // First 2 requests should be allowed
    assert_eq!(limiter.check(&key, &config).await, RateDecision::Allow);
    assert_eq!(limiter.check(&key, &config).await, RateDecision::Allow);

    // 3rd request should be denied (or wait exceeded)
    let decision = limiter.check(&key, &config).await;
    match decision {
        RateDecision::Deny { retry_after_secs } => {
            assert!(retry_after_secs >= 1);
        }
        RateDecision::Allow => panic!("Expected rate limit denial"),
    }
}

/// Test FileSecretStore
#[tokio::test]
async fn test_file_secret_store() {
    let temp_dir =
        std::env::temp_dir().join(format!("watari_secret_test_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let secret_path = temp_dir.join("MY_API_KEY");
    tokio::fs::write(&secret_path, "secret_value_from_file\n")
        .await
        .unwrap();

    let store = FileSecretStore::new(&temp_dir);

    // Normal retrieval
    let secret = store
        .get("MY_API_KEY", &SecretVersion::Latest)
        .await
        .unwrap();
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(&secret),
        "secret_value_from_file"
    );

    // Traversal rejection
    assert!(store.get("../other", &SecretVersion::Latest).await.is_err());
    assert!(store.get("sub/path", &SecretVersion::Latest).await.is_err());

    // Not found
    assert!(store
        .get("NON_EXISTENT", &SecretVersion::Latest)
        .await
        .is_err());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// Test SqliteTenantStore
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_tenant_store() {
    let db_path = format!(
        "sqlite://{}/watari_test_{}.db",
        std::env::temp_dir()
            .display()
            .to_string()
            .replace('\\', "/"),
        uuid::Uuid::new_v4()
    );
    let store = watari::storage::sqlite::SqliteTenantStore::new(&db_path, true)
        .await
        .unwrap();

    let config = UpstreamConfig {
        tenant_id: "tenant-db".to_string(),
        upstream: "sqlite-upstream".to_string(),
        base_url: Url::parse("https://api.example.com").unwrap(),
        inject: vec![InjectRule {
            header: "Authorization".to_string(),
            template: "Bearer {secret}".to_string(),
            secret_ref: "MY_KEY".to_string(),
            version: SecretVersion::Latest,
        }],
        rate_limit: RateLimitConfig {
            rpm: 120,
            burst: 10,
        },
        timeout_secs: 20,
        allowed_domains: None,
    };

    store.upsert(&config).await.unwrap();

    let fetched = store
        .get_upstream("tenant-db", "sqlite-upstream")
        .await
        .unwrap();
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.tenant_id, "tenant-db");
    assert_eq!(fetched.upstream, "sqlite-upstream");
    assert_eq!(fetched.timeout_secs, 20);
    assert_eq!(fetched.rate_limit.rpm, 120);

    let not_found = store.get_upstream("tenant-db", "other").await.unwrap();
    assert!(not_found.is_none());
}
