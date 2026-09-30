use crate::storage::InjectRule;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Sanitize request headers and inject secrets.
pub fn sanitize_and_inject_request_headers(
    incoming_headers: &HeaderMap,
    request_id: &str,
    inject_rules: &[(InjectRule, SecretString)],
) -> HeaderMap {
    let mut outgoing = HeaderMap::new();

    // 1. Identify custom hop-by-hop headers from Connection header
    let mut custom_hop_by_hop = HashSet::new();
    if let Some(conn_val) = incoming_headers.get(axum::http::header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            for h in conn_str.split(',') {
                let trimmed = h.trim().to_lowercase();
                if !trimmed.is_empty() {
                    custom_hop_by_hop.insert(trimmed);
                }
            }
        }
    }

    // 2. Identify inject header names (case-insensitive)
    let inject_names: HashSet<String> = inject_rules
        .iter()
        .map(|(rule, _)| rule.header.to_lowercase())
        .collect();

    // 3. Filter client headers
    for (key, value) in incoming_headers.iter() {
        let key_str = key.as_str().to_lowercase();

        // Always strip internal/gateway headers
        if key_str == "x-tenant-id"
            || key_str == "x-gateway-secret"
            || key_str == "authorization"
            || key_str == "cookie"
            || key_str == "proxy-authorization"
            || key_str == "host"
        {
            continue;
        }

        // Strip standard hop-by-hop
        if HOP_BY_HOP_HEADERS.contains(&key_str.as_str()) {
            continue;
        }

        // Strip custom connection hop-by-hop
        if custom_hop_by_hop.contains(&key_str) {
            continue;
        }

        // Strip headers that will be injected
        if inject_names.contains(&key_str) {
            continue;
        }

        outgoing.insert(key.clone(), value.clone());
    }

    // 4. Attach or propagate X-Request-ID
    if let Ok(req_id_val) = HeaderValue::from_str(request_id) {
        outgoing.insert(HeaderName::from_static("x-request-id"), req_id_val);
    }

    // 5. Inject secrets
    for (rule, secret) in inject_rules {
        let injected_value_str = rule.template.replace("{secret}", secret.expose_secret());
        if let Ok(header_name) = HeaderName::from_bytes(rule.header.as_bytes()) {
            if let Ok(mut header_val) = HeaderValue::from_str(&injected_value_str) {
                // Mark header value as sensitive to prevent leakage in debug/logs
                header_val.set_sensitive(true);
                outgoing.insert(header_name, header_val);
            }
        }
    }

    outgoing
}

/// Sanitize response headers from upstream before returning to client.
pub fn sanitize_response_headers(upstream_headers: &HeaderMap) -> HeaderMap {
    let mut outgoing = HeaderMap::new();

    let mut custom_hop_by_hop = HashSet::new();
    if let Some(conn_val) = upstream_headers.get(axum::http::header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            for h in conn_str.split(',') {
                let trimmed = h.trim().to_lowercase();
                if !trimmed.is_empty() {
                    custom_hop_by_hop.insert(trimmed);
                }
            }
        }
    }

    for (key, value) in upstream_headers.iter() {
        let key_str = key.as_str().to_lowercase();

        if HOP_BY_HOP_HEADERS.contains(&key_str.as_str()) || custom_hop_by_hop.contains(&key_str) {
            continue;
        }

        outgoing.insert(key.clone(), value.clone());
    }

    outgoing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SecretVersion;

    #[test]
    fn test_sanitize_and_inject_headers() {
        let mut incoming = HeaderMap::new();
        incoming.insert("x-tenant-id", HeaderValue::from_static("tenant-a"));
        incoming.insert("x-gateway-secret", HeaderValue::from_static("secret123"));
        incoming.insert(
            "authorization",
            HeaderValue::from_static("Bearer client_token"),
        );
        incoming.insert("cookie", HeaderValue::from_static("session=abc"));
        incoming.insert("host", HeaderValue::from_static("watari:8080"));
        incoming.insert("connection", HeaderValue::from_static("keep-alive, x-foo"));
        incoming.insert("x-foo", HeaderValue::from_static("bar"));
        incoming.insert("x-custom-pass", HeaderValue::from_static("pass-me"));

        let inject_rules = vec![(
            InjectRule {
                header: "Authorization".to_string(),
                template: "Bearer {secret}".to_string(),
                secret_ref: "STRIPE_KEY".to_string(),
                version: SecretVersion::Latest,
            },
            SecretString::new("injected_stripe_secret".into()),
        )];

        let out = sanitize_and_inject_request_headers(&incoming, "req-123", &inject_rules);

        assert!(!out.contains_key("x-tenant-id"));
        assert!(!out.contains_key("x-gateway-secret"));
        assert!(!out.contains_key("cookie"));
        assert!(!out.contains_key("host"));
        assert!(!out.contains_key("connection"));
        assert!(!out.contains_key("x-foo"));
        assert_eq!(out.get("x-custom-pass").unwrap(), "pass-me");
        assert_eq!(out.get("x-request-id").unwrap(), "req-123");

        let auth_val = out.get("authorization").unwrap();
        assert_eq!(auth_val.to_str().unwrap(), "Bearer injected_stripe_secret");
        assert!(auth_val.is_sensitive());
    }
}
