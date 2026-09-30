use crate::egress::SsrfSafeResolver;
use reqwest::redirect::Policy;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;

/// Build shared reqwest::Client with SSRF guard and TLS configuration.
pub fn create_proxy_client(allow_private_ips: bool) -> Result<Client, String> {
    let resolver = Arc::new(SsrfSafeResolver::new(allow_private_ips));

    Client::builder()
        .dns_resolver(resolver)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .build()
        .map_err(|e| format!("failed to build reqwest proxy client: {e}"))
}
