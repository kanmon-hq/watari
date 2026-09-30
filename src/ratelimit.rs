use crate::storage::RateLimitConfig;
use async_trait::async_trait;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::InMemoryState;
use governor::{Quota, RateLimiter as GovRateLimiter};
use moka::future::Cache;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateKey {
    pub tenant_id: String,
    pub upstream: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Deny { retry_after_secs: u64 },
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: &RateKey, config: &RateLimitConfig) -> RateDecision;
}

type DirectLimiter =
    GovRateLimiter<governor::state::NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Governor-backed rate limiter implementation caching limiters per (tenant, upstream).
#[derive(Clone)]
pub struct GovernorRateLimiter {
    cache: Cache<RateKey, Arc<DirectLimiter>>,
}

impl GovernorRateLimiter {
    pub fn new() -> Self {
        let cache = Cache::builder()
            .time_to_idle(Duration::from_secs(3600))
            .max_capacity(100000)
            .build();

        Self { cache }
    }
}

impl Default for GovernorRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RateLimiter for GovernorRateLimiter {
    async fn check(&self, key: &RateKey, config: &RateLimitConfig) -> RateDecision {
        let key_clone = key.clone();
        let rpm = NonZeroU32::new(config.rpm.max(1)).unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(config.burst.max(1)).unwrap_or(NonZeroU32::MIN);

        let limiter = self
            .cache
            .get_with(key_clone, async move {
                let quota = Quota::per_minute(rpm).allow_burst(burst);
                Arc::new(GovRateLimiter::direct(quota))
            })
            .await;

        match limiter.check() {
            Ok(_) => RateDecision::Allow,
            Err(negative) => {
                let wait_duration =
                    negative.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
                let secs = wait_duration.as_secs().max(1);
                RateDecision::Deny {
                    retry_after_secs: secs,
                }
            }
        }
    }
}
