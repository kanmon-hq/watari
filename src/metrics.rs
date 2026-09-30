use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the Prometheus metrics recorder globally.
/// If already initialized, returns the existing handle.
pub fn init_metrics_recorder() -> PrometheusHandle {
    PROMETHEUS_HANDLE
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus metrics recorder");

            // Register descriptions for Prometheus help text
            metrics::describe_counter!(
                "watari_requests_total",
                "Total number of HTTP proxy requests processed"
            );
            metrics::describe_histogram!(
                "watari_request_duration_seconds",
                "Histogram of proxy request latency in seconds"
            );
            metrics::describe_counter!(
                "watari_rate_limited_total",
                "Total number of requests blocked by rate limiter"
            );
            metrics::describe_counter!(
                "watari_egress_blocked_total",
                "Total number of requests blocked by SSRF/egress guard"
            );
            metrics::describe_gauge!(
                "watari_build_info",
                "Build metadata and version info of Watari"
            );

            // Record startup info metric
            metrics::gauge!(
                "watari_build_info",
                "version" => env!("CARGO_PKG_VERSION")
            )
            .set(1.0);

            handle
        })
        .clone()
}
