//! Telemetry primitives shared by VSR runtime layers.
//!
//! This module is intentionally dependency-light. Without the `tracing` and
//! `metrics` features, recording helpers compile to no-ops.

/// HTTP request telemetry event recorded by runtime adapters.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpRequestTelemetry<'a> {
    /// HTTP method, for example `GET`.
    pub method: &'a str,
    /// Route pattern or request path.
    pub route: &'a str,
    /// HTTP response status code.
    pub status: u16,
    /// Request latency in milliseconds.
    pub latency_ms: f64,
}

impl<'a> HttpRequestTelemetry<'a> {
    /// Create a new HTTP request telemetry event.
    pub const fn new(method: &'a str, route: &'a str, status: u16, latency_ms: f64) -> Self {
        Self {
            method,
            route,
            status,
            latency_ms,
        }
    }
}

/// Record one HTTP request event.
pub fn record_http_request(event: &HttpRequestTelemetry<'_>) {
    record_http_request_trace(event);
    record_http_request_metrics(event);
}

#[cfg(feature = "tracing")]
fn record_http_request_trace(event: &HttpRequestTelemetry<'_>) {
    tracing::info!(
        target: "vsr.http",
        method = event.method,
        route = event.route,
        status = event.status,
        latency_ms = event.latency_ms,
        "request completed",
    );
}

#[cfg(not(feature = "tracing"))]
const fn record_http_request_trace(_event: &HttpRequestTelemetry<'_>) {}

#[cfg(feature = "metrics")]
fn record_http_request_metrics(event: &HttpRequestTelemetry<'_>) {
    let status = event.status.to_string();
    metrics::counter!(
        "vsr_http_requests_total",
        "method" => event.method.to_owned(),
        "route" => event.route.to_owned(),
        "status" => status.clone(),
    )
    .increment(1);
    metrics::histogram!(
        "vsr_http_request_latency_ms",
        "method" => event.method.to_owned(),
        "route" => event.route.to_owned(),
        "status" => status,
    )
    .record(event.latency_ms);
}

#[cfg(not(feature = "metrics"))]
const fn record_http_request_metrics(_event: &HttpRequestTelemetry<'_>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_telemetry_constructor_preserves_fields() {
        let event = HttpRequestTelemetry::new("GET", "/healthz", 200, 1.25);
        assert_eq!(event.method, "GET");
        assert_eq!(event.route, "/healthz");
        assert_eq!(event.status, 200);
        assert_eq!(event.latency_ms, 1.25);
    }
}
