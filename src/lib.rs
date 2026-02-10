//! An HTTP reverse proxy built on [hyper] and [tokio].
//!
//! This crate provides the core proxy logic: configuration loading with
//! pre-compiled regex patterns, request forwarding with body streaming,
//! header and parameter blocking for GET requests, sensitive data
//! masking in response bodies, weighted round-robin load balancing with
//! passive and active health checks, structured observability via [tracing],
//! configurable timeouts, connection pool tuning, concurrency limiting,
//! and graceful shutdown.
//!
//! Every inbound request is assigned a monotonic request ID and wrapped
//! in a [`tracing::Span`] carrying the request method, URI, and client
//! address as structured fields.
//!
//! [hyper]: https://hyper.rs/
//! [tokio]: https://tokio.rs/
//! [tracing]: https://docs.rs/tracing

pub mod balancer;
pub mod config;
pub mod error;
pub mod headers;
pub mod proxy;
pub mod tls;
pub mod upstream;

pub use balancer::LoadBalancer;
pub use config::{Config, HealthCheckConfig, RuntimeConfig, TlsConfig, UpstreamConfig};
pub use error::ProxyError;
pub use proxy::{
    BoxBody, HttpClient, HttpsClient, build_client, build_https_client, handle_request,
};
pub use upstream::{UpstreamPool, UpstreamState};

pub type Result<T> = std::result::Result<T, ProxyError>;
