//! An HTTP reverse proxy built on [hyper] and [tokio].
//!
//! This crate provides the core proxy logic: configuration loading with
//! pre-compiled regex patterns, request forwarding with body streaming,
//! header and parameter blocking for GET requests, sensitive data
//! masking in response bodies, structured observability via [tracing],
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

pub mod config;
pub mod error;
pub mod headers;
pub mod proxy;

pub use config::{Config, RuntimeConfig};
pub use error::ProxyError;
pub use proxy::{HttpClient, handle_request};

pub type Result<T> = std::result::Result<T, ProxyError>;
