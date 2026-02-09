//! An HTTP reverse proxy built on [hyper] and [tokio].
//!
//! This crate provides the core proxy logic: configuration loading with
//! pre-compiled regex patterns, request forwarding with body streaming,
//! header and parameter blocking for GET requests, and sensitive data
//! masking in response bodies.
//!
//! [hyper]: https://hyper.rs/
//! [tokio]: https://tokio.rs/

pub mod config;
pub mod error;
pub mod headers;
pub mod proxy;

pub use config::{Config, RuntimeConfig};
pub use error::ProxyError;
pub use proxy::{HttpClient, handle_request};

pub type Result<T> = std::result::Result<T, ProxyError>;
