//! Error types and HTTP status code mapping.

use hyper::{Body, Response, StatusCode};
use std::fmt;

/// Every failure the proxy can produce, each mapping to a specific HTTP status.
#[derive(Debug)]
pub enum ProxyError {
    /// The configuration file could not be loaded or parsed.
    Config(String),
    /// The upstream target URI is malformed or unparseable.
    InvalidUpstream(String),
    /// A blocked header was detected in the incoming request.
    BlockedHeader(String),
    /// A blocked query parameter was detected in the incoming request.
    BlockedParam(String),
    /// The upstream server returned an error or was unreachable.
    Upstream(String),
    /// An internal error that does not fit other categories.
    Internal(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::InvalidUpstream(msg) => write!(f, "invalid upstream: {msg}"),
            Self::BlockedHeader(name) => write!(f, "blocked header: {name}"),
            Self::BlockedParam(name) => write!(f, "blocked parameter: {name}"),
            Self::Upstream(msg) => write!(f, "upstream error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl ProxyError {
    /// Returns the HTTP status code corresponding to this error variant.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Config(_) | Self::Internal(_) | Self::InvalidUpstream(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::BlockedHeader(_) | Self::BlockedParam(_) => StatusCode::FORBIDDEN,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    /// Converts this error into an HTTP response with a JSON body.
    pub fn into_response(self) -> Response<Body> {
        let status = self.status_code();
        let body = serde_json::json!({
            "error": match &self {
                Self::Config(_) => "config_error",
                Self::InvalidUpstream(_) => "invalid_upstream",
                Self::BlockedHeader(_) => "blocked_header",
                Self::BlockedParam(_) => "blocked_param",
                Self::Upstream(_) => "upstream_error",
                Self::Internal(_) => "internal_error",
            },
            "message": self.to_string(),
        });

        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .expect("building fallback response must not fail")
            })
    }
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        Self::Upstream(err.to_string())
    }
}

impl From<hyper::http::Error> for ProxyError {
    fn from(err: hyper::http::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<hyper::header::InvalidHeaderValue> for ProxyError {
    fn from(err: hyper::header::InvalidHeaderValue) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<hyper::header::InvalidHeaderName> for ProxyError {
    fn from(err: hyper::header::InvalidHeaderName) -> Self {
        Self::Internal(err.to_string())
    }
}
