//! Core proxy handler: request forwarding, body streaming, and filtering.
//!
//! Implements the full proxy pipeline including HTTP spec compliance
//! (hop-by-hop header stripping, forwarding headers, request smuggling
//! defense) and policy enforcement (header/param blocking, body size
//! limits, response masking).
//!
//! Every inbound request is assigned a monotonically increasing request ID
//! and wrapped in a [`tracing::Span`] carrying structured fields for
//! observability.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use hyper::header::HeaderName;
use hyper::{Body, Client, Method, Request, Response, Uri};
use tokio::time::timeout;
use tracing::{Instrument, debug, info, warn};

use crate::{ProxyError, Result, RuntimeConfig, headers};

/// The HTTP client type used for upstream connections.
pub type HttpClient = Client<hyper::client::HttpConnector>;

/// Global monotonic counter for assigning unique request IDs.
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Processes a single inbound request through the proxy pipeline.
///
/// The pipeline performs the following steps in order:
///
/// 1. **Request smuggling defense** — Rejects requests carrying both
///    `Content-Length` and `Transfer-Encoding` headers (RFC 7230 §3.3.3).
/// 2. **Body size enforcement** — Rejects requests whose `Content-Length`
///    exceeds the configured `max_body_size` with 413 Payload Too Large.
/// 3. **GET inspection** — If the request method is GET, blocked headers and
///    query parameters are checked. Requests matching any block rule receive
///    a 403 Forbidden response.
/// 4. **Hop-by-hop stripping** — Connection-scoped headers are removed
///    before forwarding, per RFC 7230 §6.1.
/// 5. **Forwarding headers** — `X-Forwarded-For`, `X-Forwarded-Proto`, and
///    `X-Forwarded-Host` are injected to preserve client origin metadata.
/// 6. **Host rewriting** — The `Host` header is set to the upstream authority.
/// 7. **URI rewriting** — The request URI is rewritten to target the configured
///    upstream, preserving the original path and query string.
/// 8. **Body streaming** — The request body is passed through to the upstream
///    without buffering.
/// 9. **Response hop-by-hop stripping** — Connection-scoped headers are
///    removed from the upstream response.
/// 10. **Response header stripping** — Configured internal headers (e.g.
///     `Server`, `X-Powered-By`) are removed from the response.
/// 11. **Response masking** — For text-based upstream responses, sensitive
///     parameter values are masked before returning to the client.
pub async fn handle_request(
    req: Request<Body>,
    client: HttpClient,
    config: Arc<RuntimeConfig>,
    client_addr: SocketAddr,
) -> Result<Response<Body>> {
    let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let method = req.method().clone();
    let uri = req.uri().clone();

    let span = tracing::info_span!(
        "request",
        id = request_id,
        method = %method,
        uri = %uri,
        client = %client_addr,
    );

    async move {
        info!(upstream = %config.upstream, "received request");

        if headers::is_smuggling_attempt(req.headers()) {
            warn!("request smuggling attempt detected");
            return Err(ProxyError::RequestSmuggling);
        }

        if headers::content_length_exceeds(req.headers(), config.max_body_size) {
            let declared = req
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            warn!(
                content_length = declared,
                limit = config.max_body_size,
                "request body exceeds size limit"
            );
            return Err(ProxyError::BodyTooLarge {
                limit: config.max_body_size,
            });
        }

        if method == Method::GET {
            inspect_get_request(&req, &config)?;
        }

        let upstream_uri = rewrite_uri(&uri, &config.upstream)?;
        let (mut parts, body) = req.into_parts();

        headers::strip_hop_by_hop(&mut parts.headers);
        headers::inject_forwarding_headers(&mut parts.headers, client_addr);
        headers::rewrite_host(
            &mut parts.headers,
            config
                .upstream
                .authority()
                .ok_or_else(|| ProxyError::InvalidUpstream("upstream has no authority".into()))?,
        );

        config.blocked_headers.iter().for_each(|blocked| {
            if let Ok(name) = HeaderName::from_bytes(blocked.as_bytes()) {
                parts.headers.remove(&name);
            }
        });

        parts.uri = upstream_uri;
        parts.method = method;

        debug!(
            headers = ?parts.headers,
            upstream_uri = %parts.uri,
            "forwarding request"
        );

        let start = std::time::Instant::now();
        let proxy_req = Request::from_parts(parts, body);

        let upstream_result = timeout(config.request_timeout, client.request(proxy_req)).await;

        let mut upstream_resp = match upstream_result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                warn!(
                    error = %e,
                    latency_ms = start.elapsed().as_millis() as u64,
                    "upstream request failed"
                );
                return Err(ProxyError::Upstream(e));
            }
            Err(_elapsed) => {
                warn!(
                    timeout = ?config.request_timeout,
                    latency_ms = start.elapsed().as_millis() as u64,
                    "upstream request timed out"
                );
                return Err(ProxyError::Timeout(config.request_timeout));
            }
        };

        let latency_ms = start.elapsed().as_millis() as u64;
        info!(
            status = upstream_resp.status().as_u16(),
            latency_ms, "upstream responded"
        );

        headers::strip_hop_by_hop(upstream_resp.headers_mut());
        if !config.strip_response_headers.is_empty() {
            headers::strip_response_headers(
                upstream_resp.headers_mut(),
                &config.strip_response_headers,
            );
        }

        build_response(upstream_resp, &config).await
    }
    .instrument(span)
    .await
}

/// Checks a GET request against configured block rules.
///
/// Returns `ProxyError::BlockedHeader` or `ProxyError::BlockedParam`
/// if any rule matches, allowing the caller to short-circuit with a 403.
fn inspect_get_request(req: &Request<Body>, config: &RuntimeConfig) -> Result<()> {
    let headers = req.headers();
    config
        .blocked_headers
        .iter()
        .find(|blocked| {
            HeaderName::from_bytes(blocked.as_bytes())
                .ok()
                .is_some_and(|name| headers.contains_key(&name))
        })
        .map_or(Ok(()), |name| {
            warn!(header = %name, "blocked header detected");
            Err(ProxyError::BlockedHeader(name.clone()))
        })?;

    let query = req.uri().query().unwrap_or_default();
    config
        .blocked_params
        .iter()
        .find(|param| query.contains(&format!("{param}=")))
        .map_or(Ok(()), |name| {
            warn!(param = %name, "blocked parameter detected");
            Err(ProxyError::BlockedParam(name.clone()))
        })
}

/// Rewrites the original request URI to target the configured upstream,
/// preserving the path and query string.
fn rewrite_uri(original: &Uri, upstream: &Uri) -> Result<Uri> {
    let authority = upstream
        .authority()
        .ok_or_else(|| ProxyError::InvalidUpstream("upstream has no authority".into()))?;

    let scheme = upstream
        .scheme()
        .ok_or_else(|| ProxyError::InvalidUpstream("upstream has no scheme".into()))?;

    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| ProxyError::Internal(format!("failed to build upstream URI: {e}")))
}

/// Builds the client-facing response from the upstream response.
///
/// For responses whose `Content-Type` indicates text or form-encoded data,
/// the body is collected and scanned for sensitive parameter values. All
/// other responses are streamed through unmodified.
async fn build_response(
    upstream_resp: Response<Body>,
    config: &RuntimeConfig,
) -> Result<Response<Body>> {
    if config.mask_rules.is_empty() {
        return Ok(upstream_resp);
    }

    let should_mask = upstream_resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .is_some_and(|ct| ct.contains("text/") || ct.contains("application/x-www-form-urlencoded"));

    if !should_mask {
        return Ok(upstream_resp);
    }

    let (parts, body) = upstream_resp.into_parts();
    let body_bytes = hyper::body::to_bytes(body)
        .await
        .map_err(|e| ProxyError::Internal(format!("failed to read upstream body: {e}")))?;

    let body_str = String::from_utf8_lossy(&body_bytes);
    let masked = config.mask_sensitive_data(&body_str);

    let mut response = Response::new(Body::from(Bytes::from(masked)));
    *response.status_mut() = parts.status;
    *response.headers_mut() = parts.headers;
    *response.version_mut() = parts.version;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn parse_uri(uri: &str) -> Uri {
        uri.parse::<Uri>().expect("failed to parse URI")
    }

    #[test]
    fn rewrite_uri_preserves_path_and_query() {
        let original = parse_uri("http://client-facing.com/api/v1?key=val");
        let upstream = parse_uri("http://localhost:3000");

        let result = rewrite_uri(&original, &upstream).unwrap();
        assert_eq!(result.scheme_str(), Some("http"));
        assert_eq!(result.authority().unwrap().as_str(), "localhost:3000");
        assert_eq!(result.path_and_query().unwrap().as_str(), "/api/v1?key=val");
    }

    #[test]
    fn rewrite_uri_defaults_to_root_path() {
        let original = parse_uri("http://client-facing.com");
        let upstream = parse_uri("http://localhost:3000");

        let result = rewrite_uri(&original, &upstream).unwrap();
        assert_eq!(result.path_and_query().unwrap().as_str(), "/");
    }

    #[test]
    fn inspect_get_detects_blocked_header() {
        let config = Config {
            upstream: "http://localhost:3000".into(),
            blocked_headers: vec!["x-bad-header".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/")
            .header("x-bad-header", "anything")
            .body(Body::empty())
            .unwrap();

        let result = inspect_get_request(&req, &config);
        assert!(result.is_err());
    }

    #[test]
    fn inspect_get_detects_blocked_param() {
        let config = Config {
            upstream: "http://localhost:3000".into(),
            blocked_params: vec!["secret_key".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/?secret_key=abc123")
            .body(Body::empty())
            .unwrap();

        let result = inspect_get_request(&req, &config);
        assert!(result.is_err());
    }

    #[test]
    fn inspect_get_allows_clean_request() {
        let config = Config {
            upstream: "http://localhost:3000".into(),
            blocked_headers: vec!["x-bad-header".into()],
            blocked_params: vec!["secret_key".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/path?safe=true")
            .header("x-good-header", "ok")
            .body(Body::empty())
            .unwrap();

        assert!(inspect_get_request(&req, &config).is_ok());
    }
}
