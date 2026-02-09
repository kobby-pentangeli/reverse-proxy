//! Core proxy handler: request forwarding, body streaming, and filtering.

use std::sync::Arc;

use bytes::Bytes;
use hyper::header::HeaderName;
use hyper::{Body, Client, Method, Request, Response, Uri};

use crate::{ProxyError, Result, RuntimeConfig};

/// The HTTP client type used for upstream connections.
pub type HttpClient = Client<hyper::client::HttpConnector>;

/// Processes a single inbound request through the proxy pipeline.
///
/// The pipeline performs the following steps in order:
///
/// 1. **GET inspection** — If the request method is GET, blocked headers and
///    query parameters are checked. Requests matching any block rule receive
///    a 403 Forbidden response.
/// 2. **URI rewriting** — The request URI is rewritten to target the configured
///    upstream, preserving the original path and query string.
/// 3. **Header forwarding** — Original request headers are carried through,
///    with blocked headers stripped from the outgoing request.
/// 4. **Body streaming** — The request body is passed through to the upstream
///    without buffering.
/// 5. **Response masking** — For text-based upstream responses, sensitive
///    parameter values are masked before returning to the client.
///
/// Non-GET methods skip the blocking inspection entirely and are forwarded
/// directly to the upstream.
pub async fn handle_request(
    req: Request<Body>,
    client: HttpClient,
    config: Arc<RuntimeConfig>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let original_uri = req.uri().clone();

    if method == Method::GET {
        inspect_get_request(&req, &config)?;
    }

    let upstream_uri = rewrite_uri(&original_uri, &config.upstream)?;
    let proxy_req = build_upstream_request(&req, upstream_uri, &config)?;

    let (req_parts, body) = req.into_parts();
    let _ = req_parts;

    let mut final_req = Request::from_parts(proxy_req.into_parts().0, body);
    *final_req.method_mut() = method;

    let upstream_resp = client.request(final_req).await?;
    build_response(upstream_resp, &config).await
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
        .map_or(Ok(()), |name| Err(ProxyError::BlockedHeader(name.clone())))?;

    let query = req.uri().query().unwrap_or_default();
    config
        .blocked_params
        .iter()
        .find(|param| query.contains(&format!("{param}=")))
        .map_or(Ok(()), |name| Err(ProxyError::BlockedParam(name.clone())))
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

/// Constructs the upstream request with headers forwarded and blocked
/// headers stripped.
fn build_upstream_request(
    original: &Request<Body>,
    upstream_uri: Uri,
    config: &RuntimeConfig,
) -> Result<Request<Body>> {
    let mut builder = Request::builder()
        .method(original.method())
        .uri(upstream_uri);

    let outgoing_headers = builder
        .headers_mut()
        .ok_or_else(|| ProxyError::Internal("failed to access request headers".into()))?;

    original
        .headers()
        .iter()
        .filter(|(name, _)| {
            !config
                .blocked_headers
                .iter()
                .any(|blocked| blocked == name.as_str())
        })
        .for_each(|(name, value)| {
            outgoing_headers.insert(name.clone(), value.clone());
        });

    builder
        .body(Body::empty())
        .map_err(|e| ProxyError::Internal(format!("failed to build upstream request: {e}")))
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
        .map_err(|e| ProxyError::Upstream(format!("failed to read upstream body: {e}")))?;

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

    #[test]
    fn build_upstream_request_strips_blocked_headers() {
        let config = Config {
            upstream: "http://localhost:3000".into(),
            blocked_headers: vec!["x-strip-me".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let original = Request::builder()
            .uri("http://example.com/")
            .header("x-strip-me", "gone")
            .header("x-keep-me", "stay")
            .body(Body::empty())
            .unwrap();

        let upstream_uri = parse_uri("http://localhost:3000/");
        let result = build_upstream_request(&original, upstream_uri, &config).unwrap();

        assert!(!result.headers().contains_key("x-strip-me"));
        assert!(result.headers().contains_key("x-keep-me"));
    }
}
