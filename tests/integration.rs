//! Integration tests using a local hyper backend server.
//!
//! Each test spins up a throwaway HTTP server on an OS-assigned port,
//! configures the proxy to point at it, and exercises the full
//! `handle_request` pipeline without touching the network.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use reverse_proxy::{Config, HttpClient, RuntimeConfig, handle_request};
use tokio::sync::oneshot;

/// A synthetic client address used in all test invocations.
const TEST_CLIENT_ADDR: &str = "192.168.1.100:54321";

fn test_addr() -> SocketAddr {
    TEST_CLIENT_ADDR.parse().unwrap()
}

/// Starts a local HTTP server that responds to every request with the given
/// status, content-type, and body. Returns the server address and a handle
/// to shut it down.
async fn start_backend(
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
) -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let make_svc = make_service_fn(move |_| {
        let body = body;
        let content_type = content_type;
        let status = status;
        async move {
            Ok::<_, std::convert::Infallible>(service_fn(move |_req: Request<Body>| {
                let body = body;
                let content_type = content_type;
                let status = status;
                async move {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(status)
                            .header("content-type", content_type)
                            .body(Body::from(body))
                            .expect("test response must build"),
                    )
                }
            }))
        }
    });

    let server = Server::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).serve(make_svc);
    let addr = server.local_addr();

    tokio::spawn(async move {
        let graceful = server.with_graceful_shutdown(async {
            let _ = rx.await;
        });
        let _ = graceful.await;
    });

    (addr, tx)
}

/// Starts a local backend that captures and echoes request headers as the
/// response body. Used to verify that the proxy correctly transforms headers.
async fn start_echo_headers_backend() -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let make_svc = make_service_fn(|_| async {
        Ok::<_, std::convert::Infallible>(service_fn(|req: Request<Body>| async move {
            let mut lines = Vec::new();
            for (name, value) in req.headers() {
                if let Ok(v) = value.to_str() {
                    lines.push(format!("{}: {}", name.as_str(), v));
                }
            }
            lines.sort();
            let body = lines.join("\n");
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .body(Body::from(body))
                    .expect("test response must build"),
            )
        }))
    });

    let server = Server::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).serve(make_svc);
    let addr = server.local_addr();

    tokio::spawn(async move {
        let graceful = server.with_graceful_shutdown(async {
            let _ = rx.await;
        });
        let _ = graceful.await;
    });

    (addr, tx)
}

/// Starts a backend that returns responses with internal implementation headers.
async fn start_leaky_backend() -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let make_svc = make_service_fn(|_| async {
        Ok::<_, std::convert::Infallible>(service_fn(|_req: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .header("server", "Apache/2.4.52")
                    .header("x-powered-by", "PHP/8.1")
                    .header("connection", "keep-alive")
                    .header("keep-alive", "timeout=5")
                    .body(Body::from("ok"))
                    .expect("test response must build"),
            )
        }))
    });

    let server = Server::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).serve(make_svc);
    let addr = server.local_addr();

    tokio::spawn(async move {
        let graceful = server.with_graceful_shutdown(async {
            let _ = rx.await;
        });
        let _ = graceful.await;
    });

    (addr, tx)
}

/// Builds a `RuntimeConfig` targeting the given local backend address.
fn test_config(addr: SocketAddr) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstream: format!("http://{addr}"),
            blocked_headers: vec!["x-blocked".into()],
            blocked_params: vec!["secret_key".into()],
            masked_params: vec!["password".into(), "ssn".into()],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a `RuntimeConfig` with response header stripping enabled.
fn test_config_with_stripping(addr: SocketAddr) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstream: format!("http://{addr}"),
            strip_response_headers: vec!["server".into(), "x-powered-by".into()],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a `RuntimeConfig` with a specific body size limit.
fn test_config_with_body_limit(addr: SocketAddr, limit: u64) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstream: format!("http://{addr}"),
            max_body_size: Some(limit),
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

fn test_client() -> HttpClient {
    Client::new()
}

#[tokio::test]
async fn get_request_forwards_to_upstream() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "hello").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/path?q=1"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    assert_eq!(body, Bytes::from("hello"));
}

#[tokio::test]
async fn post_request_forwards_without_inspection() {
    let (addr, _shutdown) =
        start_backend(StatusCode::CREATED, "application/json", r#"{"id":1}"#).await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/resource"))
        .header("x-blocked", "should-not-matter-for-post")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn put_request_forwards_without_inspection() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "updated").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("http://{addr}/resource/1"))
        .body(Body::from("new content"))
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_request_forwards_without_inspection() {
    let (addr, _shutdown) = start_backend(StatusCode::NO_CONTENT, "text/plain", "").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("http://{addr}/resource/1"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn get_blocked_header_returns_403() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "should not reach").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("x-blocked", "present")
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap_err()
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_blocked_param_returns_403() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "should not reach").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/?secret_key=abc"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap_err()
        .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn response_body_masking_replaces_sensitive_params() {
    let (addr, _shutdown) = start_backend(
        StatusCode::OK,
        "application/x-www-form-urlencoded",
        "user=alice&password=hunter2&ssn=123-45-6789",
    )
    .await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);

    assert!(body_str.contains("password=****"));
    assert!(body_str.contains("ssn=****"));
    assert!(body_str.contains("user=alice"));
}

#[tokio::test]
async fn response_body_not_masked_for_json_content_type() {
    let (addr, _shutdown) = start_backend(
        StatusCode::OK,
        "application/json",
        r#"{"password":"secret"}"#,
    )
    .await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    assert_eq!(body, Bytes::from(r#"{"password":"secret"}"#));
}

#[tokio::test]
async fn no_masking_when_mask_rules_empty() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "password=visible").await;

    let config = Arc::new(
        Config {
            upstream: format!("http://{addr}"),
            masked_params: vec![],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    assert_eq!(body, Bytes::from("password=visible"));
}

#[tokio::test]
async fn upstream_preserves_status_code() {
    let (addr, _shutdown) = start_backend(StatusCode::NOT_FOUND, "text/plain", "not found").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/missing"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn smuggling_attempt_returns_400() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "unreachable").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .header("content-length", "5")
        .header("transfer-encoding", "chunked")
        .body(Body::from("hello"))
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap_err()
        .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn body_too_large_returns_413() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "unreachable").await;
    let config = test_config_with_body_limit(addr, 100);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .header("content-length", "1000")
        .body(Body::from("x".repeat(1000)))
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap_err()
        .into_response();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn body_within_limit_succeeds() {
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config_with_body_limit(addr, 1000);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .header("content-length", "5")
        .body(Body::from("hello"))
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn forwarding_headers_injected_to_upstream() {
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/test"))
        .header("host", "client-facing.example.com")
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains("x-forwarded-for: 192.168.1.100"),
        "missing x-forwarded-for in: {body_str}"
    );
    assert!(
        body_str.contains("x-forwarded-proto: http"),
        "missing x-forwarded-proto in: {body_str}"
    );
    assert!(
        body_str.contains("x-forwarded-host: client-facing.example.com"),
        "missing x-forwarded-host in: {body_str}"
    );
}

#[tokio::test]
async fn host_header_rewritten_to_upstream() {
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("host", "original-host.com")
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains(&format!("host: {addr}")),
        "host should be rewritten to upstream authority, got: {body_str}"
    );
}

#[tokio::test]
async fn hop_by_hop_headers_stripped_from_request() {
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("connection", "keep-alive")
        .header("keep-alive", "timeout=5")
        .header("proxy-authorization", "Bearer token123")
        .header("x-custom", "preserved")
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        !body_str.contains("connection:"),
        "connection header should be stripped: {body_str}"
    );
    assert!(
        !body_str.contains("keep-alive:"),
        "keep-alive header should be stripped: {body_str}"
    );
    assert!(
        !body_str.contains("proxy-authorization:"),
        "proxy-authorization should be stripped: {body_str}"
    );
    assert!(
        body_str.contains("x-custom: preserved"),
        "x-custom should be preserved: {body_str}"
    );
}

#[tokio::test]
async fn response_strips_internal_and_hop_by_hop_headers() {
    let (addr, _shutdown) = start_leaky_backend().await;
    let config = test_config_with_stripping(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(Body::empty())
        .unwrap();

    let resp = handle_request(req, test_client(), config, test_addr())
        .await
        .unwrap();

    assert!(
        !resp.headers().contains_key("server"),
        "server header should be stripped"
    );
    assert!(
        !resp.headers().contains_key("x-powered-by"),
        "x-powered-by header should be stripped"
    );
    assert!(
        !resp.headers().contains_key("connection"),
        "connection hop-by-hop header should be stripped"
    );
    assert!(
        !resp.headers().contains_key("keep-alive"),
        "keep-alive hop-by-hop header should be stripped"
    );
    assert!(resp.headers().contains_key("content-type"));
}
