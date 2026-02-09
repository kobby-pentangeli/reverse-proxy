use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Response, Server};
use reverse_proxy::{Config, ProxyError, handle_request};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const CONFIG_FILE_PATH: &str = "./Config.yml";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config = Config::load_from_file(CONFIG_FILE_PATH)
        .and_then(|c| c.into_runtime())
        .unwrap_or_else(|e| {
            error!(%e, "failed to load configuration");
            std::process::exit(1);
        });

    info!(
        upstream = %config.upstream,
        blocked_headers = config.blocked_headers.len(),
        blocked_params = config.blocked_params.len(),
        mask_rules = config.mask_rules.len(),
        max_body_size = config.max_body_size,
        connect_timeout = ?config.connect_timeout,
        request_timeout = ?config.request_timeout,
        max_concurrent_requests = config.max_concurrent_requests,
        "configuration loaded"
    );

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
    let concurrency_limit = config.max_concurrent_requests;

    let config = Arc::new(config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .pool_idle_timeout(config.pool_idle_timeout)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .build_http();

    let make_service = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let client = client.clone();
        let config = Arc::clone(&config);
        let semaphore = Arc::clone(&semaphore);
        let client_addr = conn.remote_addr();
        async move {
            Ok::<_, std::convert::Infallible>(service_fn(move |req| {
                let client = client.clone();
                let config = Arc::clone(&config);
                let semaphore = Arc::clone(&semaphore);
                async move {
                    let _permit = match semaphore.try_acquire() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                limit = concurrency_limit,
                                "concurrency limit reached, rejecting request"
                            );
                            let err = ProxyError::ServiceUnavailable {
                                limit: concurrency_limit,
                            };
                            return Ok::<Response<Body>, std::convert::Infallible>(
                                err.into_response(),
                            );
                        }
                    };

                    let resp = handle_request(req, client, config, client_addr)
                        .await
                        .unwrap_or_else(|e| e.into_response());
                    Ok::<Response<Body>, std::convert::Infallible>(resp)
                }
            }))
        }
    });

    let server = Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    info!(%addr, "listening");

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    if let Err(e) = graceful.await {
        error!(%e, "server terminated with error");
    }

    info!("shutdown complete");
}

/// Awaits a shutdown signal (SIGINT or SIGTERM on Unix, Ctrl+C on all
/// platforms). Once received, the server stops accepting new connections
/// and drains in-flight requests before exiting.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => info!("received SIGINT, initiating graceful shutdown"),
            _ = sigterm.recv() => info!("received SIGTERM, initiating graceful shutdown"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        info!("received Ctrl+C, initiating graceful shutdown");
    }
}
