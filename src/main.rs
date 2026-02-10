use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::Response;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reverse_proxy::{BoxBody, Config, ProxyError, build_client, handle_request};
use tokio::net::TcpListener;
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
    let client = build_client(&config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%e, %addr, "failed to bind");
        std::process::exit(1);
    });

    info!(%addr, "listening");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, client_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(%e, "failed to accept connection");
                        continue;
                    }
                };

                let client = client.clone();
                let config = Arc::clone(&config);
                let semaphore = Arc::clone(&semaphore);

                tokio::spawn(async move {
                    let service = service_fn(move |req: hyper::Request<Incoming>| {
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
                                    return Ok::<Response<BoxBody>, std::convert::Infallible>(
                                        err.into_response().map(|b| {
                                            b.map_err(
                                                |never| -> Box<
                                                    dyn std::error::Error + Send + Sync,
                                                > {
                                                    match never {}
                                                },
                                            )
                                            .boxed()
                                        }),
                                    );
                                }
                            };

                            let resp = handle_request(req, client, config, client_addr)
                                .await
                                .unwrap_or_else(|e| {
                                    e.into_response().map(|b| {
                                        b.map_err(
                                            |never| -> Box<
                                                dyn std::error::Error + Send + Sync,
                                            > {
                                                match never {}
                                            },
                                        )
                                        .boxed()
                                    })
                                });
                            Ok::<Response<BoxBody>, std::convert::Infallible>(resp)
                        }
                    });

                    if let Err(e) = http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        warn!(%e, "connection error");
                    }
                });
            }
            () = &mut shutdown => {
                info!("shutting down, no longer accepting connections");
                break;
            }
        }
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
