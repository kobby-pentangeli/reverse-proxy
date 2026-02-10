use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::Response;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reverse_proxy::{
    BoxBody, Config, ProxyError, RuntimeConfig, build_client, build_https_client, handle_request,
};
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

    let tls_acceptor = config.tls.as_ref().map(|tls_cfg| {
        reverse_proxy::tls::build_tls_acceptor(tls_cfg).unwrap_or_else(|e| {
            error!(%e, "failed to initialize TLS");
            std::process::exit(1);
        })
    });

    let upstream_is_https = config
        .upstream
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("https"));

    info!(
        upstream = %config.upstream,
        blocked_headers = config.blocked_headers.len(),
        blocked_params = config.blocked_params.len(),
        mask_rules = config.mask_rules.len(),
        max_body_size = config.max_body_size,
        connect_timeout = ?config.connect_timeout,
        request_timeout = ?config.request_timeout,
        max_concurrent_requests = config.max_concurrent_requests,
        tls_termination = tls_acceptor.is_some(),
        tls_origination = upstream_is_https,
        "configuration loaded"
    );

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
    let concurrency_limit = config.max_concurrent_requests;
    let config = Arc::new(config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%e, %addr, "failed to bind");
        std::process::exit(1);
    });

    info!(%addr, "listening");

    if upstream_is_https {
        let client = build_https_client(&config);
        serve(
            listener,
            tls_acceptor,
            client,
            config,
            semaphore,
            concurrency_limit,
        )
        .await;
    } else {
        let client = build_client(&config);
        serve(
            listener,
            tls_acceptor,
            client,
            config,
            semaphore,
            concurrency_limit,
        )
        .await;
    }

    info!("shutdown complete");
}

/// Accepts connections on `listener`, optionally wrapping each in TLS via
/// `tls_acceptor`, and dispatches them through the proxy pipeline using the
/// given `client`. Generic over the client connector type so that both
/// plain-HTTP and HTTPS upstreams use the same accept loop.
async fn serve<C>(
    listener: TcpListener,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    client: hyper_util::client::legacy::Client<C, BoxBody>,
    config: Arc<RuntimeConfig>,
    semaphore: Arc<Semaphore>,
    concurrency_limit: usize,
) where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
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
                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<Incoming>| {
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

                    let builder = http1::Builder::new();

                    let result = match tls_acceptor {
                        Some(acceptor) => {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(%e, "TLS handshake failed");
                                    return;
                                }
                            };
                            builder
                                .serve_connection(TokioIo::new(tls_stream), svc)
                                .await
                        }
                        None => {
                            builder
                                .serve_connection(TokioIo::new(stream), svc)
                                .await
                        }
                    };

                    if let Err(e) = result {
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
