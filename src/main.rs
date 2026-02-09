use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Response, Server};
use reverse_proxy::{Config, handle_request};
use tracing::{error, info};
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
        "configuration loaded"
    );

    let config = Arc::new(config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();

    let make_service = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let client = client.clone();
        let config = Arc::clone(&config);
        let client_addr = conn.remote_addr();
        async move {
            Ok::<_, std::convert::Infallible>(service_fn(move |req| {
                let client = client.clone();
                let config = Arc::clone(&config);
                async move {
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

    if let Err(e) = server.await {
        error!(%e, "server terminated with error");
    }
}
