use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Response, Server};
use reverse_proxy::{Config, handle_request};

const CONFIG_FILE_PATH: &str = "./Config.yml";

#[tokio::main]
async fn main() {
    let config = Config::load_from_file(CONFIG_FILE_PATH)
        .and_then(|c| c.into_runtime())
        .unwrap_or_else(|e| {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        });

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

    println!("listening on http://{addr}");

    if let Err(e) = server.await {
        eprintln!("server error: {e}");
    }
}
