use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reverse_proxy::server::{
    ServerState, serve, shutdown_signal, spawn_health_checker, spawn_rate_limit_cleanup,
};
use reverse_proxy::{
    Config, IpRateLimiter, LoadBalancer, UpstreamPool, build_client, build_https_client,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
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

    let tls_acceptor = config.tls.as_ref().map(|tls_cfg| {
        reverse_proxy::tls::build_tls_acceptor(tls_cfg).unwrap_or_else(|e| {
            error!(%e, "failed to initialize TLS");
            std::process::exit(1);
        })
    });

    let upstream_is_https = config.has_https_upstream();
    let pool = UpstreamPool::from_validated(&config.upstreams);
    let balancer = LoadBalancer::new(pool);

    let rate_limiter = config.rate_limit.as_ref().map(|rl_cfg| {
        info!(
            requests_per_second = rl_cfg.requests_per_second,
            burst = rl_cfg.burst,
            "per-IP rate limiting enabled"
        );
        IpRateLimiter::from_config(rl_cfg).expect("rate limiter from config should not fail here")
    });

    info!(
        upstreams = config.upstreams.len(),
        blocked_headers = config.blocked_headers.len(),
        blocked_params = config.blocked_params.len(),
        mask_rules = config.mask_rules.len(),
        max_body_size = config.max_body_size,
        connect_timeout = ?config.connect_timeout,
        request_timeout = ?config.request_timeout,
        max_concurrent_requests = config.max_concurrent_requests,
        tls_termination = tls_acceptor.is_some(),
        tls_origination = upstream_is_https,
        active_health_checks = config.health_check.is_some(),
        rate_limiting = rate_limiter.is_some(),
        "configuration loaded"
    );

    for (i, u) in config.upstreams.iter().enumerate() {
        info!(
            index = i,
            upstream = %u.uri,
            weight = u.weight,
            "registered upstream backend"
        );
    }

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
    let concurrency_limit = config.max_concurrent_requests;
    let config = Arc::new(config);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%e, %addr, "failed to bind");
        std::process::exit(1);
    });

    info!(%addr, "listening");

    let health_check_handle = config.health_check.as_ref().map(|hc| {
        spawn_health_checker(
            balancer.clone(),
            Duration::from_millis(hc.interval_ms),
            &hc.path,
            config.failure_threshold,
        )
    });

    let cleanup_handle = rate_limiter
        .as_ref()
        .map(|rl| spawn_rate_limit_cleanup(rl.clone()));

    let state = ServerState {
        config: Arc::clone(&config),
        balancer,
        semaphore,
        concurrency_limit,
        rate_limiter,
        tls_acceptor,
    };

    if upstream_is_https {
        let client = build_https_client(&config);
        serve(listener, client, state, shutdown_signal()).await;
    } else {
        let client = build_client(&config);
        serve(listener, client, state, shutdown_signal()).await;
    }

    if let Some(handle) = health_check_handle {
        handle.abort();
    }

    if let Some(handle) = cleanup_handle {
        handle.abort();
    }

    info!("shutdown complete");
}
