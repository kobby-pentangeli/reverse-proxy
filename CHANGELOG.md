# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-12

Initial release.

### Added

- HTTP reverse proxy built on hyper 1.x, tokio, and rustls
- Weighted round-robin load balancing across multiple upstream backends
- Active health checks with configurable interval, timeout, unhealthy/healthy thresholds, and cooldown
- Passive health tracking on upstream request failures and timeouts
- TLS termination for client-facing HTTPS connections (PEM cert + key)
- TLS origination for HTTPS upstream backends via hyper-rustls
- Per-IP rate limiting using the GCRA algorithm (governor) with automatic stale-entry pruning
- Request policy enforcement: header blocking, query parameter blocking, body size limits
- Sensitive data masking in response bodies via pre-compiled regex patterns
- Hop-by-hop header stripping per RFC 2616 and `Connection`-declared headers
- Configurable response header removal (e.g. `Server`, `X-Powered-By`)
- HTTP request smuggling defense (rejects ambiguous `Transfer-Encoding` + `Content-Length`)
- Concurrency limiting with 503 backpressure when the in-flight cap is reached
- Graceful shutdown with configurable drain timeout for in-flight connections
- TCP_NODELAY on accepted connections for reduced latency
- Monotonic `X-Request-Id` header on every response
- Forwarding headers: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`
- Structured logging via tracing with selectable pretty or JSON output
- YAML-based configuration with nested timeout, pool, health check, and rate limit sections
- CLI interface via clap with `--config`, `--log-format`, and `--log-level` options
- Comprehensive test suite: 88 tests (unit + integration) covering all major code paths

[0.1.0]: https://github.com/kobby-pentangeli/reverse-proxy/releases/tag/v0.1.0
