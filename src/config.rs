//! Configuration loading, validation, and pre-compiled runtime state.
//!
//! The proxy reads its YAML configuration exactly once at startup.
//! All regex patterns for sensitive data masking are compiled at load time
//! and stored alongside the raw config for zero-allocation lookups at
//! request time.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{ProxyError, Result};

/// Default maximum request body size: 10 MiB.
pub const DEFAULT_MAX_BODY_SIZE: u64 = 10 * 1024 * 1024;

/// Default connect timeout for establishing upstream TCP connections.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default total request timeout covering the entire upstream round-trip.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default idle timeout for pooled connections before they are closed.
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum number of idle connections kept per upstream host.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 32;

/// Default maximum number of concurrent in-flight requests the proxy
/// will handle before returning 503 Service Unavailable.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1000;

/// Default weight assigned to upstream backends when none is specified.
pub const DEFAULT_UPSTREAM_WEIGHT: u32 = 1;

/// Default socket address the proxy binds to.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8100";

/// Default number of consecutive failures before marking a backend unhealthy.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// Default cooldown period before re-checking an unhealthy backend.
pub const DEFAULT_HEALTH_CHECK_COOLDOWN: Duration = Duration::from_secs(30);

/// Default interval between active health check probes.
pub const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Default path for active health check probes.
pub const DEFAULT_HEALTH_CHECK_PATH: &str = "/health";

/// Default per-IP rate limit in requests per second.
pub const DEFAULT_RATE_LIMIT_RPS: u32 = 100;

/// Default burst size for per-IP rate limiting.
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 50;

/// Raw configuration as deserialized from the YAML file.
///
/// This struct maps directly to the on-disk schema. After loading, it is
/// transformed into a [`RuntimeConfig`] that holds pre-compiled regex
/// patterns and validated upstream URIs.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Socket address the proxy listens on (default `"127.0.0.1:8100"`).
    #[serde(default)]
    pub listen: Option<String>,
    /// Upstream backends with optional weights and health check config.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    /// Header names whose presence causes the request to be rejected.
    #[serde(default)]
    pub blocked_headers: Vec<String>,
    /// Query parameter names whose presence causes the request to be rejected.
    #[serde(default)]
    pub blocked_params: Vec<String>,
    /// Parameter names whose values are masked in response bodies.
    #[serde(default)]
    pub masked_params: Vec<String>,
    /// Maximum allowed request body size in bytes (default: 10 MiB).
    /// Requests with a `Content-Length` exceeding this limit receive 413.
    #[serde(default)]
    pub max_body_size: Option<u64>,
    /// Response header names to strip before returning to the client.
    /// Typically `["server", "x-powered-by"]` to hide backend details.
    #[serde(default)]
    pub strip_response_headers: Vec<String>,
    /// Connect timeout in milliseconds for establishing upstream TCP connections
    /// (default: 5000).
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    /// Total request timeout in milliseconds covering the entire upstream
    /// round-trip (default: 30000). Requests exceeding this receive 504.
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
    /// Idle timeout in milliseconds for pooled connections (default: 60000).
    #[serde(default)]
    pub pool_idle_timeout_ms: Option<u64>,
    /// Maximum idle connections kept per upstream host (default: 32).
    #[serde(default)]
    pub pool_max_idle_per_host: Option<usize>,
    /// Maximum concurrent in-flight requests before returning 503
    /// Service Unavailable (default: 1000).
    #[serde(default)]
    pub max_concurrent_requests: Option<usize>,
    /// TLS termination configuration for accepting HTTPS connections from
    /// clients. When absent, the proxy listens on plain HTTP.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Health check configuration for upstream backends.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Per-IP rate limiting configuration. When absent, rate limiting is
    /// disabled.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Configuration for a single upstream backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamConfig {
    /// The backend address (e.g. `"http://backend1:3000"`).
    pub address: String,
    /// Relative weight for load balancing. Higher values receive
    /// proportionally more traffic. Defaults to 1.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    DEFAULT_UPSTREAM_WEIGHT
}

/// Active health check configuration.
///
/// When present, the proxy spawns a background task that periodically
/// probes each upstream at the configured path, marking backends as
/// healthy or unhealthy based on response status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthCheckConfig {
    /// HTTP path to probe (default: `/health`).
    #[serde(default = "default_health_path")]
    pub path: String,
    /// Interval between health check probes in milliseconds (default: 10000).
    #[serde(default = "default_health_interval_ms")]
    pub interval_ms: u64,
    /// Number of consecutive failures before marking a backend unhealthy
    /// (default: 3).
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Cooldown period in milliseconds before re-checking an unhealthy
    /// backend (default: 30000).
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
}

fn default_health_path() -> String {
    DEFAULT_HEALTH_CHECK_PATH.into()
}

fn default_health_interval_ms() -> u64 {
    DEFAULT_HEALTH_CHECK_INTERVAL.as_millis() as u64
}

fn default_failure_threshold() -> u32 {
    DEFAULT_FAILURE_THRESHOLD
}

fn default_cooldown_ms() -> u64 {
    DEFAULT_HEALTH_CHECK_COOLDOWN.as_millis() as u64
}

/// Per-IP rate limiting configuration.
///
/// When present, the proxy applies a token-bucket rate limiter keyed by
/// client IP address. Requests exceeding the limit receive a 429
/// Too Many Requests response with a `Retry-After` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second per client IP (default: 100).
    #[serde(default = "default_rate_limit_rps")]
    pub requests_per_second: u32,
    /// Maximum burst size above the sustained rate (default: 50).
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
}

fn default_rate_limit_rps() -> u32 {
    DEFAULT_RATE_LIMIT_RPS
}

fn default_rate_limit_burst() -> u32 {
    DEFAULT_RATE_LIMIT_BURST
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_rate_limit_rps(),
            burst: default_rate_limit_burst(),
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: default_health_path(),
            interval_ms: default_health_interval_ms(),
            failure_threshold: default_failure_threshold(),
            cooldown_ms: default_cooldown_ms(),
        }
    }
}

/// TLS termination configuration.
///
/// When present in the config file, the proxy accepts HTTPS connections
/// using the certificate chain and private key at the specified paths.
/// Both files must be PEM-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain file.
    pub cert_path: String,
    /// Path to the PEM-encoded private key file.
    pub key_path: String,
}

/// Validated upstream backend descriptor produced from [`UpstreamConfig`].
#[derive(Debug, Clone)]
pub struct ValidatedUpstream {
    /// The parsed and validated upstream URI.
    pub uri: hyper::Uri,
    /// Relative weight for load balancing.
    pub weight: u32,
}

/// Fully validated, ready-to-use configuration with pre-compiled patterns.
///
/// Created once at startup and shared across all request handlers via `Arc`.
/// Contains every value the proxy needs at runtime without touching the
/// filesystem or compiling regexes on the hot path.
#[derive(Debug)]
pub struct RuntimeConfig {
    /// Socket address the proxy binds to.
    pub listen: SocketAddr,
    /// Validated upstream backends with their load-balancing weights.
    pub upstreams: Vec<ValidatedUpstream>,
    /// Lowercased header names whose presence triggers a 403 on GET requests.
    pub blocked_headers: Vec<String>,
    /// Query parameter names whose presence triggers a 403 on GET requests.
    pub blocked_params: Vec<String>,
    /// Pre-compiled masking rules for response body inspection.
    pub mask_rules: Vec<MaskRule>,
    /// Maximum request body size in bytes. Requests whose `Content-Length`
    /// exceeds this threshold are rejected with 413 Payload Too Large.
    pub max_body_size: u64,
    /// Lowercased response header names to strip before returning to the
    /// client (e.g. `"server"`, `"x-powered-by"`).
    pub strip_response_headers: Vec<String>,
    /// Connect timeout for upstream TCP connections.
    pub connect_timeout: Duration,
    /// Total request timeout for the upstream round-trip. Expiry yields 504.
    pub request_timeout: Duration,
    /// Idle timeout for pooled upstream connections.
    pub pool_idle_timeout: Duration,
    /// Maximum idle connections per upstream host.
    pub pool_max_idle_per_host: usize,
    /// Maximum concurrent in-flight requests. Overflow yields 503.
    pub max_concurrent_requests: usize,
    /// TLS termination configuration. `None` means plain HTTP.
    pub tls: Option<TlsConfig>,
    /// Active health check configuration. `None` disables active probing.
    pub health_check: Option<HealthCheckConfig>,
    /// Number of consecutive failures before marking a backend unhealthy.
    pub failure_threshold: u32,
    /// Cooldown period before re-checking an unhealthy backend.
    pub health_check_cooldown: Duration,
    /// Per-IP rate limiting configuration. `None` disables rate limiting.
    pub rate_limit: Option<RateLimitConfig>,
}

/// A single pre-compiled masking rule binding a parameter name to its regex.
#[derive(Debug, Clone)]
pub struct MaskRule {
    /// The original parameter name this rule applies to.
    pub param: String,
    /// Compiled regex matching `{param}={value}` in query-string-style text.
    pub pattern: Regex,
}

/// Validates a single upstream address string, returning a [`ValidatedUpstream`].
fn validate_upstream(address: &str, weight: u32) -> Result<ValidatedUpstream> {
    if address.is_empty() {
        return Err(ProxyError::InvalidUpstream(
            "upstream address must not be empty".into(),
        ));
    }

    let uri = address
        .parse::<hyper::Uri>()
        .map_err(|e| ProxyError::InvalidUpstream(format!("{e}")))?;

    uri.authority().ok_or_else(|| {
        ProxyError::InvalidUpstream(format!("upstream URI has no authority: {address}"))
    })?;

    if weight == 0 {
        return Err(ProxyError::Config(format!(
            "upstream weight must be positive: {address}"
        )));
    }

    Ok(ValidatedUpstream { uri, weight })
}

impl Config {
    /// Loads configuration from a YAML file at the given path.
    ///
    /// Returns a [`ProxyError::Config`] if the file cannot be opened or
    /// its contents fail YAML deserialization.
    pub fn load_from_file(file_path: &(impl AsRef<Path> + ?Sized)) -> Result<Self> {
        let file = std::fs::File::open(file_path).map_err(|e| {
            ProxyError::Config(format!(
                "failed to open {}: {e}",
                file_path.as_ref().display()
            ))
        })?;

        serde_yaml::from_reader(file)
            .map_err(|e| ProxyError::Config(format!("failed to parse config: {e}")))
    }

    /// Validates all fields and compiles regex patterns, producing a
    /// [`RuntimeConfig`] suitable for the proxy hot path.
    ///
    /// At least one upstream must be configured.
    pub fn into_runtime(self) -> Result<RuntimeConfig> {
        if self.upstreams.is_empty() {
            return Err(ProxyError::Config(
                "at least one upstream must be configured".into(),
            ));
        }

        let listen_str = self.listen.as_deref().unwrap_or(DEFAULT_LISTEN_ADDR);
        let listen = listen_str.parse::<SocketAddr>().map_err(|e| {
            ProxyError::Config(format!("invalid listen address \"{listen_str}\": {e}"))
        })?;

        let upstreams = self
            .upstreams
            .iter()
            .map(|u| validate_upstream(&u.address, u.weight))
            .collect::<Result<Vec<_>>>()?;

        let blocked_headers = self
            .blocked_headers
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();

        let mask_rules = self
            .masked_params
            .iter()
            .map(|param| {
                let escaped = regex::escape(param);
                Regex::new(&format!("{escaped}=([^&]+)"))
                    .map(|pattern| MaskRule {
                        param: param.clone(),
                        pattern,
                    })
                    .map_err(|e| {
                        ProxyError::Config(format!("invalid mask pattern for {param}: {e}"))
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        let max_body_size = self.max_body_size.unwrap_or(DEFAULT_MAX_BODY_SIZE);

        let strip_response_headers = self
            .strip_response_headers
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();

        let connect_timeout = self
            .connect_timeout_ms
            .map_or(DEFAULT_CONNECT_TIMEOUT, Duration::from_millis);

        let request_timeout = self
            .request_timeout_ms
            .map_or(DEFAULT_REQUEST_TIMEOUT, Duration::from_millis);

        let pool_idle_timeout = self
            .pool_idle_timeout_ms
            .map_or(DEFAULT_POOL_IDLE_TIMEOUT, Duration::from_millis);

        let pool_max_idle_per_host = self
            .pool_max_idle_per_host
            .unwrap_or(DEFAULT_POOL_MAX_IDLE_PER_HOST);

        let max_concurrent_requests = self
            .max_concurrent_requests
            .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS);

        let failure_threshold = self
            .health_check
            .as_ref()
            .map_or(DEFAULT_FAILURE_THRESHOLD, |hc| hc.failure_threshold);

        let health_check_cooldown = self
            .health_check
            .as_ref()
            .map_or(DEFAULT_HEALTH_CHECK_COOLDOWN, |hc| {
                Duration::from_millis(hc.cooldown_ms)
            });

        Ok(RuntimeConfig {
            listen,
            upstreams,
            blocked_headers,
            blocked_params: self.blocked_params,
            mask_rules,
            max_body_size,
            strip_response_headers,
            connect_timeout,
            request_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            max_concurrent_requests,
            tls: self.tls,
            health_check: self.health_check,
            failure_threshold,
            health_check_cooldown,
            rate_limit: self.rate_limit,
        })
    }
}

impl RuntimeConfig {
    /// Returns `true` if any configured upstream uses the HTTPS scheme.
    pub fn has_https_upstream(&self) -> bool {
        self.upstreams.iter().any(|u| {
            u.uri
                .scheme_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("https"))
        })
    }

    /// Applies all configured masking rules to the given text, replacing
    /// matched parameter values with `****`.
    ///
    /// Returns the masked string, which may be identical to the input if
    /// no rules match.
    pub fn mask_sensitive_data(&self, data: &str) -> String {
        self.mask_rules.iter().fold(data.to_owned(), |acc, rule| {
            rule.pattern
                .replace_all(&acc, format!("{}=****", rule.param))
                .into_owned()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_upstream(addr: &str) -> Vec<UpstreamConfig> {
        vec![UpstreamConfig {
            address: addr.into(),
            weight: 1,
        }]
    }

    #[test]
    fn loads_config_from_file() {
        let config = Config::load_from_file("./Config.yml").expect("Config.yml should be loadable");

        assert_eq!(config.listen, Some("127.0.0.1:8100".into()));
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].address, "http://localhost:3000");
        assert_eq!(
            config.blocked_headers,
            vec!["User-Agent", "X-Forwarded-For"]
        );
        assert_eq!(config.blocked_params, vec!["access_token", "secret_key"]);
        assert_eq!(config.masked_params, vec!["password", "ssn", "credit_card"]);
        assert_eq!(config.connect_timeout_ms, Some(5000));
        assert_eq!(config.request_timeout_ms, Some(30000));
        assert_eq!(config.pool_idle_timeout_ms, Some(60000));
        assert_eq!(config.pool_max_idle_per_host, Some(32));
        assert_eq!(config.max_concurrent_requests, Some(1000));
        assert_eq!(
            config.rate_limit,
            Some(RateLimitConfig {
                requests_per_second: 100,
                burst: 50,
            })
        );
    }

    #[test]
    fn into_runtime_rejects_empty_upstreams() {
        let config = Config::default();
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_malformed_upstream() {
        let config = Config {
            upstreams: vec![UpstreamConfig {
                address: "not a valid uri %%".into(),
                weight: 1,
            }],
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_lowercases_blocked_headers() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_headers: vec!["X-Custom-Header".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(rt.blocked_headers, vec!["x-custom-header"]);
    }

    #[test]
    fn into_runtime_validates_upstreams() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(rt.upstreams.len(), 1);
        assert_eq!(
            rt.upstreams[0].uri,
            "http://localhost:3000".parse::<hyper::Uri>().unwrap()
        );
        assert_eq!(rt.upstreams[0].weight, 1);
    }

    #[test]
    fn into_runtime_handles_multiple_upstreams() {
        let config = Config {
            upstreams: vec![
                UpstreamConfig {
                    address: "http://backend1:3000".into(),
                    weight: 3,
                },
                UpstreamConfig {
                    address: "http://backend2:3000".into(),
                    weight: 1,
                },
            ],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(rt.upstreams.len(), 2);
        assert_eq!(
            rt.upstreams[0].uri,
            "http://backend1:3000".parse::<hyper::Uri>().unwrap()
        );
        assert_eq!(rt.upstreams[0].weight, 3);
        assert_eq!(rt.upstreams[1].weight, 1);
    }

    #[test]
    fn into_runtime_rejects_zero_weight() {
        let config = Config {
            upstreams: vec![UpstreamConfig {
                address: "http://localhost:3000".into(),
                weight: 0,
            }],
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn has_https_upstream_detects_scheme() {
        let config = Config {
            upstreams: vec![
                UpstreamConfig {
                    address: "http://backend1:3000".into(),
                    weight: 1,
                },
                UpstreamConfig {
                    address: "https://backend2:3000".into(),
                    weight: 1,
                },
            ],
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert!(rt.has_https_upstream());
    }

    #[test]
    fn mask_sensitive_data_replaces_values() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            masked_params: vec!["password".into(), "token".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");

        let input = "username=john&password=secret&token=1234567890";
        let masked = rt.mask_sensitive_data(input);
        assert_eq!(masked, "username=john&password=****&token=****");
    }

    #[test]
    fn mask_sensitive_data_leaves_unmatched_text_intact() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            masked_params: vec!["password".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");

        let input = "username=john&role=admin";
        assert_eq!(rt.mask_sensitive_data(input), input);
    }

    #[test]
    fn mask_handles_regex_special_characters_in_param_name() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            masked_params: vec!["user.password".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");

        let input = "user.password=secret123&other=value";
        assert_eq!(
            rt.mask_sensitive_data(input),
            "user.password=****&other=value"
        );
    }

    #[test]
    fn into_runtime_defaults_listen_address() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(
            rt.listen,
            DEFAULT_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn into_runtime_parses_custom_listen_address() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            listen: Some("0.0.0.0:9090".into()),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.listen, "0.0.0.0:9090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn into_runtime_rejects_invalid_listen_address() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            listen: Some("not-an-address".into()),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn health_check_config_uses_defaults() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            health_check: Some(HealthCheckConfig::default()),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
        assert_eq!(rt.health_check_cooldown, DEFAULT_HEALTH_CHECK_COOLDOWN);
        assert!(rt.health_check.is_some());
    }
}
