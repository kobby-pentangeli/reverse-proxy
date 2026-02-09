//! Configuration loading, validation, and pre-compiled runtime state.
//!
//! The proxy reads its YAML configuration exactly once at startup.
//! All regex patterns for sensitive data masking are compiled at load time
//! and stored alongside the raw config for zero-allocation lookups at
//! request time.

use crate::ProxyError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Raw configuration as deserialized from the YAML file.
///
/// This struct maps directly to the on-disk schema. After loading, it is
/// transformed into a [`RuntimeConfig`] that holds pre-compiled regex
/// patterns and validated upstream URIs.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// The upstream backend to forward requests to (e.g. `"http://localhost:3000"`).
    pub upstream: String,
    /// Header names whose presence causes the request to be rejected.
    #[serde(default)]
    pub blocked_headers: Vec<String>,
    /// Query parameter names whose presence causes the request to be rejected.
    #[serde(default)]
    pub blocked_params: Vec<String>,
    /// Parameter names whose values are masked in response bodies.
    #[serde(default)]
    pub masked_params: Vec<String>,
}

/// A single pre-compiled masking rule binding a parameter name to its regex.
#[derive(Debug, Clone)]
pub struct MaskRule {
    /// The original parameter name this rule applies to.
    pub param: String,
    /// Compiled regex matching `{param}={value}` in query-string-style text.
    pub pattern: Regex,
}

/// Fully validated, ready-to-use configuration with pre-compiled patterns.
///
/// Created once at startup and shared across all request handlers via `Arc`.
/// Contains every value the proxy needs at runtime without touching the
/// filesystem or compiling regexes on the hot path.
#[derive(Debug)]
pub struct RuntimeConfig {
    /// The validated upstream base URI (scheme + authority).
    pub upstream: hyper::Uri,
    /// Lowercased header names whose presence triggers a 403 on GET requests.
    pub blocked_headers: Vec<String>,
    /// Query parameter names whose presence triggers a 403 on GET requests.
    pub blocked_params: Vec<String>,
    /// Pre-compiled masking rules for response body inspection.
    pub mask_rules: Vec<MaskRule>,
}

impl Config {
    /// Loads configuration from a YAML file at the given path.
    ///
    /// Returns a [`ProxyError::Config`] if the file cannot be opened or
    /// its contents fail YAML deserialization.
    pub fn load_from_file(file_path: &(impl AsRef<Path> + ?Sized)) -> Result<Self, ProxyError> {
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
    /// Fails if the upstream URI is empty or malformed, or if any
    /// masked-parameter regex fails to compile.
    pub fn into_runtime(self) -> Result<RuntimeConfig, ProxyError> {
        if self.upstream.is_empty() {
            return Err(ProxyError::InvalidUpstream(
                "upstream must not be empty".into(),
            ));
        }

        let upstream = self
            .upstream
            .parse::<hyper::Uri>()
            .map_err(|e| ProxyError::InvalidUpstream(format!("{e}")))?;
        upstream
            .authority()
            .ok_or_else(|| ProxyError::InvalidUpstream("upstream URI has no authority".into()))?;

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
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RuntimeConfig {
            upstream,
            blocked_headers,
            blocked_params: self.blocked_params,
            mask_rules,
        })
    }
}

impl RuntimeConfig {
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

    #[test]
    fn loads_config_from_file() {
        let config = Config::load_from_file("./Config.yml").expect("Config.yml should be loadable");

        assert_eq!(config.upstream, "http://localhost:3000");
        assert_eq!(
            config.blocked_headers,
            vec!["User-Agent", "X-Forwarded-For"]
        );
        assert_eq!(config.blocked_params, vec!["access_token", "secret_key"]);
        assert_eq!(config.masked_params, vec!["password", "ssn", "credit_card"]);
    }

    #[test]
    fn into_runtime_validates_upstream() {
        let config = Config {
            upstream: String::new(),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_malformed_upstream() {
        let config = Config {
            upstream: "not a valid uri %%".into(),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_lowercases_blocked_headers() {
        let config = Config {
            upstream: "http://localhost:3000".into(),
            blocked_headers: vec!["X-Custom-Header".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(rt.blocked_headers, vec!["x-custom-header"]);
    }

    #[test]
    fn mask_sensitive_data_replaces_values() {
        let config = Config {
            upstream: "http://localhost:3000".into(),
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
            upstream: "http://localhost:3000".into(),
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
            upstream: "http://localhost:3000".into(),
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
}
