//!
//! A simple HTTP server acting as a reverse proxy, to be used with [Hyper].
//!
//! [Hyper]: https://hyper.rs/
//!
//! # Example
//!
//! 1. Define a `Config.yml` file at the root of your project, with content like:
//!
//! ```yml
//! blocked_headers:
//!  - User-Agent
//!  - X-Forwarded-For
//! blocked_params:
//!  - access_token
//!  - secret_key
//! masked_params:
//!  - password
//!  - ssn
//!  - credit_card
//! ```
//!
//! 2. Add these dependencies to your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! reverse-proxy = "0.1.0"
//! hyper = { version = "0.14", features = ["full"] }
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! 3. In `src/main.rs`, create a new HTTP server that uses our proxy as its request handler:
//!
//! ```rust,ignore
//! use hyper::{Body, Request, Server};
//! use std::{convert::Infallible, net::SocketAddr};
//! use std::net::IpAddr;
//! use std::sync::Arc;
//!
//! use reverse_proxy::{Config, handle_request};
//!
//! fn main() {
//!     let config = Arc::new(Config::from_file("./Config.yml"));
//!     let addr: SocketAddr = ([127, 0, 0, 1], 8080).into();
//!
//!     let server = Server::bind(&addr).serve(move || {
//!         let config = config.clone();
//!
//!         async {
//!             Ok::<_, hyper::Error>(hyper::service::service_fn(move |req: Request<Body>| {
//!                 handle_request(req, config.clone())
//!             }))
//!         }
//!     });
//!
//!     println!("Listening on http://{}", addr);
//!
//!     hyper::rt::run(server);
//! }
//! ```
//!

use hyper::{http::header::HeaderName, Body, Client, Method, Request, Response, StatusCode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents client config information parsed from the provided configuration file.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// A set of headers that we want to remove from incoming requests
    pub blocked_headers: Option<Vec<String>>,
    /// A set of rules for blocking requests based on request headers or body content
    pub blocked_params: Option<Vec<String>>,
    /// Sensitive information we want to mask before forwarding
    pub masked_params: Vec<String>,
}

impl Config {
    /// Load the client configuration from a file.
    pub fn load_from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = match std::fs::File::open(file_path) {
            Ok(file) => file,
            Err(err) => return Err(format!("Failed to open config file: {}", err).into()),
        };
        let yaml_val: serde_yaml::Value = serde_yaml::from_reader(file)?;

        match serde_yaml::from_value(yaml_val) {
            Ok(config) => Ok(config),
            Err(err) => Err(format!("Failed to deserialize config file: {}", err).into()),
        }
    }

    /// Inspect the response body for any sensitive data and mask it.
    pub fn mask_sensitive_data(&self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut masked_data = data.to_owned();
        for param in &self.masked_params {
            let re = Regex::new(&format!("{}=([^&]+)", param))?;
            masked_data = re
                .replace_all(&masked_data, &format!("{}=****", param))
                .to_string();
        }
        Ok(masked_data)
    }
}

/// Handle an incoming request.
pub async fn handle_request(
    req: Request<Body>,
    config: Arc<Config>,
) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    log::info!("Incoming request:\n{:#?}", &req);
    let uri = req.uri();

    // Only inspect `GET` requests
    if req.method() != Method::GET {
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Only GET requests are inspected"))?);
    }

    // Check if any blocked headers are present
    let headers = req.headers().clone();
    if let Some(blocked_headers) = &config.blocked_headers {
        for header in blocked_headers.iter() {
            let header_name = HeaderName::from_bytes(header.as_bytes())?;
            if headers.contains_key(&header_name) {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!(
                        "Blocked request because it contains the blocked header: {}",
                        header
                    )))?);
            }
        }
    }

    // Check if any blocked parameters are present
    let params = uri.query().map_or(String::new(), |s| s.to_string());
    if let Some(blocked_params) = &config.blocked_params {
        for param in blocked_params.iter() {
            let blocked_param = format!("{}=", param);
            if params.contains(&blocked_param) {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!(
                        "Blocked request because it contains the blocked parameter: {}",
                        param
                    )))?);
            }
        }
    }

    // Process the request
    let client = Client::new();
    let mut proxy_req = Request::new(Body::empty());
    *proxy_req.method_mut() = req.method().clone();
    *proxy_req.uri_mut() = req.uri().clone();

    let headers = proxy_req.headers_mut();
    for (name, _value) in headers.clone().iter() {
        // Remove any headers that were blocked
        if let Some(blocked_headers) = &config.blocked_headers {
            if blocked_headers.contains(&name.as_str().to_string()) {
                headers.remove(name);
            }
        }
    }

    // Send the modified request to the destination server and return the response
    log::info!("Outgoing request:\n{:#?}", &proxy_req);
    let res = client.request(proxy_req).await?;
    // Inspect the response body for any sensitive data and mask it before forwarding
    let masked_body = config.mask_sensitive_data(&format!("{:?}", &res.into_body()))?;
    let response = Response::new(Body::from(masked_body));
    log::info!("Response:\n{:#?}", &response);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_load_from_file() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::load_from_file("./Config.yml")?;
        assert_eq!(
            config.blocked_headers,
            Some(vec![
                "User-Agent".to_string(),
                "X-Forwarded-For".to_string()
            ])
        );
        assert_eq!(
            config.blocked_params,
            Some(vec!["access_token".to_string(), "secret_key".to_string()])
        );
        assert_eq!(
            config.masked_params,
            vec![
                "password".to_string(),
                "ssn".to_string(),
                "credit_card".to_string()
            ]
        );
        Ok(())
    }

    #[test]
    fn test_config_mask_sensitive_data() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config {
            masked_params: vec!["password".to_string(), "token".to_string()],
            ..Default::default()
        };
        let data = "username=john&password=secret&token=1234567890";
        let masked_data = config.mask_sensitive_data(data)?;
        assert_eq!(masked_data, "username=john&password=****&token=****");
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_request_blocked_headers() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config {
            blocked_headers: Some(vec!["X-Forwarded-For".to_string()]),
            ..Default::default()
        };
        let req = Request::builder()
            .uri("http://www.rust-lang.org/")
            .body(Body::empty())?;

        let res = handle_request(req, Arc::new(config)).await?;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_request_blocked_params() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config {
            blocked_params: Some(vec!["password".to_string()]),
            ..Default::default()
        };
        let req = Request::builder()
            .uri("http://www.rust-lang.org/login?username=john&password=secret")
            .body(Body::empty())?;
        let res = handle_request(req, Arc::new(config)).await?;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_request_no_blocked_headers_or_params(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::default();
        let req = Request::builder()
            .uri("http://www.rust-lang.org/")
            .body(Body::empty())?;
        let res = handle_request(req, Arc::new(config)).await?;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }
}
