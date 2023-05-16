//!
//! A simple HTTP server acting as a reverse proxy, to be used with [Hyper].
//!
//! [Hyper]: https://hyper.rs/

use hyper::{http::header::HeaderName, Body, Client, Method, Request, Response, StatusCode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

type HttpClient = Client<hyper::client::HttpConnector>;
type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

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
    pub fn load_from_file(file_path: &str) -> Result<Self, Error> {
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
    pub fn mask_sensitive_data(&self, data: &str) -> Result<String, Error> {
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
    client: HttpClient,
) -> Result<Response<Body>, Error> {
    log::info!("Incoming request:\n{:#?}", &req);
    let uri = req.uri();
    let config = Arc::new(Config::load_from_file("./Config.yml")?);

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
    fn test_config_load_from_file() -> Result<(), Error> {
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
    fn test_config_mask_sensitive_data() -> Result<(), Error> {
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
    async fn test_handle_request_blocked_headers() -> Result<(), Error> {
        let client = HttpClient::new();
        let req = Request::builder()
            .uri("http://www.rust-lang.org/")
            .body(Body::empty())?;

        let res = handle_request(req, client).await?;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_request_blocked_params() -> Result<(), Error> {
        let client = HttpClient::new();
        let req = Request::builder()
            .uri("http://www.rust-lang.org/login?username=john&password=secret")
            .body(Body::empty())?;
        let res = handle_request(req, client).await?;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_request_no_blocked_headers_or_params() -> Result<(), Error> {
        let client = HttpClient::new();
        let req = Request::builder()
            .uri("http://www.rust-lang.org/")
            .body(Body::empty())?;
        let res = handle_request(req, client).await?;
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }
}
