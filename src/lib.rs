use hyper::{http::header::HeaderName, Body, Client, Method, Request, Response, StatusCode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::sync::Arc;

/// Representation of client config information,
/// parsed from the provided configuration file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// A set of headers that we want to remove from incoming requests
    pub blocked_headers: Option<Vec<String>>,
    /// A set of rules for blocking requests based on request headers or body content
    pub blocked_params: Option<Vec<String>>,
    /// Sensitive information we want to mask before forwarding
    pub masked_params: Vec<String>,
}

impl Config {
    pub fn load_from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = match std::fs::File::open(file_path) {
            Ok(file) => file,
            Err(err) => return Err(format!("Failed to open config file: {}", err).into()),
        };

        let mut buf = String::new();
        if let Err(err) = file.read_to_string(&mut buf) {
            return Err(format!("Failed to read config file: {}", err).into());
        }

        match serde_json::from_str(&buf) {
            Ok(config) => Ok(config),
            Err(err) => Err(format!("Failed to deserialize config file: {}", err).into()),
        }
    }

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
    let masked_body = config.mask_sensitive_data(&format!("{:?}", &res.body()))?;
    let response = Response::new(Body::from(masked_body));
    log::info!("Response:\n{:#?}", &response);

    Ok(response)
}
