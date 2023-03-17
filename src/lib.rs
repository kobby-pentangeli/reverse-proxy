use hyper::{
    http::header::{HeaderName, HeaderValue},
    Body, Client, Method, Request, Response,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub blocked_headers: Option<Vec<String>>,
    pub blocked_params: Option<Vec<String>>,
    pub additional_headers: Option<Vec<(String, String)>>,
    pub mask_params: Vec<String>,
}

impl ProxyConfig {
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

    pub fn mask_response_body(&self, body: &str) -> String {
        let mut masked_body = body.to_owned();
        for param in &self.mask_params {
            let re = Regex::new(&format!("{}=([^&]+)", param)).unwrap();
            masked_body = re
                .replace_all(&masked_body, &format!("{}=****", param))
                .to_string();
        }
        masked_body
    }
}

pub async fn handle_request(
    req: Request<Body>,
    config: Arc<ProxyConfig>,
) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    let uri = req.uri();

    // Only inspect `GET` requests
    if req.method() != &Method::GET {
        return Ok(Response::builder()
            .status(400)
            .body(Body::from("Only GET requests are supported"))?);
    }

    // Check if any blocked headers are present
    let headers = req.headers().clone();
    if let Some(blocked_headers) = &config.blocked_headers {
        for header in blocked_headers.iter() {
            let header_name = HeaderName::from_bytes(header.as_bytes()).unwrap();
            if headers.contains_key(&header_name) {
                return Ok(Response::builder().status(400).body(Body::from(format!(
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
                return Ok(Response::builder().status(400).body(Body::from(format!(
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
    for (name, value) in headers.iter_mut() {
        // Remove any headers that were blocked
        if let Some(blocked_headers) = &config.blocked_headers {
            if blocked_headers.contains(&name.as_str().to_string()) {
                headers.remove(name).unwrap();
            }
        }
        // Add any additional headers specified in the config
        if let Some(add_headers) = &config.additional_headers {
            for (header_name, header_value) in add_headers.iter() {
                let header_name = HeaderName::from_bytes(header_name.as_bytes()).unwrap();
                let header_value = HeaderValue::from_str(header_value).unwrap();
                headers.insert(header_name, header_value);
            }
        }
    }

    // Send the modified request to the destination server and return the response
    let mut res = client.request(proxy_req).await?;
    let body = std::mem::replace(res.body_mut(), Body::empty());
    Ok(Response::new(body))
}
