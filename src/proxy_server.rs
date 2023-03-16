use crate::proxy_config::ProxyConfig;
use hyper::{
    http::header::{HeaderName, HeaderValue},
    Method,
};
use hyper::{Body, Client, Request, Response};
use std::sync::Arc;

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
