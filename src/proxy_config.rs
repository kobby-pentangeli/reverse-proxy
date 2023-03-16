use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Read;

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
