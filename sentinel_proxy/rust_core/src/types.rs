use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRequest {
    pub id:        String,
    pub timestamp: String,
    pub method:    String,
    pub url:       String,
    pub host:      String,
    pub port:      u16,
    pub path:      String,
    pub headers:   HashMap<String, String>,
    pub body:      String,
    pub is_https:  bool,
    pub http_ver:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowResponse {
    pub id:            String,
    pub request_id:    String,
    pub timestamp:     String,
    pub status_code:   u16,
    pub headers:       HashMap<String, String>,
    pub body:          String,
    pub body_length:   usize,
    pub content_type:  String,
    pub response_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum ProxyEvent {
    #[serde(rename = "request")]
    Request(FlowRequest),
    #[serde(rename = "response")]
    Response(FlowResponse),
    #[serde(rename = "intercepted")]
    Intercepted {
        id:      String,
        method:  String,
        url:     String,
        host:    String,
        path:    String,
        headers: HashMap<String, String>,
        body:    String,
    },
    #[serde(rename = "websocket")]
    WebSocket {
        id:        String,
        host:      String,
        direction: String,
        content:   String,
        is_binary: bool,
        timestamp: String,
    },
    #[serde(rename = "error")]
    Error {
        id:      String,
        message: String,
    },
}
