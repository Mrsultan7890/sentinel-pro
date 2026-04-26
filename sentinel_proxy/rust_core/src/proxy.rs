use crate::cert_store::CertStore;
use crate::intercept::{InterceptAction, InterceptManager};
use crate::ipc::{send_event, IpcSender};
use crate::match_replace::MatchReplaceEngine;
use crate::tls;
use crate::types::{FlowRequest, FlowResponse, ProxyEvent};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tracing::debug;
use uuid::Uuid;

pub async fn handle_connection(
    stream:    TcpStream,
    _peer:     SocketAddr,
    ipc:       IpcSender,
    certs:     CertStore,
    intercept: Arc<InterceptManager>,
    mr:        Arc<MatchReplaceEngine>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let ipc       = ipc.clone();
                let certs     = certs.clone();
                let intercept = intercept.clone();
                let mr        = mr.clone();
                async move { route(req, ipc, certs, intercept, mr).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| anyhow!(e.to_string()))
}

async fn route(
    req:       Request<Incoming>,
    ipc:       IpcSender,
    certs:     CertStore,
    intercept: Arc<InterceptManager>,
    mr:        Arc<MatchReplaceEngine>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        Ok(do_connect(req, ipc, certs, intercept, mr).await)
    } else {
        Ok(do_http(req, ipc, intercept, mr).await)
    }
}

fn do_connect(
    req:       Request<Incoming>,
    ipc:       IpcSender,
    certs:     CertStore,
    intercept: Arc<InterceptManager>,
    mr:        Arc<MatchReplaceEngine>,
) -> impl std::future::Future<Output = Response<Full<Bytes>>> {
    let host_port = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
    let (host, port) = split_host_port(&host_port, 443);

    tokio::task::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(req).await {
            let acceptor = tls::make_acceptor(&host, &certs);
            if let Ok(client_tls) = acceptor.accept(TokioIo::new(upgraded)).await {
                let is_h2 = client_tls.get_ref().1
                    .alpn_protocol().map(|p| p == b"h2").unwrap_or(false);
                let io = TokioIo::new(client_tls);
                let h  = host.clone();
                let p  = port;
                let tx = ipc.clone();
                let ic = intercept.clone();
                let mr = mr.clone();

                let svc = service_fn(move |mut req: Request<Incoming>| {
                    let uri = format!("https://{}:{}{}", h, p,
                        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/"));
                    *req.uri_mut() = uri.parse().unwrap();
                    let tx = tx.clone(); let ic = ic.clone(); let mr = mr.clone();
                    async move { Ok::<_, hyper::Error>(do_http(req, tx, ic, mr).await) }
                });

                if is_h2 {
                    hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new()
                    ).serve_connection(io, svc).await.ok();
                } else {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc).with_upgrades().await.ok();
                }
            }
        }
    });

    async {
        Response::builder().status(StatusCode::OK)
            .body(Full::new(Bytes::new())).unwrap()
    }
}

async fn do_http(
    req:       Request<Incoming>,
    ipc:       IpcSender,
    intercept: Arc<InterceptManager>,
    mr:        Arc<MatchReplaceEngine>,
) -> Response<Full<Bytes>> {
    // WebSocket upgrade detect karo
    let is_ws_upgrade = req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("websocket"))
        .unwrap_or(false);

    if is_ws_upgrade {
        let host  = req.uri().host().unwrap_or("").to_string();
        let port  = req.uri().port_u16().unwrap_or(443);
        let path  = req.uri().path_and_query()
            .map(|p| p.to_string()).unwrap_or("/".into());
        let ipc_ws = ipc.clone();
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                crate::websocket::handle_websocket_upgrade(
                    upgraded, &host, port, &path, ipc_ws
                ).await;
            }
        });
        return Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    let id        = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();
    let method    = req.method().to_string();
    let uri       = req.uri().clone();
    let url       = uri.to_string();
    let is_https  = url.starts_with("https://");
    let http_ver  = format!("{:?}", req.version());
    let host      = uri.host().unwrap_or("").to_string();
    let port      = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
    let path      = uri.path_and_query().map(|p| p.to_string()).unwrap_or("/".into());

    let req_headers: HashMap<String, String> = req.headers().iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let body_str   = String::from_utf8_lossy(&body_bytes).chars().take(10000).collect::<String>();

    // Send request event to Python
    send_event(&ipc, ProxyEvent::Request(FlowRequest {
        id: id.clone(), timestamp: timestamp.clone(),
        method: method.clone(), url: url.clone(),
        host: host.clone(), port, path: path.clone(),
        headers: req_headers.clone(), body: body_str,
        is_https, http_ver,
    }));

    // ── Match & Replace on request ────────────────────────────────────────────
    let mut final_url     = url.clone();
    let mut final_headers: Vec<(String, String)> = req_headers.iter()
        .map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut final_body    = body_bytes.to_vec();
    mr.apply_to_request(&mut final_url, &mut final_headers, &mut final_body);

    // Rebuild HeaderMap from modified headers
    let mut hmap = parts.headers.clone();
    hmap.clear();
    for (k, v) in &final_headers {
        if let (Ok(name), Ok(val)) = (
            k.parse::<hyper::header::HeaderName>(),
            v.parse::<hyper::header::HeaderValue>(),
        ) { hmap.insert(name, val); }
    }
    let final_body_bytes = Bytes::from(final_body);

    // ── Intercept ─────────────────────────────────────────────────────────────
    let (send_headers, send_body) = if intercept.is_enabled() && intercept.in_scope(&host) {
        send_event(&ipc, ProxyEvent::Intercepted {
            id: id.clone(), method: method.clone(), url: url.clone(),
            host: host.clone(), path: path.clone(),
            headers: req_headers.clone(),
            body: String::from_utf8_lossy(&final_body_bytes).chars().take(10000).collect(),
        });

        match intercept.hold(&id).await {
            InterceptAction::Drop => {
                return Response::builder().status(200)
                    .body(Full::new(Bytes::from("<!-- dropped -->")))
                    .unwrap();
            }
            InterceptAction::ForwardModified { headers, body } => {
                let mut m = hmap.clone();
                m.clear();
                for (k, v) in &headers {
                    if let (Ok(n), Ok(val)) = (
                        k.parse::<hyper::header::HeaderName>(),
                        v.parse::<hyper::header::HeaderValue>(),
                    ) { m.insert(n, val); }
                }
                (m, Bytes::from(body))
            }
            InterceptAction::Forward => (hmap, final_body_bytes),
        }
    } else {
        (hmap, final_body_bytes)
    };

    // ── Forward upstream ──────────────────────────────────────────────────────
    let start = Instant::now();
    match upstream(&method, &final_url, &host, port, is_https, send_headers, send_body).await {
        Ok((status, mut resp_headers, resp_body)) => {
            let elapsed      = start.elapsed().as_secs_f64() * 1000.0;
            let content_type = resp_headers.get("content-type").cloned().unwrap_or_default();
            let mut decoded  = decompress(&resp_headers, resp_body);

            // M&R on response
            let mut resp_hdr_vec: Vec<(String, String)> = resp_headers.iter()
                .map(|(k, v)| (k.clone(), v.clone())).collect();
            mr.apply_to_response(&mut resp_hdr_vec, &mut decoded);
            resp_headers = resp_hdr_vec.into_iter().collect();

            let resp_str = String::from_utf8_lossy(&decoded).chars().take(50000).collect::<String>();
            send_event(&ipc, ProxyEvent::Response(FlowResponse {
                id: Uuid::new_v4().to_string(), request_id: id.clone(),
                timestamp: Utc::now().to_rfc3339(), status_code: status,
                headers: resp_headers.clone(), body: resp_str,
                body_length: decoded.len(), content_type, response_time: elapsed,
            }));

            let mut builder = Response::builder().status(status);
            for (k, v) in &resp_headers {
                let kl = k.to_lowercase();
                if kl == "transfer-encoding" || kl == "content-encoding" || kl == "content-length" {
                    continue;
                }
                builder = builder.header(k, v);
            }
            builder = builder.header("content-length", decoded.len().to_string());
            builder.body(Full::new(Bytes::from(decoded))).unwrap_or_else(|_| {
                Response::builder().status(502).body(Full::new(Bytes::new())).unwrap()
            })
        }
        Err(e) => {
            send_event(&ipc, ProxyEvent::Error { id, message: e.to_string() });
            Response::builder().status(502)
                .body(Full::new(Bytes::from(format!("SentinelProxy: {}", e)))).unwrap()
        }
    }
}

async fn upstream(
    method:   &str,
    url:      &str,
    host:     &str,
    port:     u16,
    is_https: bool,
    headers:  hyper::HeaderMap,
    body:     Bytes,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let tcp = TcpStream::connect(format!("{}:{}", host, port)).await?;
    if is_https {
        let sn  = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let tls = tls::make_connector().connect(sn, tcp).await?;
        // Try HTTP/2 first via ALPN, fallback to HTTP/1.1
        let negotiated_h2 = tls.get_ref().1
            .alpn_protocol().map(|p| p == b"h2").unwrap_or(false);
        if negotiated_h2 {
            let (mut s, c) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(), TokioIo::new(tls)
            ).await?;
            tokio::spawn(c);
            // HTTP/2 uses full URI in request
            let r = s.send_request(build_req_h2(method, url, headers, body)?).await?;
            read_resp(r).await
        } else {
            let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
            tokio::spawn(c);
            let r = s.send_request(build_req(method, url, headers, body)?).await?;
            read_resp(r).await
        }
    } else {
        let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(c);
        let r = s.send_request(build_req(method, url, headers, body)?).await?;
        read_resp(r).await
    }
}

fn build_req(m: &str, url: &str, h: hyper::HeaderMap, b: Bytes) -> Result<Request<Full<Bytes>>> {
    let uri: hyper::Uri = url.parse()?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut req = Request::builder().method(m).uri(path);

    // Ensure Host header is set correctly
    let host_val = if let Some(port) = uri.port_u16() {
        format!("{}:{}", uri.host().unwrap_or(""), port)
    } else {
        uri.host().unwrap_or("").to_string()
    };

    let mut has_host = false;
    for (k, v) in &h {
        let kl = k.as_str().to_lowercase();
        if kl == "proxy-connection" || kl == "proxy-authorization" {
            continue;
        }
        if kl == "host" {
            has_host = true;
            req = req.header(k, v);
        } else {
            req = req.header(k, v);
        }
    }
    if !has_host && !host_val.is_empty() {
        req = req.header("host", &host_val);
    }
    Ok(req.body(Full::new(b))?)
}

/// HTTP/2 request — uses full URI (authority form not needed for h2)
fn build_req_h2(m: &str, url: &str, h: hyper::HeaderMap, b: Bytes) -> Result<Request<Full<Bytes>>> {
    // HTTP/2: use full URL as URI so hyper sets :authority correctly
    let uri: hyper::Uri = url.parse()?;
    let mut req = Request::builder().method(m).uri(uri);
    for (k, v) in &h {
        let kl = k.as_str().to_lowercase();
        // Strip HTTP/1.1-only headers that are forbidden in HTTP/2
        if kl == "proxy-connection" || kl == "proxy-authorization"
            || kl == "connection" || kl == "keep-alive"
            || kl == "upgrade" || kl == "transfer-encoding"
            || kl == "host"  // HTTP/2 uses :authority instead
        {
            continue;
        }
        req = req.header(k, v);
    }
    Ok(req.body(Full::new(b))?)
}

async fn read_resp(r: Response<Incoming>) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let status  = r.status().as_u16();
    let headers = r.headers().iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = r.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, headers, body))
}

fn decompress(headers: &HashMap<String, String>, body: Vec<u8>) -> Vec<u8> {
    let enc = headers.get("content-encoding")
        .or_else(|| headers.get("Content-Encoding"))
        .map(|s| s.to_lowercase()).unwrap_or_default();
    if enc.contains("gzip") {
        use std::io::Read;
        let mut d = flate2::read::GzDecoder::new(body.as_slice());
        let mut out = Vec::new();
        if d.read_to_end(&mut out).is_ok() && !out.is_empty() { return out; }
    } else if enc.contains("deflate") {
        use std::io::Read;
        let mut d = flate2::read::ZlibDecoder::new(body.as_slice());
        let mut out = Vec::new();
        if d.read_to_end(&mut out).is_ok() && !out.is_empty() { return out; }
    } else if enc.contains("br") {
        let mut out = Vec::new();
        if brotli::BrotliDecompress(&mut body.as_slice(), &mut out).is_ok() && !out.is_empty() {
            return out;
        }
    }
    body
}

fn split_host_port(s: &str, default: u16) -> (String, u16) {
    match s.rfind(':') {
        Some(i) => (s[..i].to_string(), s[i+1..].parse().unwrap_or(default)),
        None    => (s.to_string(), default),
    }
}
