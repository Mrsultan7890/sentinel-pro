/// WebSocket handler — intercepts WS messages between browser and server
///
/// Flow:
///   Browser → CONNECT host:443 → TLS → WS Upgrade
///   We intercept each message, send to Python, then forward

use crate::ipc::{send_event, IpcSender};
use crate::types::ProxyEvent;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio_tungstenite::{
    accept_async_with_config, connect_async_with_config,
    tungstenite::Message,
};
use tracing::debug;
use uuid::Uuid;

pub async fn handle_websocket_upgrade(
    upgraded: Upgraded,
    host:     &str,
    port:     u16,
    path:     &str,
    ipc:      IpcSender,
) {
    let url = format!("wss://{}:{}{}", host, port, path);
    debug!("[WS] Upgrading to WebSocket: {}", url);

    let io = TokioIo::new(upgraded);

    // Accept WS from browser
    let browser_ws = match accept_async_with_config(io, None).await {
        Ok(ws) => ws,
        Err(e) => { debug!("[WS] accept error: {}", e); return; }
    };

    // Connect to real server
    let server_ws = match connect_async_with_config(&url, None, false).await {
        Ok((ws, _)) => ws,
        Err(e) => { debug!("[WS] connect error: {}", e); return; }
    };

    let (mut browser_tx, mut browser_rx) = browser_ws.split();
    let (mut server_tx,  mut server_rx)  = server_ws.split();

    let host_str = host.to_string();
    let url_str  = url.clone();
    let ipc1     = ipc.clone();
    let ipc2     = ipc.clone();
    let h1       = host_str.clone();

    // Browser → Server
    let b2s = tokio::spawn(async move {
        while let Some(Ok(msg)) = browser_rx.next().await {
            let content = msg_to_string(&msg);
            send_event(&ipc1, ProxyEvent::WebSocket {
                id:        Uuid::new_v4().to_string(),
                host:      h1.clone(),
                direction: "client→server".to_string(),
                content:   content.clone(),
                is_binary: msg.is_binary(),
                timestamp: Utc::now().to_rfc3339(),
            });
            if server_tx.send(msg).await.is_err() { break; }
        }
    });

    // Server → Browser
    let s2b = tokio::spawn(async move {
        while let Some(Ok(msg)) = server_rx.next().await {
            let content = msg_to_string(&msg);
            send_event(&ipc2, ProxyEvent::WebSocket {
                id:        Uuid::new_v4().to_string(),
                host:      host_str.clone(),
                direction: "server→client".to_string(),
                content:   content.clone(),
                is_binary: msg.is_binary(),
                timestamp: Utc::now().to_rfc3339(),
            });
            if browser_tx.send(msg).await.is_err() { break; }
        }
    });

    tokio::select! {
        _ = b2s => {}
        _ = s2b => {}
    }
}

fn msg_to_string(msg: &Message) -> String {
    match msg {
        Message::Text(t)   => t.to_string(),
        Message::Binary(b) => format!("<binary {} bytes>", b.len()),
        Message::Ping(b)   => format!("<ping {} bytes>", b.len()),
        Message::Pong(b)   => format!("<pong {} bytes>", b.len()),
        Message::Close(_)  => "<close>".to_string(),
        Message::Frame(_)  => "<frame>".to_string(),
    }
}
