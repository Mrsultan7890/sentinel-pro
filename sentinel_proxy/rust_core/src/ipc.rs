use crate::intercept::InterceptManager;
use crate::match_replace::{MatchReplaceEngine, MrRule};
use crate::types::ProxyEvent;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

pub type IpcSender = mpsc::UnboundedSender<ProxyEvent>;

pub async fn start_ipc_server(
    socket_path: &str,
    intercept:   Arc<InterceptManager>,
    mr_engine:   Arc<MatchReplaceEngine>,
) -> IpcSender {
    // mpsc: proxy.rs sends events here
    let (mpsc_tx, mut mpsc_rx) = mpsc::unbounded_channel::<ProxyEvent>();

    // broadcast: fan-out to Python connections (capacity 1024)
    let (bcast_tx, _) = broadcast::channel::<String>(1024);
    let bcast_tx_arc  = Arc::new(bcast_tx);

    let path        = socket_path.to_string();
    let events_path = format!("{}.events", path);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&events_path);

    // Task 1: mpsc → broadcast bridge
    let bcast_fwd = bcast_tx_arc.clone();
    tokio::spawn(async move {
        while let Some(event) = mpsc_rx.recv().await {
            if let Ok(mut json) = serde_json::to_string(&event) {
                json.push('\n');
                let _ = bcast_fwd.send(json);
            }
        }
    });

    // Task 2: Command server (Python → Rust)
    let cmd_path = path.clone();
    tokio::spawn(async move {
        let listener = match UnixListener::bind(&cmd_path) {
            Ok(l)  => l,
            Err(e) => { warn!("[IPC-cmd] bind failed: {}", e); return; }
        };
        debug!("[IPC-cmd] Listening on {}", cmd_path);
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let ic = intercept.clone();
                    let mr = mr_engine.clone();
                    tokio::spawn(handle_commands(stream, ic, mr));
                }
                Err(e) => warn!("[IPC-cmd] accept error: {}", e),
            }
        }
    });

    // Task 3: Events server (Rust → Python) — each connection gets its own broadcast receiver
    let bcast_for_events = bcast_tx_arc.clone();
    tokio::spawn(async move {
        let listener = match UnixListener::bind(&events_path) {
            Ok(l)  => l,
            Err(e) => { warn!("[IPC-events] bind failed: {}", e); return; }
        };
        debug!("[IPC-events] Listening on {}", events_path);
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    debug!("[IPC-events] Python connected");
                    // Each connection subscribes to broadcast
                    let mut rx = bcast_for_events.subscribe();
                    tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(json) => {
                                    if stream.write_all(json.as_bytes()).await.is_err() {
                                        debug!("[IPC-events] write failed");
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    debug!("[IPC-events] lagged by {}", n);
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) => warn!("[IPC-events] accept error: {}", e),
            }
        }
    });

    mpsc_tx
}

async fn handle_commands(
    stream:    tokio::net::UnixStream,
    intercept: Arc<InterceptManager>,
    mr_engine: Arc<MatchReplaceEngine>,
) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(cmd) => {
                let action  = cmd["action"].as_str().unwrap_or("");
                let flow_id = cmd["flow_id"].as_str().unwrap_or("");
                match action {
                    "forward"       => { intercept.forward(flow_id); }
                    "drop"          => { intercept.drop_flow(flow_id); }
                    "forward_all"   => { intercept.forward_all(); }
                    "intercept_on"  => { intercept.set_enabled(true); }
                    "intercept_off" => {
                        intercept.set_enabled(false);
                        intercept.forward_all();
                    }
                    "forward_modified" => {
                        let headers: Vec<(String, String)> = cmd["headers"]
                            .as_array().unwrap_or(&vec![])
                            .iter()
                            .filter_map(|h| {
                                let k = h["name"].as_str()?.to_string();
                                let v = h["value"].as_str()?.to_string();
                                Some((k, v))
                            })
                            .collect();
                        let body = cmd["body"].as_str()
                            .map(|b| b.as_bytes().to_vec())
                            .unwrap_or_default();
                        intercept.forward_modified(flow_id, headers, body);
                    }
                    "set_mr_rules" => {
                        if let Some(rv) = cmd.get("rules") {
                            if let Ok(rules) = serde_json::from_value::<Vec<MrRule>>(rv.clone()) {
                                mr_engine.set_rules(rules);
                            }
                        }
                    }
                    "set_intercept_scope" => {
                        // hosts: ["example.com", "api.example.com"] — empty = intercept all
                        if let Some(arr) = cmd["hosts"].as_array() {
                            let hosts: Vec<String> = arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            intercept.set_scope_filter(hosts);
                        }
                    }
                    _ => debug!("[IPC-cmd] unknown: {}", action),
                }
            }
            Err(e) => debug!("[IPC-cmd] parse error: {}", e),
        }
    }
}

pub fn send_event(tx: &IpcSender, event: ProxyEvent) {
    let _ = tx.send(event);
}
