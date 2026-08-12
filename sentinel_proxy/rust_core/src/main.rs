// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

mod proxy;
mod tls;
mod pq_tls;
mod pq_tls_config;
mod pq_cipher_suites;
mod cert_store;
mod ipc;
mod types;
mod intercept;
mod match_replace;
mod websocket;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let host       = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1");
    let port       = args.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(8082);
    let ipc_path   = args.get(3).map(|s| s.clone())
        .unwrap_or_else(|| "/tmp/sentinel_proxy_v2.sock".to_string());

    // Intercept manager
    let intercept = Arc::new(intercept::InterceptManager::new());

    // Match & Replace engine
    let mr_engine = Arc::new(match_replace::MatchReplaceEngine::new());

    // IPC server
    let ipc_tx = ipc::start_ipc_server(&ipc_path, intercept.clone(), mr_engine.clone()).await;

    // Cert store
    let cert_store = cert_store::CertStore::new();

    let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    info!("SentinelProxy Core v2.0 listening on {}:{}", host, port);
    info!("IPC socket: {}", ipc_path);
    info!("Ready — set browser proxy to {}:{}", host, port);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let ipc       = ipc_tx.clone();
                let certs     = cert_store.clone();
                let intercept = intercept.clone();
                let mr        = mr_engine.clone();
                tokio::spawn(async move {
                    if let Err(e) = proxy::handle_connection(
                        stream, peer_addr, ipc, certs, intercept, mr
                    ).await {
                        tracing::debug!("Connection error from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => error!("Accept error: {}", e),
        }
    }
}
