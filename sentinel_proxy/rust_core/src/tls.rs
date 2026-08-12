// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

use crate::cert_store::CertStore;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub fn make_acceptor(host: &str, store: &CertStore) -> TlsAcceptor {
    let (cert_pem, key_pem) = store.get_cert_for_host(host);

    let cert_chain = certs(&mut BufReader::new(cert_pem.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();

    let key = {
        let pkcs8: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();
        if !pkcs8.is_empty() {
            rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.into_iter().next().unwrap())
        } else {
            let rsa: Vec<_> = rsa_private_keys(&mut BufReader::new(key_pem.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default();
            rustls::pki_types::PrivateKeyDer::Pkcs1(rsa.into_iter().next().unwrap())
        }
    };

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();

    // ALPN: HTTP/2 + HTTP/1.1
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    TlsAcceptor::from(Arc::new(config))
}

pub fn make_connector() -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // ALPN: try HTTP/2 first, fallback HTTP/1.1
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    TlsConnector::from(Arc::new(config))
}

/// Check if negotiated protocol is HTTP/2
pub fn _is_http2(_stream: &tokio_rustls::server::TlsStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>) -> bool {
    false // placeholder — checked via alpn_protocol() on the stream
}
