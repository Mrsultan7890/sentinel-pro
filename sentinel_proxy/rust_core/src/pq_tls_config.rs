// Post-Quantum TLS Configuration
// Hybrid cipher suites with PQ crypto
// Integrates with existing rustls setup

#![allow(dead_code)]
use crate::cert_store::CertStore;
use crate::pq_tls::{HybridKemKeypair, HybridSignKeypair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// PQ-TLS mode configuration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PQMode {
    /// Classical crypto only (X25519 + Ed25519)
    Classical,
    /// Hybrid mode (X25519+Kyber + Ed25519+Dilithium)
    Hybrid,
    /// Post-quantum only (Kyber + Dilithium)
    PQOnly,
}

/// Global PQ mode (can be changed at runtime)
static mut PQ_MODE: PQMode = PQMode::Classical;

/// Set PQ mode
pub fn set_pq_mode(mode: PQMode) {
    unsafe {
        PQ_MODE = mode;
    }
}

/// Get current PQ mode
pub fn get_pq_mode() -> PQMode {
    unsafe { PQ_MODE }
}

/// Create TLS acceptor with PQ support
pub fn make_pq_acceptor(host: &str, store: &CertStore) -> TlsAcceptor {
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

    // TODO: Add custom cipher suites based on PQ_MODE
    // For now, use default rustls cipher suites
    // Future: Implement custom CipherSuite with Kyber/Dilithium

    TlsAcceptor::from(Arc::new(config))
}

/// Create TLS connector with PQ support
pub fn make_pq_connector() -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // ALPN: try HTTP/2 first, fallback HTTP/1.1
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // TODO: Add custom cipher suites based on PQ_MODE
    // For now, use default rustls cipher suites

    TlsConnector::from(Arc::new(config))
}

/// Generate PQ keypair for TLS
pub fn generate_pq_keypair() -> (HybridKemKeypair, HybridSignKeypair) {
    let kem = HybridKemKeypair::generate();
    let sig = HybridSignKeypair::generate();
    (kem, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::PublicKey as KemPublicKey;
    use pqcrypto_traits::sign::PublicKey as SignPublicKey;

    #[test]
    fn test_pq_mode() {
        set_pq_mode(PQMode::Hybrid);
        assert_eq!(get_pq_mode(), PQMode::Hybrid);

        set_pq_mode(PQMode::Classical);
        assert_eq!(get_pq_mode(), PQMode::Classical);

        set_pq_mode(PQMode::PQOnly);
        assert_eq!(get_pq_mode(), PQMode::PQOnly);
    }

    #[test]
    fn test_generate_pq_keypair() {
        let (kem, sig) = generate_pq_keypair();
        assert_eq!(kem.classical_public.as_bytes().len(), 32);
        assert!(kem.pq_public.as_bytes().len() > 0);
        assert_eq!(sig.classical_verifying.as_bytes().len(), 32);
        assert!(sig.pq_public.as_bytes().len() > 0);
    }
}
