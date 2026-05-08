// Post-Quantum TLS Integration for SentinelProxy
// Hybrid X25519+Kyber1024 key exchange
// Hybrid Ed25519+Dilithium5 signatures

use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::kem::{PublicKey, SharedSecret, Ciphertext};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, SignedMessage, DetachedSignature};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use std::io::{self, Error, ErrorKind};

/// Hybrid keypair for key exchange (X25519 + Kyber1024)
pub struct HybridKemKeypair {
    pub classical_secret: EphemeralSecret,
    pub classical_public: X25519PublicKey,
    pub pq_public: kyber1024::PublicKey,
    pub pq_secret: kyber1024::SecretKey,
}

impl HybridKemKeypair {
    /// Generate new hybrid keypair
    pub fn generate() -> Self {
        let classical_secret = EphemeralSecret::random_from_rng(OsRng);
        let classical_public = X25519PublicKey::from(&classical_secret);
        let (pq_public, pq_secret) = kyber1024::keypair();
        
        Self {
            classical_secret,
            classical_public,
            pq_public,
            pq_secret,
        }
    }
}

/// Hybrid signature keypair (Ed25519 + Dilithium5)
pub struct HybridSignKeypair {
    pub classical_signing: SigningKey,
    pub classical_verifying: VerifyingKey,
    pub pq_public: dilithium5::PublicKey,
    pub pq_secret: dilithium5::SecretKey,
}

impl HybridSignKeypair {
    /// Generate new hybrid signature keypair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let classical_signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let classical_verifying = classical_signing.verifying_key();
        let (pq_public, pq_secret) = dilithium5::keypair();
        
        Self {
            classical_signing,
            classical_verifying,
            pq_public,
            pq_secret,
        }
    }
}

/// Hybrid key exchange: X25519 + Kyber1024
/// Note: This consumes the classical_secret (X25519 requires ownership)
pub fn hybrid_key_exchange_client(
    pq_public: &kyber1024::PublicKey,
) -> io::Result<(Vec<u8>, X25519PublicKey, kyber1024::Ciphertext)> {
    // Generate ephemeral X25519 keypair
    let classical_secret = EphemeralSecret::random_from_rng(OsRng);
    let classical_public = X25519PublicKey::from(&classical_secret);
    
    // Placeholder peer public key (in real TLS, this comes from server)
    let peer_public = X25519PublicKey::from([0u8; 32]);
    
    // X25519 key exchange
    let classical_shared = classical_secret.diffie_hellman(&peer_public);
    
    // Kyber1024 encapsulation
    let (pq_shared, ciphertext) = kyber1024::encapsulate(pq_public);
    
    // Combine shared secrets using KDF (SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(classical_shared.as_bytes());
    hasher.update(pq_shared.as_bytes());
    let combined = hasher.finalize();
    
    Ok((combined.to_vec(), classical_public, ciphertext))
}

/// Hybrid signature: Ed25519 + Dilithium5
pub fn hybrid_sign(message: &[u8], keypair: &HybridSignKeypair) -> io::Result<Vec<u8>> {
    // Ed25519 signature
    let classical_sig = keypair.classical_signing.sign(message);
    
    // Dilithium5 signature
    let pq_sig = dilithium5::detached_sign(message, &keypair.pq_secret);
    
    // Combine signatures: [classical_sig (64 bytes) | pq_sig (4595 bytes)]
    let mut combined = Vec::with_capacity(64 + pq_sig.as_bytes().len());
    combined.extend_from_slice(classical_sig.to_bytes().as_ref());
    combined.extend_from_slice(pq_sig.as_bytes());
    
    Ok(combined)
}

/// Hybrid signature verification: Ed25519 + Dilithium5
pub fn hybrid_verify(
    message: &[u8],
    signature: &[u8],
    classical_pubkey: &VerifyingKey,
    pq_pubkey: &dilithium5::PublicKey,
) -> io::Result<bool> {
    if signature.len() < 64 {
        return Err(Error::new(ErrorKind::InvalidData, "Signature too short"));
    }
    
    // Split signature
    let (classical_sig_bytes, pq_sig_bytes) = signature.split_at(64);
    
    // Verify Ed25519
    let classical_sig = Signature::from_bytes(classical_sig_bytes.try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Ed25519 signature"))?);
    
    if classical_pubkey.verify(message, &classical_sig).is_err() {
        return Ok(false);
    }
    
    // Verify Dilithium5
    let pq_sig = dilithium5::DetachedSignature::from_bytes(pq_sig_bytes)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Dilithium5 signature"))?;
    
    match dilithium5::verify_detached_signature(&pq_sig, message, pq_pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_keypair() {
        let keypair = HybridKemKeypair::generate();
        assert_eq!(keypair.classical_public.as_bytes().len(), 32);
        assert!(keypair.pq_public.as_bytes().len() > 0);
    }

    #[test]
    fn test_hybrid_sign_keypair() {
        let keypair = HybridSignKeypair::generate();
        assert_eq!(keypair.classical_verifying.as_bytes().len(), 32);
        assert!(keypair.pq_public.as_bytes().len() > 0);
    }

    #[test]
    fn test_hybrid_sign_verify() {
        let keypair = HybridSignKeypair::generate();
        let message = b"test message";
        
        let signature = hybrid_sign(message, &keypair).unwrap();
        assert!(signature.len() > 64);
        
        let valid = hybrid_verify(
            message,
            &signature,
            &keypair.classical_verifying,
            &keypair.pq_public,
        ).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_hybrid_sign_verify_invalid() {
        let keypair = HybridSignKeypair::generate();
        let message = b"test message";
        let wrong_message = b"wrong message";
        
        let signature = hybrid_sign(message, &keypair).unwrap();
        
        let valid = hybrid_verify(
            wrong_message,
            &signature,
            &keypair.classical_verifying,
            &keypair.pq_public,
        ).unwrap();
        
        assert!(!valid);
    }
}
