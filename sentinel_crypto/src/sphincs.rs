// SPHINCS+ Hash-Based Signatures
// Quantum-resistant signature scheme (stateless)
// NIST PQC Round 3 Finalist

use pqcrypto_sphincsplus::sphincssha2128ssimple as sphincs;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature as DetachedSig, SignedMessage as SignedMsg};
use std::io::{self, Error, ErrorKind};

/// SPHINCS+ keypair
pub struct SphincsKeypair {
    pub public: sphincs::PublicKey,
    pub secret: sphincs::SecretKey,
}

impl SphincsKeypair {
    /// Generate new SPHINCS+ keypair
    pub fn generate() -> Self {
        let (public, secret) = sphincs::keypair();
        Self { public, secret }
    }
}

/// Sign message with SPHINCS+
pub fn sign(message: &[u8], keypair: &SphincsKeypair) -> io::Result<Vec<u8>> {
    let signed = sphincs::sign(message, &keypair.secret);
    Ok(signed.as_bytes().to_vec())
}

/// Verify SPHINCS+ signature
pub fn verify(signed_message: &[u8], public_key: &sphincs::PublicKey) -> io::Result<Vec<u8>> {
    let signed_msg = sphincs::SignedMessage::from_bytes(signed_message)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid signed message"))?;
    
    match sphincs::open(&signed_msg, public_key) {
        Ok(msg) => Ok(msg.to_vec()),
        Err(_) => Err(Error::new(ErrorKind::InvalidData, "Signature verification failed")),
    }
}

/// Detached signature
pub fn sign_detached(message: &[u8], keypair: &SphincsKeypair) -> io::Result<Vec<u8>> {
    let sig = sphincs::detached_sign(message, &keypair.secret);
    Ok(sig.as_bytes().to_vec())
}

/// Verify detached signature
pub fn verify_detached(message: &[u8], signature: &[u8], public_key: &sphincs::PublicKey) -> io::Result<bool> {
    let sig = sphincs::DetachedSignature::from_bytes(signature)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid signature"))?;
    
    match sphincs::verify_detached_signature(&sig, message, public_key) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_keypair() {
        let keypair = SphincsKeypair::generate();
        assert!(keypair.public.as_bytes().len() > 0);
        assert!(keypair.secret.as_bytes().len() > 0);
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let keypair = SphincsKeypair::generate();
        let message = b"quantum-resistant test";
        
        let signed = sign(message, &keypair).unwrap();
        let verified = verify(&signed, &keypair.public).unwrap();
        
        assert_eq!(verified, message);
    }

    #[test]
    fn test_sphincs_detached() {
        let keypair = SphincsKeypair::generate();
        let message = b"detached signature test";
        
        let signature = sign_detached(message, &keypair).unwrap();
        let valid = verify_detached(message, &signature, &keypair.public).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_sphincs_invalid_signature() {
        let keypair = SphincsKeypair::generate();
        let message = b"original message";
        let wrong_message = b"tampered message";
        
        let signature = sign_detached(message, &keypair).unwrap();
        let valid = verify_detached(wrong_message, &signature, &keypair.public).unwrap();
        
        assert!(!valid);
    }
}
