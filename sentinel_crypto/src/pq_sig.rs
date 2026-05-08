use pqcrypto_dilithium::dilithium5::*;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};

pub struct DilithiumSigner;
pub struct DilithiumPublicKey(pub Vec<u8>);
pub struct DilithiumSecretKey(pub Vec<u8>);

impl DilithiumSigner {
    pub fn keypair() -> (DilithiumPublicKey, DilithiumSecretKey) {
        let (pk, sk) = keypair();
        (DilithiumPublicKey(pk.as_bytes().to_vec()), DilithiumSecretKey(sk.as_bytes().to_vec()))
    }

    pub fn sign(msg: &[u8], sk: &DilithiumSecretKey) -> Vec<u8> {
        let secret_key = SecretKey::from_bytes(&sk.0).unwrap();
        let signed = sign(msg, &secret_key);
        signed.as_bytes().to_vec()
    }

    pub fn verify(signed_msg: &[u8], pk: &DilithiumPublicKey) -> Result<Vec<u8>, String> {
        let public_key = PublicKey::from_bytes(&pk.0).unwrap();
        let signed = SignedMessage::from_bytes(signed_msg).unwrap();
        match open(&signed, &public_key) {
            Ok(msg) => Ok(msg),
            Err(_) => Err("Signature verification failed".to_string()),
        }
    }

    pub fn sign_detached(msg: &[u8], sk: &DilithiumSecretKey) -> Vec<u8> {
        let secret_key = SecretKey::from_bytes(&sk.0).unwrap();
        let sig = detached_sign(msg, &secret_key);
        sig.as_bytes().to_vec()
    }

    pub fn verify_detached(msg: &[u8], sig: &[u8], pk: &DilithiumPublicKey) -> bool {
        let public_key = PublicKey::from_bytes(&pk.0).unwrap();
        let signature = DetachedSignature::from_bytes(sig).unwrap();
        verify_detached_signature(&signature, msg, &public_key).is_ok()
    }
}
