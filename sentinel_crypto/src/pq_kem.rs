use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

pub struct KyberKEM;
pub struct KyberPublicKey(pub Vec<u8>);
pub struct KyberSecretKey(pub Vec<u8>);
pub struct KyberCiphertext(pub Vec<u8>);

impl KyberKEM {
    pub fn keypair() -> (KyberPublicKey, KyberSecretKey) {
        let (pk, sk) = keypair();
        (KyberPublicKey(pk.as_bytes().to_vec()), KyberSecretKey(sk.as_bytes().to_vec()))
    }

    pub fn encapsulate(pk: &KyberPublicKey) -> (Vec<u8>, KyberCiphertext) {
        let public_key = PublicKey::from_bytes(&pk.0).unwrap();
        let (ss, ct) = encapsulate(&public_key);
        (ss.as_bytes().to_vec(), KyberCiphertext(ct.as_bytes().to_vec()))
    }

    pub fn decapsulate(ct: &KyberCiphertext, sk: &KyberSecretKey) -> Vec<u8> {
        let secret_key = SecretKey::from_bytes(&sk.0).unwrap();
        let ciphertext = Ciphertext::from_bytes(&ct.0).unwrap();
        let ss = decapsulate(&ciphertext, &secret_key);
        ss.as_bytes().to_vec()
    }
}
