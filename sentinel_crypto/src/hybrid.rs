use crate::pq_kem::{KyberKEM, KyberPublicKey, KyberSecretKey, KyberCiphertext};
use crate::pq_sig::{DilithiumSigner, DilithiumPublicKey, DilithiumSecretKey};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey as SigPublicKey, ED25519};
use ring::rand::SystemRandom;

pub struct HybridKEM;
pub struct HybridSigner;

impl HybridKEM {
    pub fn keypair() -> ((Vec<u8>, KyberPublicKey), (Vec<u8>, KyberSecretKey)) {
        let rng = SystemRandom::new();
        let x25519_sk = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let x25519_pk = x25519_sk.compute_public_key().unwrap().as_ref().to_vec();
        let (kyber_pk, kyber_sk) = KyberKEM::keypair();
        ((x25519_pk, kyber_pk), (vec![], kyber_sk))
    }

    pub fn encapsulate(pk: &(Vec<u8>, KyberPublicKey)) -> (Vec<u8>, (Vec<u8>, KyberCiphertext)) {
        let rng = SystemRandom::new();
        let x25519_sk = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let x25519_pk_eph = x25519_sk.compute_public_key().unwrap().as_ref().to_vec();
        let peer_pk = UnparsedPublicKey::new(&X25519, &pk.0);
        let x25519_ss = agree_ephemeral(x25519_sk, &peer_pk, |ss| ss.to_vec()).unwrap();
        
        let (kyber_ss, kyber_ct) = KyberKEM::encapsulate(&pk.1);
        let mut combined_ss = x25519_ss;
        combined_ss.extend_from_slice(&kyber_ss);
        (combined_ss, (x25519_pk_eph, kyber_ct))
    }

    pub fn decapsulate(ct: &(Vec<u8>, KyberCiphertext), sk: &(Vec<u8>, KyberSecretKey)) -> Vec<u8> {
        let kyber_ss = KyberKEM::decapsulate(&ct.1, &sk.1);
        let mut combined_ss = vec![];
        combined_ss.extend_from_slice(&kyber_ss);
        combined_ss
    }
}

impl HybridSigner {
    pub fn keypair() -> ((Vec<u8>, DilithiumPublicKey), (Vec<u8>, DilithiumSecretKey)) {
        let rng = SystemRandom::new();
        let ed25519_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let ed25519_kp = Ed25519KeyPair::from_pkcs8(ed25519_pkcs8.as_ref()).unwrap();
        let ed25519_pk = ed25519_kp.public_key().as_ref().to_vec();
        let (dilithium_pk, dilithium_sk) = DilithiumSigner::keypair();
        ((ed25519_pk, dilithium_pk), (vec![], dilithium_sk))
    }

    pub fn sign(msg: &[u8], sk: &(Vec<u8>, DilithiumSecretKey)) -> (Vec<u8>, Vec<u8>) {
        let dilithium_sig = DilithiumSigner::sign_detached(msg, &sk.1);
        (vec![], dilithium_sig)
    }

    pub fn verify(msg: &[u8], sig: &(Vec<u8>, Vec<u8>), pk: &(Vec<u8>, DilithiumPublicKey)) -> bool {
        DilithiumSigner::verify_detached(msg, &sig.1, &pk.1)
    }
}
