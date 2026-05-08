use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Kyber1024,
    Dilithium5,
    HybridKEM,
    HybridSig,
    X25519,
    Ed25519,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub kem: Algorithm,
    pub sig: Algorithm,
    pub version: u32,
}

pub struct CryptoAgility {
    configs: HashMap<u32, CryptoConfig>,
    current_version: u32,
}

impl CryptoAgility {
    pub fn new() -> Self {
        let mut configs = HashMap::new();
        configs.insert(1, CryptoConfig {
            kem: Algorithm::X25519,
            sig: Algorithm::Ed25519,
            version: 1,
        });
        configs.insert(2, CryptoConfig {
            kem: Algorithm::HybridKEM,
            sig: Algorithm::HybridSig,
            version: 2,
        });
        configs.insert(3, CryptoConfig {
            kem: Algorithm::Kyber1024,
            sig: Algorithm::Dilithium5,
            version: 3,
        });
        Self { configs, current_version: 2 }
    }

    pub fn get_current(&self) -> &CryptoConfig {
        self.configs.get(&self.current_version).unwrap()
    }

    pub fn upgrade(&mut self, version: u32) -> Result<(), String> {
        if self.configs.contains_key(&version) {
            self.current_version = version;
            Ok(())
        } else {
            Err(format!("Version {} not found", version))
        }
    }

    pub fn list_versions(&self) -> Vec<u32> {
        let mut versions: Vec<u32> = self.configs.keys().copied().collect();
        versions.sort();
        versions
    }
}

impl Default for CryptoAgility {
    fn default() -> Self {
        Self::new()
    }
}
