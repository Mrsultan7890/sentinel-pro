use dashmap::DashMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

const CA_CERT: &str = "/home/kali/.mitmproxy/sentinel-ca-cert.pem";
const CA_KEY:  &str = "/home/kali/.mitmproxy/sentinel-ca.key";

#[derive(Clone)]
pub struct CertStore {
    cache: Arc<DashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::ensure_ca();
        Self { cache: Arc::new(DashMap::new()) }
    }

    /// Generate CA with openssl if not exists
    fn ensure_ca() {
        if Path::new(CA_CERT).exists() && Path::new(CA_KEY).exists() {
            return;
        }
        let _ = std::fs::create_dir_all("/home/kali/.mitmproxy");

        // Generate CA key
        Command::new("openssl")
            .args(["genrsa", "-out", CA_KEY, "2048"])
            .output().ok();

        // Generate CA cert with all required extensions
        Command::new("openssl")
            .args([
                "req", "-new", "-x509", "-days", "3650",
                "-key",  CA_KEY,
                "-out",  CA_CERT,
                "-subj", "/CN=SentinelProxy CA v2.0/O=SentinelProxy",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always",
            ])
            .output().ok();
    }

    /// Generate domain cert signed by our CA using openssl
    pub fn get_cert_for_host(&self, host: &str) -> (Vec<u8>, Vec<u8>) {
        // Wildcard: sub.example.com → cache key = *.example.com
        let cache_key = if host.starts_with("www.") || host.matches('.').count() >= 2 {
            let parts: Vec<&str> = host.splitn(2, '.').collect();
            if parts.len() == 2 { format!("*.{}", parts[1]) } else { host.to_string() }
        } else {
            host.to_string()
        };

        if let Some(cached) = self.cache.get(&cache_key) {
            return cached.clone();
        }

        let safe    = cache_key.replace('.', "_").replace('*', "star");
        let tmp_key  = format!("/tmp/sp_{}.key", safe);
        let tmp_csr  = format!("/tmp/sp_{}.csr", safe);
        let tmp_cert = format!("/tmp/sp_{}.crt", safe);
        let tmp_ext  = format!("/tmp/sp_{}.ext", safe);

        // SAN includes both exact host and wildcard
        let san = if cache_key.starts_with("*.") {
            format!("DNS:{},DNS:{}", cache_key, &cache_key[2..])
        } else {
            format!("DNS:{}", cache_key)
        };

        let ext = format!(
            "basicConstraints=CA:FALSE\n\
             keyUsage=critical,digitalSignature,keyEncipherment\n\
             extendedKeyUsage=serverAuth\n\
             subjectKeyIdentifier=hash\n\
             authorityKeyIdentifier=keyid:always\n\
             subjectAltName={}\n",
            san
        );
        let _ = std::fs::write(&tmp_ext, &ext);

        Command::new("openssl")
            .args(["genrsa", "-out", &tmp_key, "2048"])
            .output().ok();

        Command::new("openssl")
            .args([
                "req", "-new",
                "-key",  &tmp_key,
                "-out",  &tmp_csr,
                "-subj", &format!("/CN={}", cache_key),
            ])
            .output().ok();

        Command::new("openssl")
            .args([
                "x509", "-req", "-days", "825",
                "-in",      &tmp_csr,
                "-CA",      CA_CERT,
                "-CAkey",   CA_KEY,
                "-CAcreateserial",
                "-out",     &tmp_cert,
                "-extfile", &tmp_ext,
            ])
            .output().ok();

        let cert_pem = std::fs::read(&tmp_cert).unwrap_or_default();
        let key_pem  = std::fs::read(&tmp_key).unwrap_or_default();

        for f in [&tmp_key, &tmp_csr, &tmp_cert, &tmp_ext] {
            let _ = std::fs::remove_file(f);
        }

        self.cache.insert(cache_key, (cert_pem.clone(), key_pem.clone()));
        (cert_pem, key_pem)
    }
}
