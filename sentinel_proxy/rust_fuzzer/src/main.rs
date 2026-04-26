/// SentinelProxy Parallel Fuzzer v2.0
/// Input  (stdin): JSON config
/// Output (stdout): JSONL results (one per line)
///
/// Config format:
/// {
///   "url": "https://target.com/page",
///   "method": "GET",
///   "param": "id",
///   "param2": "name",
///   "mode": "sniper|battering_ram|pitchfork|cluster_bomb",
///   "payloads": ["payload1", "payload2", ...],
///   "payloads2": ["p1", "p2", ...],
///   "threads": 20,
///   "delay_ms": 0,
///   "grep": "error",
///   "post_body": "user=§param§&pass=test",
///   "headers": {"Cookie": "session=abc"}
/// }

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct FuzzConfig {
    url:        String,
    #[serde(default = "default_get")]
    method:     String,
    param:      String,
    #[serde(default)]
    param2:     String,
    #[serde(default = "default_sniper")]
    mode:       String,
    payloads:   Vec<String>,
    #[serde(default)]
    payloads2:  Vec<String>,
    #[serde(default = "default_threads")]
    threads:    usize,
    #[serde(default)]
    delay_ms:   u64,
    #[serde(default)]
    grep:       String,
    #[serde(default)]
    post_body:  String,
    #[serde(default)]
    headers:    HashMap<String, String>,
}

fn default_get()     -> String { "GET".into() }
fn default_sniper()  -> String { "sniper".into() }
fn default_threads() -> usize  { 20 }

#[derive(Serialize)]
struct FuzzResult {
    payload:     String,
    payload2:    String,
    status:      u16,
    length:      usize,
    diff:        i64,
    grep_match:  bool,
    interesting: bool,
    error:       Option<String>,
    elapsed_ms:  u64,
    body:        String,
}

fn main() {
    // Read config from stdin
    let stdin  = io::stdin();
    let mut input = String::new();
    for line in stdin.lock().lines() {
        match line {
            Ok(l) => input.push_str(&l),
            Err(_) => break,
        }
    }

    let cfg: FuzzConfig = match serde_json::from_str(&input) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("Config parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Build attack pairs
    let pairs: Vec<(String, String)> = match cfg.mode.as_str() {
        "battering_ram" => cfg.payloads.iter()
            .map(|p| (p.clone(), p.clone())).collect(),
        "pitchfork" => cfg.payloads.iter()
            .zip(cfg.payloads2.iter().chain(std::iter::repeat(&String::new())))
            .map(|(a, b)| (a.clone(), b.clone())).collect(),
        "cluster_bomb" => cfg.payloads.iter()
            .flat_map(|p1| cfg.payloads2.iter().map(move |p2| (p1.clone(), p2.clone())))
            .collect(),
        _ => cfg.payloads.iter().map(|p| (p.clone(), String::new())).collect(),
    };

    let total     = pairs.len();
    let base_len  = Arc::new(AtomicUsize::new(0));
    let done      = Arc::new(AtomicUsize::new(0));
    let stdout    = io::stdout();
    let out_lock  = Arc::new(std::sync::Mutex::new(stdout));

    // Build reqwest blocking client
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.threads)
        .build()
        .unwrap();

    pool.install(|| {
        pairs.par_iter().for_each(|(p1, p2)| {
            let start = Instant::now();
            let result = send_request(&client, &cfg, p1, p2);
            let elapsed = start.elapsed().as_millis() as u64;

            let (status, length, body, err) = match result {
                Ok((s, l, b)) => (s, l, b, None),
                Err(e)        => (0, 0, String::new(), Some(e)),
            };

            // Set base length from first response
            let base = base_len.compare_exchange(0, length, Ordering::SeqCst, Ordering::SeqCst)
                .unwrap_or_else(|v| v);

            let diff        = length as i64 - base as i64;
            let grep_match  = !cfg.grep.is_empty() && body.to_lowercase().contains(&cfg.grep.to_lowercase());
            let interesting = status != 200 && status != 301 && status != 302 && status != 404
                || diff.abs() > 50
                || grep_match;

            let res = FuzzResult {
                payload:    p1.clone(),
                payload2:   p2.clone(),
                status,
                length,
                diff,
                grep_match,
                interesting,
                error:      err,
                elapsed_ms: elapsed,
                body:       body.chars().take(500).collect(),
            };

            let json = serde_json::to_string(&res).unwrap_or_default();
            let mut out = out_lock.lock().unwrap();
            writeln!(out, "{}", json).ok();
            out.flush().ok();

            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if cfg.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(cfg.delay_ms));
            }

            // Progress to stderr
            eprint!("\r{}/{}", n, total);
        });
    });

    eprintln!("\nDone: {}/{}", total, total);
}

fn send_request(
    client: &reqwest::blocking::Client,
    cfg:    &FuzzConfig,
    p1:     &str,
    p2:     &str,
) -> Result<(u16, usize, String), String> {
    let sep = if cfg.url.contains('?') { "&" } else { "?" };

    let url = match cfg.mode.as_str() {
        "sniper" => format!("{}{}{}={}", cfg.url, sep, cfg.param,
            urlencoding::encode(p1)),
        "battering_ram" => format!("{}{}{}={}&{}={}", cfg.url, sep,
            cfg.param, urlencoding::encode(p1),
            cfg.param2, urlencoding::encode(p1)),
        "pitchfork" | "cluster_bomb" => format!("{}{}{}={}&{}={}", cfg.url, sep,
            cfg.param, urlencoding::encode(p1),
            cfg.param2, urlencoding::encode(p2)),
        _ => format!("{}{}{}={}", cfg.url, sep, cfg.param, urlencoding::encode(p1)),
    };

    let mut req = if !cfg.post_body.is_empty() {
        let body = cfg.post_body
            .replace(&format!("§{}§", cfg.param), &urlencoding::encode(p1))
            .replace(&format!("§{}§", cfg.param2), &urlencoding::encode(p2));
        client.post(&cfg.url).body(body)
            .header("Content-Type", "application/x-www-form-urlencoded")
    } else {
        match cfg.method.to_uppercase().as_str() {
            "POST"   => client.post(&url),
            "PUT"    => client.put(&url),
            "DELETE" => client.delete(&url),
            _        => client.get(&url),
        }
    };

    for (k, v) in &cfg.headers {
        req = req.header(k, v);
    }

    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body   = resp.text().unwrap_or_default();
    let length = body.len();
    Ok((status, length, body))
}
