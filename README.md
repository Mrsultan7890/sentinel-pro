```
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ████████╗██╗  ██╗███████╗   ███████╗███████╗███╗   ██╗████████╗  ║
║   ╚══██╔══╝██║  ██║██╔════╝   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝  ║
║      ██║   ███████║█████╗     ███████╗█████╗  ██╔██╗ ██║   ██║     ║
║      ██║   ██╔══██║██╔══╝     ╚════██║██╔══╝  ██║╚██╗██║   ██║     ║
║      ██║   ██║  ██║███████╗   ███████║███████╗██║ ╚████║   ██║     ║
║      ╚═╝   ╚═╝  ╚═╝╚══════╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝     ║
║                                                                      ║
║    ██████╗ ██████╗  ██████╗     ██╗   ██╗██████╗     ██╗           ║
║    ██╔══██╗██╔══██╗██╔═══██╗    ██║   ██║╚════██╗   ███║           ║
║    ██████╔╝██████╔╝██║   ██║    ██║   ██║ █████╔╝   ╚██║           ║
║    ██╔═══╝ ██╔══██╗██║   ██║    ╚██╗ ██╔╝██╔═══╝     ██║           ║
║    ██║     ██║  ██║╚██████╔╝     ╚████╔╝ ███████╗    ██║           ║
║    ╚═╝     ╚═╝  ╚═╝ ╚═════╝       ╚═══╝  ╚══════╝    ╚═╝           ║
║                                                                      ║
║   🛡  OSINT  │  🐛 Bug Bounty  │  🔍 Recon  │  🤖 AI/ML            ║
║   Python · Go · Rust  │  40+ Platforms  │  Legal-Grade              ║
╚══════════════════════════════════════════════════════════════════════╝
```

# The Sentinel Pro v2.1

> Professional OSINT · Bug Bounty · Threat Intelligence Platform  
> Multi-language: **Python** (orchestration) · **Go** (HTTP scraping) · **Rust** (parallel analysis)  
> Built-in **ML engine** with continuous learning from real scans

---

## Requirements

- Kali Linux (recommended) or any Debian-based distro
- Python 3.10+
- Go 1.21+
- Rust / Cargo 1.70+
- Chromium (for screenshots)

---

## Installation

### Option A — Native (recommended for Kali)

```bash
# 1. Clone / extract the project
cd /path/to/osints

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Build Go + Rust binaries
bash setup.sh

# 5. Configure API keys (optional but recommended)
cp .env.example .env
nano .env
```

### Option B — Docker (single command)

```bash
cp .env.example .env
nano .env                  # fill in your keys
docker compose up          # starts Tor + Sentinel automatically
```

---

## API Keys (Optional)

Copy `.env.example` to `.env` and fill in the keys you have.  
The tool works without any keys — keys unlock additional data sources.

| Key | Service | Free Tier |
|-----|---------|-----------|
| `SHODAN_API_KEY` | Shodan host intelligence | Yes (limited) |
| `GITHUB_TOKEN` | GitHub code dorking | Yes (5000 req/hr) |
| `SERPAPI_KEY` | Google dorking auto-execute | Paid |
| `SECURITYTRAILS_API_KEY` | DNS history | Yes (50 req/month) |
| `NVD_API_KEY` | CVE lookup (higher rate limit) | Yes (free) |
| `HIBP_API_KEY` | HaveIBeenPwned breach lookup | Paid ($3.50/month) |
| `DEHASHED_EMAIL` | Dehashed plaintext passwords | Paid |
| `DEHASHED_API_KEY` | Dehashed plaintext passwords | Paid |
| `NUMVERIFY_API_KEY` | Phone carrier + line type | Yes (100 req/month) |
| `ABSTRACTAPI_PHONE_KEY` | Phone validation backup | Yes (250 req/month) |
| `TELEGRAM_BOT_TOKEN` | Instant CRITICAL alerts | Free |
| `TELEGRAM_CHAT_ID` | Telegram DM target | Free |

---

## Usage

### Interactive Mode

```bash
source venv/bin/activate
python3 main.py
```

### Direct CLI Mode (non-interactive)

```bash
python3 main.py --bugbounty example.com
python3 main.py --recon example.com
python3 main.py --breach user@example.com
python3 main.py --email user@example.com
python3 main.py --phone +919876543210
python3 main.py --scan-all example.com     # recon + bugbounty + breach
python3 main.py --version
python3 main.py --help
```

---

## Commands

### Bug Bounty
```
sentinel-pro> bugbounty <domain>
```
Runs: SSL/TLS grading · Security headers · Port scan · Endpoint discovery (626 paths) · Shodan lookup · SQLi/XSS/SSRF/Blind SQLi/DOM XSS · Screenshot · JS file analysis · CVE lookup · Subdomain takeover · CORS · Open redirect · HTTP smuggling · DirBuster · Nuclei templates · Cookie security · DNS zone transfer · Rust fuzzer · Tech fingerprint · Auth bypass / JWT · API security / GraphQL · LFI/RFI · XXE · SSTI · Clickjacking · Prototype pollution · OAuth misconfigurations · Rust parallel analysis

### Recon
```
sentinel-pro> recon <domain>
```
Runs: WHOIS + DNS records · Subdomain enumeration (6 sources, 386-word wordlist, 30 threads) · Go deep scraper · Wayback Machine (5000 URLs) · DNS history · Google dorking · GitHub dorking · ASN/IP range mapping · Cloud asset discovery · Certificate transparency · Job posting OSINT

### Breach Check
```
sentinel-pro> breach <email or username>
```
Checks: BreachDirectory · HudsonRock stealer logs · LeakCheck · IntelX · HIBP v3 · Dehashed plaintext passwords · Paste Monitor (psbdmp.ws)

### Email OSINT
```
sentinel-pro> email <email>
```
Checks: MX/SPF validation · Disposable email detection · Social profile probing (8 platforms) · Breach databases · Infostealer logs

### Phone OSINT
```
sentinel-pro> phone <number>
```
Checks: E.164 normalization · Country + carrier + line type (mobile/landline/VoIP) · NumVerify API · AbstractAPI · Social hints (WhatsApp/Telegram) · Spam/scam reputation

### Full Scan
```
sentinel-pro> scan all <domain>
```
Chains recon + bugbounty + breach in sequence.

### OSINT Collection
```
sentinel-pro> collect <target>      # 40+ platform social collection
sentinel-pro> analyze               # AI threat analysis
sentinel-pro> fakecheck             # Fake profile / deepfake detection
sentinel-pro> darkweb <target>      # Dark web / Tor investigation
sentinel-pro> semantic              # Semantic content analysis
sentinel-pro> financial             # Crypto / financial trail analysis
sentinel-pro> network               # Influence network mapping
sentinel-pro> evidence              # Legal evidence vault
sentinel-pro> report                # Court-grade legal report
sentinel-pro> status                # System + API keys status
```

### ML Model Training
```
sentinel-pro> train status          # Model training status + pending samples
sentinel-pro> train collect         # CRL se training data crawl karo
sentinel-pro> train run             # Models train karo
sentinel-pro> train save            # Trained models save karo
sentinel-pro> train eval            # Accuracy evaluation report
```

> **Continuous Learning:** Every real scan automatically feeds labeled data into the training pool.  
> After every 50 new samples, models auto-retrain silently in the background.

### System
```
sentinel-pro> tor on / off / status / newip
sentinel-pro> telegram test / status
sentinel-pro> pdf
sentinel-pro> clear
```

---

## ML Engine

The Sentinel Pro includes a built-in ML engine that improves with every scan.

### Models

| Model | Algorithm | Purpose |
|-------|-----------|---------|
| `ThreatClassifier` | TF-IDF + LogisticRegression | Predict threat level from text (LOW/MEDIUM/HIGH/CRITICAL) |
| `FakeProfileDetector` | TF-IDF + RandomForest | Detect fake/bot accounts (0–100% probability) |
| `IdentityLinker` | Bayesian log-odds | Link multiple profiles to same person |

### NLP Engine

| Feature | Backend | Accuracy |
|---------|---------|---------|
| Named Entity Recognition | spaCy `en_core_web_sm` (fallback: NLTK) | ~90% (spaCy) / ~60% (NLTK) |
| Language Detection | langdetect (55 languages) | ~95% |
| Writing Fingerprint | Character n-gram TF-IDF | Authorship attribution |
| Personality Analysis | Context-aware keyword matching | Negation-aware |

### Training Data Pipeline (CRL)

```
CRL (crawl-relevance-layers)
    ↓
search_and_crawl(query, mode="keyword")
    ↓
Labeled training data (text + label)
    ↓
ThreatClassifier.train()  →  threat_classifier.joblib
FakeDetector.train()      →  fake_detector.joblib
    ↓
Auto-loaded on next scan
```

### Continuous Learning Flow

```
Real scan runs (nlp / fakecheck / breach / person)
    ↓
scan_result_to_training_data() extracts labeled samples
    ↓
scan_feedback.jsonl mein save
    ↓
Every 50 new samples → auto-retrain + save
    ↓
Better accuracy on next scan
```

---

## Reports

All scans auto-save reports to `reports/` directory:

| Format | Contents |
|--------|----------|
| `.json` | Full machine-readable data |
| `_summary.txt` | Human-readable summary + Executive Summary + Remediation Priority |
| `.html` | Dark-theme interactive HTML report + Executive Summary card |
| `.pdf` | PDF export via WeasyPrint (`pip install weasyprint`) |

---

## Alerts

Set `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` in `.env` to receive instant alerts after every scan for CRITICAL/HIGH findings.

---

## Architecture

```
main.py                      ← CLI orchestrator (Python)
config.py                    ← Centralized config + API keys
docker-compose.yml           ← Docker: Tor sidecar + Sentinel
Dockerfile                   ← Python 3.11-slim + Tor + Chromium + Go + Rust
modules/
  bugbounty/
    ssl_checker.py           ← SSL/TLS grading
    headers_checker.py       ← Security headers
    port_scanner.py          ← TCP port scanner
    endpoint_scanner.py      ← 626 sensitive paths + WAF + HTTP methods
    shodan_scanner.py        ← Shodan host intelligence
    vuln_scanner.py          ← SQLi (error+blind) / XSS (reflected+DOM) / SSRF / header injection
    screenshot.py            ← Chromium headless screenshots
    js_analyzer.py           ← JS file secret extraction
    cve_lookup.py            ← NVD CVE lookup with CVSS scoring
    auth_bypass.py           ← JWT alg:none / weak secret / 2FA bypass / admin panels
    api_scanner.py           ← REST/GraphQL introspection / BOLA / mass assignment
    lfi_scanner.py           ← LFI/RFI (40+ payloads)
    xxe_scanner.py           ← XXE injection
    ssti_scanner.py          ← SSTI (Jinja2/Twig/Freemarker/Velocity)
    clickjacking.py          ← X-Frame-Options + CSP audit
    prototype_pollution.py   ← JSON prototype pollution
    oauth_scanner.py         ← OAuth open redirect / implicit flow / PKCE / client_secret
    cors_scanner.py          ← CORS misconfiguration
    open_redirect.py         ← Unvalidated redirect
    subdomain_takeover.py    ← Dangling DNS takeover
    nuclei_bridge.py         ← Nuclei template scanner
    smuggler_bridge.py       ← HTTP request smuggling
    dirbuster_bridge.py      ← Directory brute-force
    cookie_analyzer.py       ← Cookie security flags
    dns_zone_transfer.py     ← AXFR zone transfer
    fuzzer_bridge.py         ← Rust parallel fuzzer
    tech_fingerprint.py      ← Deep tech stack detection (favicon hash + headers + HTML)
    rust_analyzer_bridge.py  ← Rust binary bridge
    report.py                ← JSON + TXT + HTML reports (with Executive Summary)
  recon/
    whois_lookup.py          ← WHOIS + DNS records
    subdomain_enum.py        ← 6 sources / 386-word wordlist / 30 threads
    go_scraper_bridge.py     ← Go binary bridge
    wayback.py               ← Wayback Machine CDX API (5000 URLs)
    dns_history.py           ← HackerTarget + SecurityTrails
    email_osint.py           ← Email investigation (8 social platforms)
    phone_osint.py           ← Phone number OSINT (carrier/country/social/reputation)
    github_dorker.py         ← GitHub code search
    google_dorker.py         ← Google dork automation
    asn_mapper.py            ← ASN / IP range mapping
    cloud_assets.py          ← S3/GCS/Azure bucket discovery
    cert_transparency.py     ← crt.sh + certspotter CT logs
    job_osint.py             ← Job posting tech stack extraction
    report.py                ← JSON + TXT + HTML reports (with Executive Summary)
    email_report.py          ← Email OSINT reports
    phone_report.py          ← Phone OSINT reports
  breach/
    breach_checker.py        ← 7 sources: BreachDirectory / HudsonRock / LeakCheck / IntelX / HIBP / Dehashed / Paste Monitor
    report.py                ← JSON + TXT + HTML reports (with Executive Summary)
  ml_engine/
    nlp_analyzer.py          ← spaCy NER + TF-IDF + personality + writing fingerprint
    entity_matcher.py        ← TF-IDF cosine similarity profile matching
    identity_scorer.py       ← Bayesian log-odds identity confidence scoring
    username_clusterer.py    ← DBSCAN username clustering
    writing_fingerprinter.py ← Character n-gram authorship attribution
    timeline_analyzer.py     ← KMeans activity pattern + timezone estimation
    trainer.py               ← CRL-powered training pipeline + continuous learning
  notifications.py           ← Telegram CRITICAL/HIGH alerts
  pdf_export.py              ← WeasyPrint PDF export
  utils.py                   ← Thread-safe rate limiter + Tor session + safe HTTP wrapper
models/
  ml_engine/
    threat_classifier.joblib ← Trained threat level classifier
    fake_detector.joblib     ← Trained fake profile detector
    metadata.json            ← Training metadata + sample counts
    training_data/           ← CRL-crawled + real-scan training data
scraper/                     ← Go HTTP scraper binary
analyzer/                    ← Rust parallel analyzer binary
```

---

## Rate Limiting

All HTTP requests go through `modules/utils.rate_limited_get()` which:
- Enforces per-namespace rate limits (configurable in `.env`)
- Thread-safe with `threading.Lock()`
- Returns `None` on timeout/connection error instead of crashing
- Respects `OSINT_RATE_LIMIT` and `OSINT_RATE_PERIOD` env vars

---

## Environment Variables

```bash
# API Keys
SHODAN_API_KEY=
GITHUB_TOKEN=
SERPAPI_KEY=
SECURITYTRAILS_API_KEY=
NVD_API_KEY=
HIBP_API_KEY=
DEHASHED_EMAIL=
DEHASHED_API_KEY=
NUMVERIFY_API_KEY=
ABSTRACTAPI_PHONE_KEY=

# Telegram
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Rate limiting (default: 10 requests per 60 seconds)
OSINT_RATE_LIMIT=10
OSINT_RATE_PERIOD=60

# Timeouts
OSINT_TIMEOUT=10
OSINT_LONG_TIMEOUT=30

# Logging
OSINT_LOG_LEVEL=INFO
```

---

## Legal Notice

This tool is intended for **authorized security testing and OSINT research only**.  
Always obtain proper written authorization before scanning any target.  
The authors are not responsible for misuse.
