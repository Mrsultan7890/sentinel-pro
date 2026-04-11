# Changelog

All notable changes to The Sentinel Pro are documented here.

---

## [3.0.0] — Current

### Added — ML Engine (`modules/ml_engine/`)
- **EntityMatcher** — TF-IDF character n-gram + cosine similarity for cross-platform profile matching
- **UsernameClusterer** — DBSCAN density-based clustering, 52-dimensional feature vectors, leet-speak normalization
- **IdentityScorer** — Bayesian log-odds aggregation with OSINT-grade evidence weights
- **NLPProfileAnalyzer** — NLTK NER (persons/orgs/locations), profession detection, interest profiling, personality markers, writing style fingerprint, hidden contact extraction, language detection, TF-IDF key topics
- **TimelineAnalyzer** — KMeans activity clustering, timezone estimation from posting patterns, sleep window detection, behavioral pattern analysis (burst posting, late-night activity, regular schedule)
- **WritingFingerprinter** — Authorship attribution via character n-grams + function word frequencies + stylometrics + punctuation patterns

### Added — Person OSINT (`modules/recon/`)
- **PersonOSINT** — `person <name/email/phone>` command — 10 social platforms, username variations, Gravatar lookup, people search engines
- **ImageOSINT** — `image <path>` command — EXIF metadata, reverse image search, OpenCV face detection, DeepFace analysis
- **RelationMapper** — ML-powered graph builder using EntityMatcher + UsernameClusterer + IdentityScorer
- **PersonReport** — JSON + HTML + summary report generator

### Added — NLP Command
- `nlp <text>` — direct text analysis
- `nlp session` — analyze collected session data automatically

### Updated — Config
- `config.py` — ML settings (threshold, eps, min_samples), `validate_ml_engine()` function, `ML_MODELS_DIR`
- `.env.example` — ML configuration variables
- `requirements.txt` — scikit-learn, numpy, nltk, scipy now required (not optional)
- `setup.sh` — NLTK data auto-download, `models/ml_engine/` directory creation
- `modules/ml_engine/__init__.py` — proper exports for all 6 ML classes

---

## [2.1.0]

### Added
- **Phone OSINT** — `phone <number>` command — NumVerify + AbstractAPI + carrier/line-type + social hints + spam reputation
- **OAuth Scanner** — `modules/bugbounty/oauth_scanner.py` — open redirect, implicit flow, state param, PKCE bypass, client_secret exposure, OIDC config audit
- **docker-compose.yml** — single `docker compose up` startup with Tor sidecar
- **Executive Summary** — all 3 report types (bugbounty/recon/breach) now include prioritized remediation section
- **PDF Export** — `modules/pdf_export.py` — WeasyPrint dark-theme PDF after every scan + manual `pdf` command
- **Telegram Alerts** — `modules/notifications.py` — auto CRITICAL/HIGH alerts after bugbounty/recon/breach scans

### Security Fixes
- HTML escaping (`html.escape`) in all report files — XSS prevention
- `urllib3.disable_warnings()` globally — SSL warning suppression
- `RotatingFileHandler` (5MB / 3 backups) — log rotation
- Pinned all `requirements.txt` dependencies

### Infrastructure
- `Dockerfile` — Python 3.11-slim + Tor + Chromium + Go + Rust + nmap, non-root user
- `LICENSE` — MIT with legal notice

---

## [2.0.0]

### Phase 9 — Recon Modules
- `asn_mapper.py` — ASN / IP range mapping via BGPView
- `cloud_assets.py` — S3/GCS/Azure bucket discovery
- `cert_transparency.py` — crt.sh + certspotter CT log mining
- `job_osint.py` — LinkedIn/Indeed/Glassdoor tech stack extraction

### Phase 7 — Bug Bounty Modules
- `auth_bypass.py` — JWT alg:none, weak secret brute-force, 2FA bypass, admin panel detection
- `api_scanner.py` — REST/GraphQL introspection, BOLA, mass assignment, rate limit bypass
- `lfi_scanner.py` — LFI/RFI with 40+ payloads, POST form detection
- `xxe_scanner.py` — XXE injection on XML endpoints
- `ssti_scanner.py` — SSTI for Jinja2/Twig/Freemarker/Velocity
- `clickjacking.py` — X-Frame-Options + CSP frame-ancestors audit
- `prototype_pollution.py` — JSON prototype pollution via GET/POST/headers

### Breach Module Upgrade
- HIBP v3 API (breaches + pastes)
- Dehashed plaintext password lookup
- Paste Monitor (psbdmp.ws + Ghostbin)

### Subdomain Enum Upgrade
- Wordlist: 60 → 386 entries
- Sources: 4 → 6 (added VirusTotal + AlienVault OTX + RapidDNS)
- Threads: 10 → 50

### Vuln Scanner Upgrade
- Blind time-based SQLi
- DOM XSS detection
- POST form auto-detection via BeautifulSoup
- Header injection (X-Forwarded-Host / X-Original-URL)

### Endpoint Scanner Upgrade
- Sensitive paths: 45 → 626
- HTTP method testing (TRACE/DELETE/PUT via OPTIONS)
- Enhanced tech fingerprinting (React/Angular/Vue/Rails/ASP.NET)

---

## [1.0.0]

### Initial Release
- Core OSINT: collect, analyze, darkweb, semantic, media, financial, network, fakecheck, evidence, report
- Bug Bounty: SSL, headers, ports, endpoints, Shodan, vuln scan, screenshot, JS analyzer, CVE lookup
- Recon: WHOIS, subdomain enum, Go scraper, Wayback Machine, DNS history, Google/GitHub dorking
- Breach: BreachDirectory, HudsonRock, LeakCheck, IntelX
- Tor routing via socks5h://127.0.0.1:9050
- Multi-language: Python orchestration + Go HTTP scraper + Rust parallel analyzer
