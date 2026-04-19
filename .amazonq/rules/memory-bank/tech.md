# The Sentinel Pro v3.0 — Technology Stack

## Languages & Runtimes
| Language | Version | Role |
|----------|---------|------|
| Python | 3.10+ | Primary — orchestration, ML, OSINT, reporting |
| Go | 1.19+ (1.21 recommended) | Network services — scraping, fuzzing, proxying |
| Rust | 1.70+ (edition 2021) | CPU-intensive parallel tasks — analysis, fuzzing |

## Python Dependencies (requirements.txt)

### Core HTTP & Networking
- `requests[socks]>=2.31.0` — HTTP with SOCKS proxy support
- `httpx[http2,brotli]>=0.25.0` — Async HTTP/2 client
- `urllib3>=2.0.0`, `PySocks>=1.7.1`
- `aiohttp>=3.9.0` — Async HTTP

### HTML Parsing
- `beautifulsoup4>=4.12.0`, `lxml>=4.9.3`

### DNS & Network Recon
- `dnspython>=2.4.0`, `python-whois>=0.9.4`

### Security & Crypto
- `cryptography>=41.0.0`, `pyOpenSSL>=23.0.0`

### Tor / Proxy
- `stem>=1.8.2` — Tor control protocol

### CLI & UI
- `rich>=13.0.0` — Rich terminal output
- `pyfiglet>=0.8.0` — ASCII art banners
- `tqdm>=4.65.0` — Progress bars
- `colorama>=0.4.6`

### ML & Data Science
- `torch>=2.0.0` — PyTorch (CPU version supported)
- `numpy>=1.24.0`, `scipy>=1.10.0`
- `scikit-learn>=1.3.0`, `joblib>=1.3.0`
- `lightgbm` — Log analysis / attack pattern detection
- `networkx>=3.1.0` — Graph neural network / entity graphs

### NLP
- `nltk>=3.8.0`, `spacy>=3.7.0`
- `langdetect>=1.0.9`
- Post-install: `python -m spacy download en_core_web_sm`

### Image OSINT
- `Pillow>=10.0.0`, `opencv-python>=4.8.0`
- `mmh3>=4.0.0` — Favicon hash fingerprinting

### Reporting
- `weasyprint>=60.0` — PDF generation
- `matplotlib>=3.7.0` — Charts/visualizations

### OSINT APIs
- `shodan>=1.28.0`
- `ddgs>=6.0.0` — DuckDuckGo search
- `fake-useragent>=1.4.0`

### Optional (heavy)
- `deepface>=0.0.79` + `tf-keras>=2.15.0` — Face analysis (~500MB)
- `transformers>=4.35.0` — HuggingFace fake profile detection

### Config
- `python-dotenv>=1.0.0`
- `ratelimit>=2.2.1`

## Rust Dependencies (Cargo.toml)
- `serde` + `serde_json` — JSON serialization
- `rayon` — Data parallelism
- `regex` — Pattern matching

## Go Dependencies
- Standard library only (go 1.19 module)

## Model Artifacts
| File | Format | Purpose |
|------|--------|---------|
| sentinel_threat_net.pt | PyTorch | SentinelNet v4.0 weights (8.55 MB) |
| sentinel_vocab.json | JSON | Tokenizer vocabulary |
| rl_qtable.json | JSON | Q-Learning Q-table (462 states) |
| threat_classifier.joblib | joblib | TF-IDF + LogReg classifier |
| fake_detector.joblib | joblib | Random Forest fake profile detector |
| ga_fitness.json | JSON | Genetic algorithm fitness data |

## Database
- SQLite via Python `sqlite3` stdlib
- `data/sentinel.db` — main database
- `data/sentinel_memory.db` — long-term memory
- Tables: scans, findings, iocs, decisions, memory, rl_episodes, tool_stats

## External Tools (Kali Linux)
Invoked via PTY/subprocess by kali_controller.py:
- `nmap` — port/service scanning
- `nikto` — web server scanning
- `nuclei` — vulnerability templates
- `gobuster` / `ffuf` — directory/parameter fuzzing
- `sqlmap` — SQL injection
- `amass` — subdomain enumeration
- `whatweb` — web tech fingerprinting
- `wafw00f` — WAF detection
- `sslscan` — SSL/TLS analysis
- `theHarvester` — email/subdomain harvesting
- `searchsploit` — exploit database search
- `chromium` — web screenshots

## Configuration (config.py)
All config loaded from environment via `python-dotenv`:

```python
# Key environment variables
TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID   # Alerts
HIBP_API_KEY                            # HaveIBeenPwned
DEHASHED_EMAIL, DEHASHED_API_KEY        # Dehashed
SHODAN_API_KEY                          # Shodan
GITHUB_TOKEN                            # GitHub dorking
SERPAPI_KEY                             # Google dorking
SECURITYTRAILS_API_KEY                  # DNS history
NVD_API_KEY                             # CVE lookup
TOR_PROXY=socks5h://127.0.0.1:9050     # Tor routing
```

Key config constants:
- `ML_CONFIDENCE_THRESHOLD = 0.50`
- `ML_CLUSTER_EPS = 0.35` (DBSCAN)
- `STEALTH_MIN_DELAY = 2.0s`, `STEALTH_MAX_DELAY = 5.0s`
- `REQUEST_TIMEOUT = 10s`, `LONG_REQUEST_TIMEOUT = 30s`
- `RATE_LIMIT_REQUESTS = 10` per `60s`
- `MAX_RETRIES = 3`

## Development Commands

### Setup
```bash
git clone https://github.com/Mrsultan7890/osints.git
cd osints
bash setup.sh
```

### Run
```bash
sentinel                          # Interactive shell
sentinel --bugbounty example.com  # Direct CLI
sentinel --recon example.com
sentinel --breach user@example.com
sentinel --scan-all example.com
```

### Python
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python main.py
```

### Build Rust
```bash
cd analyzer && cargo build --release
cd fuzzer && cargo build --release
cd media_analyzer && cargo build --release
```

### Build Go
```bash
cd scraper && go build -o scraper .
cd dirbuster && go build -o dirbuster .
cd network_mapper && go build -o network_mapper .
cd smuggler && go build -o smuggler .
cd stealth_proxy && go build -o stealth_proxy .
cd predictor && go build -o predictor .
```

### ML Training
```bash
python train_model.py             # Local training
python colab_train.py             # Google Colab training
python data_pipeline.py           # Data pipeline
python data_pipeline_v2.py        # Data pipeline v2
python rl_train_bg.py             # Background RL training
```

### Docker
```bash
docker-compose up
```

## Legal Compliance Standards
- ISO 27037, NIST SP 800-86, RFC 3227 (evidence standards)
- Chain of custody via evidence_manager.py
- Court-grade HTML/PDF reports
