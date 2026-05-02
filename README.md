# The Sentinel Pro v3.0

```
  ██████╗ ██████╗  ██████╗     ██╗   ██╗██████╗     ██╗
  ██╔══██╗██╔══██╗██╔═══██╗    ██║   ██║╚════██╗   ███║
  ██████╔╝██████╔╝██║   ██║    ██║   ██║ █████╔╝   ╚██║
  ██╔═══╝ ██╔══██╗██║   ██║    ╚██╗ ██╔╝██╔═══╝     ██║
  ██║     ██║  ██║╚██████╔╝     ╚████╔╝ ███████╗    ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝       ╚═══╝  ╚══════╝    ╚═╝
```

> **Professional OSINT · Bug Bounty · Threat Intelligence · Autonomous AI Platform**
> Multi-language: **Python** · **Go** · **Rust**
> Built-in **Autonomous AI Brain** with ReAct Loop · Q-Learning RL · Custom Neural Networks

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)](https://rust-lang.org)
[![Go](https://img.shields.io/badge/go-1.21%2B-cyan)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red)](https://kali.org)
[![SentinelNet](https://img.shields.io/badge/SentinelNet-v5.0%20F1%3D0.83-orange)](models/)
[![Seq2Seq](https://img.shields.io/badge/Seq2Seq-v2.0%20CNN%2BTransformer-blue)](models/)
[![RL](https://img.shields.io/badge/RL-Q--Learning%20171%20states-purple)](sentinel_brain/)
[![Groq](https://img.shields.io/badge/Groq-llama--3.3--70b-green)](modules/ml_engine/)
[![SentinelProxy](https://img.shields.io/badge/SentinelProxy-v2.0%20Rust%20Core-red)](sentinel_proxy/)

---

## What Makes This Different

This is **not** a script collection. This is a fully autonomous AI security platform where:

- The AI **thinks** — ReAct loop: Reason → Act → Observe → Reason again
- The AI **learns** — Q-Learning RL trains on your real targets
- The AI **classifies** — SentinelNet v5.0 (CNN+Transformer, F1=0.83)
- The AI **generates** — Seq2Seq v2.0 generates commands, chains, reports
- The AI **reasons** — Groq llama-3.3-70b as primary reasoning layer
- The AI **remembers** — Long-term SQLite memory across sessions
- The AI **monitors** — 24/7 background monitoring with Telegram alerts
- The AI **intercepts** — SentinelProxy v2.0 Rust core — 200K req/sec
- Everything runs on **your machine** — no cloud required for core features

---

## Architecture

```
sentinel-pro> brain investigate target.com
        ↓
┌─────────────────────────────────────────────┐
│           SENTINEL BRAIN v2.0               │
│         ReAct Autonomous Loop               │
│                                             │
│  Groq llama-3.3-70b  ← Primary reasoning   │
│  Seq2Seq v2.0        ← Command generation  │
│  SentinelNet v5.0    ← Threat classification│
│  Heuristic           ← Final fallback       │
│                                             │
│  Reason → Act → Observe → Reason again      │
└─────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────┐
│         KALI CONTROLLER v2.0                │
│   Real PTY Terminal — Full OS Control       │
│                                             │
│  nmap → nikto → sqlmap → nuclei → gobuster  │
│  Auto output parsing + Tool chaining        │
│  19 tools integrated                        │
└─────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────┐
│           ADVANCED ML ENGINE                │
│                                             │
│  SentinelNet v5.0  — CNN+Transformer        │
│  Seq2Seq v2.0      — Command generation     │
│  GNN               — Entity relationship    │
│  Isolation Forest  — Anomaly detection      │
│  DBSCAN            — Username/IP clustering │
│  LightGBM          — Log analysis           │
│  Genetic Algo      — Tool sequence optimizer│
│  Q-Learning        — RL autonomous select   │
│  TF-IDF + LogReg   — Threat classifier      │
│  Random Forest     — Fake profile detector  │
└─────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────┐
│           UNIFIED DATABASE                  │
│         SQLite — sentinel.db                │
│                                             │
│  scans · findings · iocs · decisions        │
│  memory · rl_episodes · tool_stats          │
└─────────────────────────────────────────────┘
        ↓
    Telegram Alert + PDF Report
```

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Autonomous Brain** | ReAct loop, adaptive planning, retry logic, ML-driven decisions |
| **18 Agents** | recon, exploit, osint, breach, report, darkweb, network, terminal, scheduler, credential, system_monitor, correlation, filesystem, monitor, notification, browser, attack_chain, threat_intel |
| **Sentinel Intel** | Maltego-style graph intelligence platform · 13 engines (Email, Phone, IP, Domain, Person, Username, Hash, Cryptocurrency, CVE, Breach, Company, Malware, URL) · 40+ transforms · PyQt6 GUI · AI-powered auto-chaining · Risk visualization |
| **RL Agent** | Q-Learning, 19 tools, 171 states learned, epsilon-greedy |
| **SentinelNet v5.0** | CNN+Transformer, F1=0.83, threat/type/action/confidence |
| **Seq2Seq v2.0** | CNN Encoder + Transformer Decoder, cmd_gen/chain_gen/report_gen |
| **SentinelLM** | Custom language model for security text generation |
| **Groq LLM** | llama-3.3-70b-versatile, primary reasoning + fallback llama-3.1-8b |
| **Advanced ML** | GNN, Isolation Forest, DBSCAN, LightGBM, Genetic Algorithm, EntityMatcher, UsernameClusterer, IdentityScorer, NLPAnalyzer, TimelineAnalyzer, WritingFingerprinter |
| **OSINT** | 40+ social platforms, person/email/phone/image profiling · digital footprint · relation mapper |
| **Bug Bounty** | 29 scanners — SSL/TLS · Headers · Ports · SQLi/XSS/SSRF · LFI/RFI · XXE · SSTI · CORS · OAuth · JWT · Prototype Pollution · Subdomain Takeover · Shodan · CVE Lookup · HTTP Smuggling · DirBuster · Nuclei · Cookie Analyzer · DNS Zone Transfer · Rust Fuzzer · Tech Fingerprint · Auth Bypass · API Scanner · Clickjacking |
| **Recon** | 20 modules — WHOIS · DNS · Subdomains · Wayback · GitHub/Google dorking · ASN · Cloud assets · Cert Transparency · Job OSINT · Relation Mapper |
| **Breach** | HaveIBeenPwned · HudsonRock · LeakCheck · IntelX · Dehashed · Paste Monitor |
| **24/7 Monitor** | Continuous target monitoring · persistent daemon · new finding → auto Telegram alert · survives reboot |
| **Dark Web** | Tor integration · .onion crawling · Stealth mode |
| **Forensics** | Metasploit integration · privilege manager · secure file manager · evidence vault · YARA · memory analysis |
| **Legal** | Chain of custody · evidence manager · court-grade HTML/PDF reports · digital footprint |
| **SentinelProxy v2.0** | Rust core · 200K req/sec · HTTP/2 · WebSocket · Intercept · Match&Replace · Parallel Fuzzer · 22 tabs · AI analysis · 34K+ payloads |
| **License Manager** | Offline HMAC-SHA256 license system · Machine binding · No server required · Basic/Pro/Elite plans |
| **Wordlist Manager** | Central wordlist resolution · Bundled payloads · SecLists integration · Auto-install instructions · Depth control (fast/normal/deep) |
| **Report Builder** | Groq executive summary · MITRE ATT&CK mapping · Severity charts · Evidence hash · Digital signature |

---

## Requirements

- **OS:** Kali Linux (recommended)
- **Python:** 3.10+
- **Go:** 1.21+
- **Rust/Cargo:** 1.70+
- **Chromium:** for screenshots
- **OpenSSL:** for SentinelProxy CA cert generation

---

## Installation

```bash
git clone https://github.com/Mrsultan7890/osints.git
cd osints
bash setup.sh
sentinel
```

### Build SentinelProxy Rust Core

```bash
# Proxy core
cd sentinel_proxy/rust_core
cargo build --release

# Parallel fuzzer
cd ../rust_fuzzer
cargo build --release

cd ../..
```

### Build Go Services

```bash
cd scraper        && go build -o scraper .        && cd ..
cd dirbuster      && go build -o dirbuster .      && cd ..
cd network_mapper && go build -o network_mapper . && cd ..
cd smuggler       && go build -o smuggler .       && cd ..
cd stealth_proxy  && go build -o stealth_proxy .  && cd ..
cd predictor      && go build -o predictor .      && cd ..
```

### Build Rust Services

```bash
cd analyzer       && cargo build --release && cd ..
cd fuzzer         && cargo build --release && cd ..
cd media_analyzer && cargo build --release && cd ..
```

---

## Quick Start

```bash
# Interactive mode
sentinel

# Direct CLI
sentinel --bugbounty example.com
sentinel --recon example.com
sentinel --breach user@example.com
sentinel --scan-all example.com

# SentinelProxy v2.0 (Rust Core)
cd sentinel_proxy
python3 main.py

# Or from main CLI
sentinel-pro> proxy start
```

---

## CLI Commands

### Autonomous Brain
```
sentinel-pro> brain investigate <target>     # Full autonomous scan
sentinel-pro> brain nmap -sV <target>        # Direct tool execution
sentinel-pro> brain full hack <target>       # Complete attack chain
```

### RL Agent
```
sentinel-pro> rl train <episodes>            # Train on your targets
sentinel-pro> rl run <target>                # Autonomous RL scan
sentinel-pro> rl status                      # Q-table stats
```

### Autonomous Agents
```
sentinel-pro> agent <task>                   # ReAct agent — SentinelNet decides
sentinel-pro> agent <task> --auto            # Fully autonomous (no confirmation)
sentinel-pro> auto <target>                  # Autonomous mode — model decides all
sentinel-pro> auto <target> --auto           # Fully autonomous
sentinel-pro> attackchain <target>           # Full chain: recon→analyze→exploit→fix→report
sentinel-pro> attack chain <target>          # Same as above
```

### 24/7 Monitor
```
sentinel-pro> monitor add <target>           # Add target to monitor
sentinel-pro> monitor remove <target>        # Remove target
sentinel-pro> monitor start                  # Start monitoring
sentinel-pro> monitor stop                   # Stop monitoring
sentinel-pro> monitor interval <seconds>     # Set scan interval
sentinel-pro> monitor status                 # Monitor status
sentinel-pro> monitor persistent install     # Install as system service (survives reboot)
sentinel-pro> monitor persistent status      # Check persistent service status
sentinel-pro> monitor persistent sync        # Sync current targets to service
sentinel-pro> monitor persistent restart     # Restart service
sentinel-pro> monitor persistent uninstall   # Remove service
```

### Bug Bounty
```
sentinel-pro> bugbounty <domain>
```
SSL/TLS · Headers · Ports · SQLi/XSS/SSRF · Blind SQLi · DOM XSS · SSTI · CORS · LFI/RFI · XXE · Clickjacking · OAuth · JWT · Nuclei · DirBuster · Rust Fuzzer · Cookie Analyzer · DNS Zone Transfer · Tech Fingerprint · Auth Bypass · API Scanner · Prototype Pollution · Subdomain Takeover · Shodan · CVE Lookup · HTTP Smuggling · Open Redirect · Screenshot

### Recon
```
sentinel-pro> recon <domain>
```
WHOIS · DNS · Subdomains · Go Scraper · Wayback · DNS History · Google Dorks · GitHub Dorks · ASN · Cloud Assets · Cert Transparency · Job OSINT · Relation Mapper

### Breach Check
```
sentinel-pro> breach <email or username>
```
HIBP · HudsonRock · LeakCheck · IntelX · Dehashed · Paste Monitor

### OSINT
```
sentinel-pro> email <email>                  # Full email OSINT
sentinel-pro> phone <number>                 # Phone OSINT
sentinel-pro> person <name/email/phone>      # Person OSINT + relation graph
sentinel-pro> image <path>                   # Image OSINT + EXIF + face detection
sentinel-pro> osint <target>                 # Auto-detect type and run
sentinel-pro> collect <target>               # Multi-source data collection
sentinel-pro> analyze                        # AI predictive threat analysis
sentinel-pro> nlp <text>                     # NLP deep analysis
sentinel-pro> nlp session                    # Analyze collected session data
sentinel-pro> fakecheck                      # Fake profile detection
sentinel-pro> semantic                       # Semantic content analysis
sentinel-pro> media                          # Media integrity validation
sentinel-pro> financial                      # Financial trail analysis
sentinel-pro> network                        # Influence network mapping
```

### Attack Chain
```
sentinel-pro> attackchain <target>
sentinel-pro> attackchain <target> --auto
sentinel-pro> attackchain <target> --mode full|recon_only|vuln_only
```

### Forensics & Metasploit
```
sentinel-pro> forensics case <name>          # Create forensics case
sentinel-pro> forensics memory <case> <dump> # Analyze memory dump
sentinel-pro> forensics status               # Show forensics tools status
sentinel-pro> metasploit search <target>     # Search for exploits
sentinel-pro> metasploit payload <type> <lhost> <lport>  # Generate payload
sentinel-pro> metasploit sessions            # List active sessions
sentinel-pro> metasploit status              # Show Metasploit status
sentinel-pro> privilege status               # Privilege manager status
sentinel-pro> privilege test                 # Test sudo access
sentinel-pro> privilege clear                # Clear password cache
sentinel-pro> evidence                       # Manage evidence vault
sentinel-pro> secure stats                   # Secure file system stats
sentinel-pro> secure verify <chain_id>       # Verify evidence integrity
sentinel-pro> secure backup <file>           # Create encrypted backup
sentinel-pro> secure cleanup                 # Clean temporary files
sentinel-pro> secure audit                   # File operation audit log
sentinel-pro> filesystem <path>              # Secure filesystem browser
```

### Dark Web
```
sentinel-pro> darkweb <target>               # Dark web investigation
sentinel-pro> tor on / off / status / newip  # Tor routing control
sentinel-pro> stealth                        # Configure stealth settings
```

### AI / ML
```
sentinel-pro> groq <prompt>                  # Direct Groq LLM query
sentinel-pro> semantic <text>                # Semantic text analysis
sentinel-pro> nlp <text>                     # NLP profile analysis
sentinel-pro> fakecheck                      # Fake profile detection
sentinel-pro> financial <target>             # Financial analysis
sentinel-pro> media <file>                   # Media validation
```

### ML Training
```
sentinel-pro> train status                   # Model status + drift detection
sentinel-pro> train collect                  # Collect from MalwareBazaar/CISA/ExploitDB/URLhaus/OTX
sentinel-pro> train github                   # Collect from GitHub GHSA + security repos
sentinel-pro> train run                      # Train all models
sentinel-pro> train save                     # Save trained models
sentinel-pro> train eval                     # Evaluate model accuracy
```

### Scan Depth
```
sentinel-pro> depth fast                     # ⚡ Fast scan (~30 sec)
sentinel-pro> depth normal                   # ⚖ Normal scan (~2-3 min) [default]
sentinel-pro> depth deep                     # 🔍 Deep scan (full wordlist)
sentinel-pro> depth                          # Show current depth + payload counts
```

### Bulk Operations
```
sentinel-pro> bulk <file> bugbounty          # Bulk bug bounty scan
sentinel-pro> bulk <file> recon              # Bulk recon
sentinel-pro> bulk <file> breach             # Bulk breach check
sentinel-pro> bulk <file> email              # Bulk email OSINT
sentinel-pro> bulk <file> phone              # Bulk phone OSINT
sentinel-pro> bulk <file> all                # Auto-detect type + full scan
```

### Reporting
```
sentinel-pro> report                         # Generate legal-grade report
sentinel-pro> pdf                            # Export last scan to PDF
sentinel-pro> telegram test                  # Send test Telegram alert
sentinel-pro> telegram status                # Show Telegram config
```

### Proxy
```
sentinel-pro> proxy start                    # Start SentinelProxy v2.0
sentinel-pro> proxy stop                     # Stop proxy
sentinel-pro> proxy restart                  # Kill stale + fresh start
sentinel-pro> proxy status                   # Check if running
```

### Profiles
```
sentinel-pro> profile list                   # List scanning profiles
sentinel-pro> profile <name>                 # Switch profile (stealth/fast/balanced/monitoring)
sentinel-pro> profile current                # Show current profile
```

### Sentinel Intel (Graph Intelligence Platform)
```
sentinel-pro> intel                          # Launch Sentinel Intel GUI
```

### License Management
```
sentinel-pro> activate <KEY>                 # Activate license key
```

### System
```
sentinel-pro> status                         # Detailed system status
sentinel-pro> clear                          # Clear screen
sentinel-pro> help / ?                       # Command reference
sentinel-pro> exit / quit / q               # Exit
```

---

## Sentinel Intel — Maltego-Style Graph Intelligence Platform

**Professional OSINT graph visualization with AI-powered transforms**

```bash
cd sentinel_intel
python3 main.py

# Or from main CLI
sentinel-pro> intel
```

### Architecture

```
┌─────────────────────────────────────────────┐
│         SENTINEL INTEL v2.0                 │
│    Maltego Killer — Graph Intelligence     │
│                                             │
│  PyQt6 GUI        — Modern dark theme       │
│  NetworkX         — Graph engine            │
│  13 Engines       — Intelligence sources    │
│  40+ Transforms   — OSINT operations        │
│  ML Integration   — SentinelNet + Groq      │
│  Auto-Chain       — AI suggests next steps  │
│  Risk Viz         — Color + glow by threat  │
└─────────────────────────────────────────────┘
```

### 13 Intelligence Engines

| Engine | Sources | Capabilities |
|--------|---------|-------------|
| **Email** | 15+ sources | Breach check · Domain validation · Social profiles · Disposable detection |
| **Phone** | 10+ sources | Carrier lookup · Country · Line type · Social hints · Reputation |
| **IP** | 12+ sources | Geolocation · ASN · Shodan · Threat intel · Open ports · Reverse DNS |
| **Domain** | 20+ sources | WHOIS · DNS · Subdomains · Tech stack · Cloud assets · Cert transparency |
| **Person** | 40+ platforms | Social profiles · Username variations · Relation graph · Digital footprint |
| **Username** | 50+ platforms | Sherlock-style enumeration · Cross-platform correlation · Variant detection |
| **Hash** | 6+ sources | VirusTotal · MalwareBazaar · ThreatFox · Hybrid Analysis · AlienVault OTX |
| **Cryptocurrency** | 5+ sources | Blockchain.info · Blockchair · Etherscan · Whale Alert · BitcoinAbuse |
| **CVE** | NVD + MITRE | Vulnerability lookup · CVSS scoring · Exploit availability |
| **Breach** | 7+ sources | HIBP · HudsonRock · LeakCheck · IntelX · Dehashed · Paste Monitor |
| **Company** | Multiple | Company intel · Employee enumeration · Tech stack · Job postings |
| **Malware** | 6+ sources | Hash analysis · Family detection · Behavior · IOCs |
| **URL** | Multiple | URL reputation · Phishing detection · Redirect chains |

### 40+ Transforms

**Email Transforms:**
- email_to_breaches — Check data breaches
- email_to_social_profiles — Find social media
- email_to_domain_info — Domain validation
- email_investigate — Full investigation

**Phone Transforms:**
- phone_to_carrier — Carrier lookup
- phone_to_location — Geolocation
- phone_to_social_hints — Social profiles
- phone_investigate — Full investigation

**IP Transforms:**
- ip_to_geolocation — Location data
- ip_to_asn — ASN information
- ip_to_shodan — Shodan intelligence
- ip_to_ports — Open ports scan
- ip_investigate — Full investigation

**Domain Transforms:**
- domain_to_whois — WHOIS lookup
- domain_to_subdomains — Subdomain enumeration
- domain_to_dns — DNS records
- domain_to_tech_stack — Technology detection
- domain_to_certificates — SSL/TLS certs
- domain_investigate — Full investigation

**Person Transforms:**
- person_to_emails — Email discovery
- person_to_phones — Phone discovery
- person_to_social_profiles — Social media
- person_to_usernames — Username variations
- person_investigate — Full investigation

**Username Transforms:**
- username_to_platforms — Platform enumeration
- username_to_variants — Username variations
- username_investigate — Full investigation

**Hash Transforms:**
- hash_to_malware_info — Malware analysis
- hash_to_threat_intel — Threat intelligence
- hash_investigate — Full investigation

**Cryptocurrency Transforms:**
- crypto_to_transactions — Transaction history
- crypto_to_balance — Wallet balance
- crypto_to_related_addresses — Related wallets
- crypto_investigate — Full investigation

### UI Features

**Main Window:**
- 3-panel layout: Entities | Canvas | Properties
- Search & filter bar
- Menu bar: File, Edit, View, ML, Tools, Help
- Toolbar: 10+ quick actions
- Status bar: Live stats
- 15+ keyboard shortcuts

**Graph Canvas:**
- 19 entity types with unique colors
- Risk-based visualization (color + glow)
- Emoji icons for each entity type
- Hover effects
- Drag-and-drop nodes
- Auto-layout (circular)
- Zoom in/out
- High-res PNG export (2x)

**Entity Palette:**
- 15+ entity types
- Quick Add with auto-detection
- Search box
- Smart type inference

**Transform Palette:**
- 8 tabs organized by entity type
- 40+ transforms
- Auto-Chain button with AI
- Progress tracking
- Search/filter

**Properties Panel:**
- Tabbed interface (Properties | History)
- Color-coded risk scores
- Transform history display
- ML cluster info
- Notes display

### ML Integration

**SentinelNet v5.0:**
- Real-time threat classification
- Risk scoring per entity
- Anomaly detection

**Groq LLM:**
- Auto-chain suggestions
- Deep analysis per transform
- Context-aware recommendations

**Advanced ML:**
- DBSCAN clustering — Group related entities
- Link prediction — Suggest connections
- Entity matching — Cross-platform correlation
- Identity scoring — Confidence levels
- Fake detection — Profile authenticity
- Writing fingerprinting — Authorship attribution

### Entity Types (19 total)

```
📧 Email          🌐 IP            👤 Person         🌍 Domain
📱 Phone          👥 Username       🔗 URL            🔐 Hash
🚨 CVE            🔌 Port           🏢 Company        📍 Location
💰 Cryptocurrency 🦠 Malware        💥 Breach         📜 Certificate
⚠️ Threat         ⚙️ Technology     💸 Transaction
```

### Keyboard Shortcuts

**File Operations:**
- `Ctrl+N` — New Graph
- `Ctrl+O` — Open Graph
- `Ctrl+S` — Save Graph
- `Ctrl+Shift+P` — Export PNG
- `Ctrl+Shift+J` — Export JSON
- `Ctrl+Q` — Exit

**Edit Operations:**
- `Ctrl+L` — Auto Layout
- `Ctrl+E` — Center View
- `Ctrl++` — Zoom In
- `Ctrl+-` — Zoom Out
- `Ctrl+Del` — Clear Graph
- `F5` — Reload Graph

**ML Operations:**
- `Ctrl+K` — Run Clustering
- `Ctrl+P` — Predict Links
- `Ctrl+R` — Risk Analysis

**Help:**
- `F1` — Documentation

### Database

```
sentinel_intel/data/sentinel_intel.db
├── nodes              — Graph nodes (entities)
├── edges              — Graph edges (relationships)
├── transform_history  — Transform execution log
├── ml_cache           — ML predictions cache
├── risk_scores        — Risk scoring data
└── clusters           — Entity clusters
```

### Maltego Comparison

| Feature | Maltego | Sentinel Intel v2.0 |
|---------|---------|---------------------|
| **Price** | $999/year | FREE ✅ |
| **AI/ML** | None | 10+ algorithms ✅ |
| **Transforms** | ~100 (paid) | 40+ (60% free) ✅ |
| **Auto-Chain** | Manual | AI-powered ✅ |
| **Risk Viz** | None | Color + Glow ✅ |
| **Icons** | Basic | Emoji ✅ |
| **Theme** | Light | Modern Dark ✅ |
| **Blockchain** | Limited | Full intel ✅ |
| **Malware** | Basic | Deep analysis ✅ |
| **Open Source** | No | Yes ✅ |

**Result: Sentinel Intel v2.0 > Maltego** 🏆

---

## License Manager

**Offline HMAC-SHA256 license system — no server required**

### Features

- **Offline verification** — No internet required after activation
- **Machine binding** — License tied to hardware ID
- **HMAC-SHA256** — Cryptographically secure
- **No server** — All verification happens locally
- **3 Plans** — Basic (1 month), Pro (3 months), Elite (1 year)

### Usage

```bash
# Activate license
sentinel-pro> activate SENT3-<encoded>-<signature>

# Check status
sentinel-pro> status
```

### Key Format

```
SENT3-<base64_payload>-<hmac_signature>

Payload (JSON):
{
  "p": "elite",              # plan: basic/pro/elite
  "e": "user@example.com",   # email
  "x": "2027-01-01",          # expiry (or "lifetime")
  "i": "2026-01-01"           # issued date
}
```

### Machine Binding

- Linux: `/etc/machine-id` (first 16 chars)
- Fallback: MAC address MD5 hash
- Stored in: `~/.sentinel_pro/license.key`
- Permissions: `0600` (owner read/write only)

### Plans

| Plan | Duration | Features |
|------|----------|----------|
| **Basic** | 1 Month | Full Access |
| **Pro** | 3 Months | Full Access |
| **Elite** | 1 Year | Full Access |

---

## Wordlist Manager

**Central wordlist resolution with auto-install instructions**

### Features

- **Priority system:**
  1. Bundled payloads (`sentinel_proxy/payloads/`)
  2. Kali Linux system wordlists (`/usr/share/seclists`, `/usr/share/wordlists`)
  3. Hardcoded fallback (always works)

- **Auto-install instructions** — Clear commands when wordlists missing
- **Depth control** — Fast/Normal/Deep scan modes
- **No crashes** — Tool never fails due to missing wordlists

### Wordlist Map

| Name | Purpose | Sources |
|------|---------|----------|
| `dirbust_fast` | Fast directory scan | common.txt (4,614 entries) |
| `dirbust_normal` | Normal directory scan | common.txt (4,614 entries) |
| `dirbust_deep` | Deep directory scan | big.txt + raft-large (220K+ entries) |
| `subdomains` | Subdomain brute-force | top1million-5000.txt |
| `params` | Parameter fuzzing | burp-parameter-names.txt |
| `passwords` | Password brute-force | rockyou.txt |
| `usernames` | Username enumeration | top-usernames-shortlist.txt |
| `sqli` | SQL injection | Generic-SQLi.txt |
| `xss` | XSS payloads | XSS-Jhaddix.txt |
| `lfi` | LFI payloads | LFI-Jhaddix.txt |

### Scan Depth Control

```bash
# Set scan depth
sentinel-pro> depth fast      # ⚡ ~30 sec, 4K entries
sentinel-pro> depth normal    # ⚖ ~2-3 min, 4K entries [default]
sentinel-pro> depth deep      # 🔍 Full scan, 220K+ entries

# Check current depth
sentinel-pro> depth
```

### Installation

```bash
# Install SecLists
sudo apt install seclists

# Install wordlists (includes rockyou)
sudo apt install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

### Status Check

```bash
sentinel-pro> status

# Shows wordlist availability:
# ✓ dirbust_fast    (seclists)
# ✓ subdomains      (seclists)
# ✗ passwords       (missing — sudo apt install wordlists)
```

---

## Report Builder

**Enhanced reporting with Groq AI and MITRE ATT&CK mapping**

### Features

- **Groq Executive Summary** — AI-generated professional summary
- **MITRE ATT&CK Mapping** — Automatic technique mapping
- **Severity Charts** — Matplotlib bar + pie charts
- **Evidence Hash** — SHA-256 integrity verification
- **Digital Signature** — Watermarked reports
- **Multi-format** — JSON, HTML, PDF, TXT

### MITRE ATT&CK Coverage

**19 Tools Mapped:**
- nmap → T1046 (Network Service Discovery)
- subfinder/amass → T1590 (Gather Victim Network Information)
- theHarvester → T1589 (Gather Victim Identity Information)
- gobuster/ffuf → T1083 (File and Directory Discovery)
- nikto/nuclei → T1190 (Exploit Public-Facing Application)
- sqlmap → T1190 (Exploit Public-Facing Application)
- hydra → T1110 (Brute Force)
- searchsploit → T1588.005 (Exploits)
- And more...

### Report Components

**JSON Report:**
```json
{
  "target": "example.com",
  "scan_type": "bugbounty",
  "risk_level": "HIGH",
  "total_findings": 15,
  "findings": [...],
  "executive_summary": "AI-generated summary",
  "mitre_attack": [...],
  "evidence_hash": "sha256...",
  "_sentinel": {
    "_generated_by": "Sentinel Pro v3.0",
    "_author": "@who_is_the_black_hat",
    "_copyright": "Copyright (c) 2026..."
  }
}
```

**HTML Report:**
- Modern dark theme
- Color-coded severity badges
- Interactive severity charts
- MITRE ATT&CK table with links
- Evidence integrity section
- Digital signature footer

**PDF Report:**
- Auto-generated from HTML via WeasyPrint
- Court-grade quality
- Embedded charts
- Chain of custody

### Severity Colors

```
CRITICAL : #e74c3c (Red)
HIGH     : #e67e22 (Orange)
MEDIUM   : #f39c12 (Yellow)
LOW      : #27ae60 (Green)
```

### Digital Signature

**All reports include:**
- Tool name and version
- Author attribution
- GitHub link
- Copyright notice
- Timestamp
- Warning about unauthorized redistribution

**Footer (HTML):**
```html
Generated by Sentinel Pro v3.0 · @who_is_the_black_hat
Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
This report was generated by licensed software.
Unauthorized copying or redistribution is prohibited.
```

---

## SentinelNet v5.0 — Custom Neural Network

**Completely custom — built from scratch. No GPT, no OpenAI, no external models.**

```
Architecture: Embedding → CNN (k=3,5,7) → LayerNorm → Multi-Head Classifier
Outputs:
  ├── threat_label   : LOW / MEDIUM / HIGH / CRITICAL
  ├── threat_type    : recon / web_vuln / breach / malware / phishing /
  │                    apt / insider / misconfig / social_eng / unknown
  ├── action_hint    : monitor / patch_now / block_ip / escalate /
  │                    investigate / notify_team / collect_evidence / no_action
  └── confidence     : 0.0 - 1.0

Training:
  ├── 50,000+ samples
  ├── NVD CVE database
  ├── GitHub security advisories (GHSA)
  ├── MITRE ATT&CK
  ├── MalwareBazaar + CISA KEV + ExploitDB + URLhaus + AlienVault OTX
  ├── Real scan feedback (continuous learning — every 50 new samples)
  └── 3-round curriculum learning (basic → medium → high)

Performance:
  ├── F1 Score     : 0.8335
  ├── Accuracy     : 83.3%
  ├── Model size   : 8.56 MB
  └── Saved at     : models/ml_engine/sentinel_threat_net.pt
```

---

## Seq2Seq v2.0 — Command Generation Model

```
Architecture: CNN Encoder (k=3,5,7) → Transformer Decoder (4 heads, 3 layers)
Tasks:
  ├── cmd_gen    : natural language → exact Kali command
  ├── chain_gen  : target description → tool chain sequence
  └── report_gen : finding description → report text

Specs:
  ├── Vocab size   : 8,000 BPE tokens
  ├── Embed dim    : 256
  ├── FF dim       : 512
  ├── Model size   : 29.24 MB
  └── Saved at     : models/ml_engine/sentinel_seq2seq.pt
```

---

## SentinelLM — Custom Language Model

```
Custom security-domain language model for text generation.
  ├── Model size   : models/ml_engine/sentinellm_v1.pt
  ├── Vocab        : models/ml_engine/sentinellm_vocab.json
  └── Domain       : security text, vulnerability descriptions, OSINT reports
```

---

## Groq LLM Integration

```
Primary model  : llama-3.3-70b-versatile
Fallback model : llama-3.1-8b-instant

Used for:
  ├── Brain reasoning — primary ReAct loop decisions
  ├── SentinelProxy Scanner — deep vulnerability analysis
  ├── Auto-Fuzz — parameter detection from HTML/JS
  ├── Auto Report — executive summary generation
  ├── CSRF PoC — exploitability analysis
  ├── Race Condition — race condition analysis
  ├── Param Miner — interesting parameter analysis
  ├── Collaborator — OOB hit analysis
  └── Fallback chain: Groq → Seq2Seq → SentinelNet → heuristic
```

---

## RL Agent — Q-Learning

```
State  : [tools_used, findings, ports, subdomains, risk_level]
Actions: nmap, nikto, nuclei, gobuster, ffuf, sqlmap, amass,
         whatweb, wafw00f, sslscan, theHarvester, searchsploit, breach

Reward:
  +20  Critical finding    +5  Medium finding    -1  Nothing found
  +10  High finding        +3  New subdomain      -2  Tool error
                           +2  New port

Current Stats:
  States learned : 171
  Epsilon        : 0.30
  Training data  : 523 real episodes from DB
  Saved at       : models/ml_engine/rl_qtable.json
```

---

## Advanced ML Engine

| Algorithm | Purpose |
|-----------|---------|
| **GNN** | Entity relationship graph — domain→IP→subdomain→email |
| **Isolation Forest** | Anomaly detection — unusual ports, weird responses |
| **DBSCAN** | Username/IP clustering — same person across platforms |
| **LightGBM** | Log analysis — attack pattern detection |
| **Genetic Algorithm** | Tool sequence optimization — best scan order |
| **TF-IDF + LogReg** | Threat classifier — 9 security sources |
| **TF-IDF + RandomForest** | Fake profile detector — 112,474 samples |
| **EntityMatcher** | TF-IDF char n-gram + cosine similarity cross-platform matching |
| **UsernameClusterer** | DBSCAN 52-dim feature vectors, leet-speak normalization |
| **IdentityScorer** | Bayesian log-odds aggregation with OSINT-grade evidence weights |
| **NLPProfileAnalyzer** | NLTK NER, profession/interest/personality detection, writing style |
| **TimelineAnalyzer** | KMeans activity clustering, timezone estimation, sleep window detection |
| **WritingFingerprinter** | Authorship attribution via char n-grams + stylometrics |

---

## Model Artifacts

```
models/ml_engine/
├── sentinel_threat_net.pt          ← SentinelNet v5.0 weights     (8.56 MB)
├── sentinel_vocab.json             ← SentinelNet tokenizer vocab   (0.25 MB)
├── sentinel_seq2seq.pt             ← Seq2Seq v2.0 weights          (29.24 MB)
├── sentinel_seq2seq_vocab.json     ← Seq2Seq tokenizer vocab
├── sentinellm_v1.pt                ← SentinelLM weights
├── sentinellm_vocab.json           ← SentinelLM vocab
├── sentinel_proxy_net.pt           ← SentinelProxy-specific model
├── sentinel_proxy_vocab.json       ← Proxy model vocab
├── rl_qtable.json                  ← Q-Learning Q-table            (0.02 MB)
├── threat_classifier.joblib        ← TF-IDF + LogReg classifier    (0.01 MB)
├── fake_detector.joblib            ← Random Forest fake detector   (13.10 MB)
├── ga_fitness.json                 ← Genetic algorithm fitness
└── training_data/                  ← JSONL training datasets
```

---

## 18 Autonomous Agents

```
sentinel_brain/agents/
├── recon_agent.py          ← Reconnaissance orchestration
├── exploit_agent.py        ← Bug bounty / exploitation
├── osint_agent.py          ← OSINT investigation
├── breach_agent.py         ← Credential leak checking
├── report_agent.py         ← Report generation + Telegram alerts
├── darkweb_agent.py        ← Dark web crawling + Tor
├── network_agent.py        ← Network topology mapping
├── terminal_agent.py       ← PTY terminal execution
├── scheduler_agent.py      ← Task scheduling
├── credential_agent.py     ← Credential management
├── system_monitor_agent.py ← System resource monitoring
├── correlation_agent.py    ← Cross-source data correlation
├── filesystem_agent.py     ← Secure file operations
├── monitor_agent.py        ← 24/7 target monitoring
├── notification_agent.py   ← Telegram + alert management
├── browser_agent.py        ← Headless browser automation
├── attack_chain_agent.py   ← Full attack chain orchestration
└── threat_intel_agent.py   ← Threat intelligence aggregation
```

---

## SentinelProxy v2.0 — Rust-Powered Burp Suite Alternative

```
cd sentinel_proxy && python3 main.py
        ↓
┌─────────────────────────────────────────────────────┐
│              SENTINEL PROXY v2.0                    │
│      Rust Core + Python AI — Burp Suite Killer      │
│                                                     │
│  tokio + hyper    — async Rust proxy engine         │
│  rustls           — TLS 1.2/1.3 MITM               │
│  HTTP/2           — ALPN negotiation                │
│  WebSocket        — full WS intercept (wired)       │
│  rayon            — parallel fuzzer (50x faster)    │
│  SentinelNet v5.0 — real-time threat scoring        │
│  ProxyMLEngine    — 10 ML algorithms per request    │
│  Groq LLM         — deep vulnerability analysis     │
│  34,311 payloads  — from PayloadsAllTheThings        │
└─────────────────────────────────────────────────────┘
```

Configure browser proxy: `127.0.0.1:8082`

### Why Rust Core?

| Feature | Old (mitmproxy) | New (Rust) |
|---------|----------------|------------|
| Speed | ~500 req/sec | ~200,000 req/sec |
| HTTP/2 | ✗ | ✓ ALPN |
| WebSocket | partial | ✓ full intercept |
| Memory | ~200MB | ~8MB |
| Startup | 3-5s | instant |
| Python 3.13 | ✗ broken | ✓ works |
| Wildcard certs | ✗ | ✓ *.domain.com |
| Scope-based intercept | ✗ | ✓ Rust level |

### Rust Core Architecture

```
Browser
  ↓ HTTP/HTTPS/HTTP2/WebSocket
┌─────────────────────────────────────────┐
│         Rust Core (sentinel_proxy_core) │
│                                         │
│  tokio TCP listener                     │
│  → HTTP CONNECT → TLS MITM (rustls)     │
│  → ALPN → HTTP/2 or HTTP/1.1           │
│  → WebSocket detect → full intercept    │
│  → Match & Replace (regex, Rust level)  │
│  → Scope-based intercept filter         │
│  → Intercept hold/forward/drop          │
│    (tokio oneshot channel)              │
│  → Wildcard cert generation (openssl)   │
│                                         │
│  Unix socket IPC:                       │
│    .sock        ← Python→Rust commands  │
│    .sock.events ← Rust→Python events    │
└──────────────┬──────────────────────────┘
               │ JSON events (newline-delimited)
┌──────────────▼──────────────────────────┐
│         Python Layer                    │
│                                         │
│  rust_bridge.py     — IPC receiver      │
│  rust_fuzzer_bridge.py — Fuzzer bridge  │
│  analyzer.py        — Pattern+SentinelNet+Groq
│  proxy_ml_engine.py — 10 ML algorithms  │
│  proxy_db.py        — SQLite storage    │
│  app.py             — Tkinter UI (22 tabs)
└─────────────────────────────────────────┘
```

### Tabs (22 total)

| Tab | Purpose |
|-----|---------|
| **Proxy** | Live HTTP/HTTPS/HTTP2 interception · color-coded risk · intercept FWD/DROP |
| **Repeater** | Modify and resend requests · response time · Raw/Hex/Render |
| **Intruder** | 4 attack modes · Rust parallel fuzzer · 34K+ payloads · grep match |
| **Scanner** | 9 pattern detectors + SentinelNet + Groq deep analysis |
| **Decoder** | URL / Base64 / Hex / HTML / MD5 / SHA1 / SHA256 / SHA512 |
| **Logger** | Full traffic log · search · risk/method filter · flagged only |
| **Highlight** | Custom color rules · 7 colors · field-based matching |
| **Auto-Fuzz** | AI param detection · HTML forms + JS vars + Groq · smart payload selection |
| **Comparer** | Side-by-side diff · added/removed/unchanged · stats |
| **Scope** | Include/exclude domains · wildcard support · match counter |
| **Report** | HTML/PDF report · Groq executive summary · risk breakdown |
| **Match & Replace** | Regex rules · request/response modify at Rust level |
| **Active Scanner** | CVE matching · auto-test all params · remediation guidance |
| **Session Analyzer** | JWT · OAuth · SAML · Cookie deep analysis |
| **WebSocket** | WS message viewer · replay · filter · export |
| **Target** | Site map tree · host/path hierarchy · request detail |
| **Organizer** | Save + annotate interesting requests · tags · notes |
| **Collaborator** | OOB blind detection · local HTTP listener · AI hit analysis |
| **AI Payloads** | Groq context-aware payload generation · WAF bypass variants |
| **CSRF PoC** | Auto HTML PoC generator · AI exploitability analysis |
| **Param Miner** | Hidden parameter discovery · AI suggestions · response diff |
| **Race Condition** | Turbo Intruder style · gate technique · timeline visualization |

### ProxyML Engine — 10 Algorithms (wired to every request)

```
1. SentinelNet v5.0    — HTTP request threat classification
2. IsolationForest     — HTTP anomaly detection
3. DBSCAN              — Session-based attack clustering
4. LightGBM            — HTTP log pattern analysis
5. TF-IDF Payload FP   — Payload fingerprinting (34K payloads)
6. LSTM Chain          — Request sequence pattern detection
7. Random Forest WAF   — WAF bypass probability
8. Autoencoder         — Response anomaly detection
9. Markov Chain        — Attack path prediction
10. Online SGD         — User-flagged request learning
```

### Parallel Fuzzer (Rust)

```
Engine  : sentinel_fuzzer (Rust + rayon)
Speed   : 50x faster than Python
Threads : configurable (default 20)
Modes   : Sniper · Battering Ram · Pitchfork · Cluster Bomb

Payload Types (21):
  SQLi · XSS · LFI · SSRF · SSTI · RCE · XXE
  Open Redirect · LDAP · NoSQL · GraphQL · JWT
  CORS · CRLF · Path Traversal · File Upload
  Prototype Pollution · Request Smuggling
  Cache Deception · XPATH · Custom

Payload Counts:
  SQLi          : 1,138    XSS           : 2,296
  LFI           : 4,778    Path Traversal: 22,662
  RCE           :   587    XXE           :   293
  Total         : 34,311 payloads
```

### Intercept (FWD/DROP)

```
1. Click INTERCEPT: ON in toolbar
2. Browse any site — requests pause
3. View/edit request in Request panel
4. Click ▶ FWD to forward or ✕ DROP to drop
5. Rust holds flow via tokio oneshot channel
   — zero CPU while waiting
6. Scope filter: only intercept specific hosts
   (set via IPC command set_intercept_scope)
```

### Certificate Setup

```bash
# Auto-generated on first proxy start (openssl)
~/.mitmproxy/sentinel-ca-cert.pem

# Wildcard support: *.example.com certs auto-generated
# SAN includes both *.domain.com and domain.com

# Firefox:
# Settings → Privacy → View Certificates
# → Authorities → Import → sentinel-ca-cert.pem
# → "Trust this CA to identify websites" ✓

# Chromium:
chromium --proxy-server=http://127.0.0.1:8082 \
         --ignore-certificate-errors \
         --user-data-dir=/tmp/sentinel-proxy
```

### SentinelProxy Database

```
data/sentinel_proxy.db
├── requests             — all intercepted traffic + AI analysis
├── saved_requests       — manually saved requests (Repeater)
├── repeater_history     — Repeater send history
├── intruder_results     — fuzzing results (Intruder + Auto-Fuzz)
├── scope_rules          — include/exclude domain rules
├── highlight_rules      — color rules
├── match_replace_rules  — M&R rules
├── organizer            — saved interesting requests with notes/tags
└── collaborator_hits    — OOB callback hits
```

---

## Go Services

| Directory | Binary | Purpose |
|-----------|--------|---------|
| `scraper/` | `scraper` | HTTP scraping with Go concurrency — emails, subdomains, tech hints |
| `dirbuster/` | `dirbuster` | Directory/path brute-forcing |
| `network_mapper/` | `network_mapper` | Network topology + influence mapping |
| `predictor/` | `predictor` | Prediction service |
| `smuggler/` | `smuggler` | HTTP request smuggling (CL.TE / TE.CL) |
| `stealth_proxy/` | `stealth_proxy` | Stealth proxy routing |

## Rust Services

| Directory | Binary | Purpose |
|-----------|--------|---------|
| `analyzer/` | `analyzer` | Parallel content analysis — entity extraction, correlations |
| `fuzzer/` | `fuzzer` | Parallel parameter fuzzing |
| `media_analyzer/` | `media_analyzer` | Media file analysis |
| `sentinel_proxy/rust_core/` | `sentinel_proxy_core` | Full proxy engine |
| `sentinel_proxy/rust_fuzzer/` | `sentinel_fuzzer` | Parallel HTTP fuzzer |

---

## Unified Database

```
data/sentinel.db
├── scans        — every scan record
├── findings     — all vulnerabilities
├── iocs         — IPs, domains, emails, hashes
├── decisions    — brain decisions + RL episodes
├── memory       — long-term target memory
├── rl_episodes  — RL training history
└── tool_stats   — tool effectiveness (feeds Genetic optimizer)

data/sentinel_memory.db
└── long-term memory across sessions

data/sentinel_proxy.db
└── SentinelProxy traffic + rules + results
```

---

## 24/7 Autonomous Monitoring

```bash
sentinel-pro> monitor add target.com
sentinel-pro> monitor interval 3600    # every hour
sentinel-pro> monitor persistent install  # survives reboot
```

New finding → automatic Telegram alert:
```
🔔 MONITOR ALERT
Target : target.com
Time   : 2026-04-25 08:00
New    : 3 finding(s)

🔴 SQL Injection — login form parameter
🟠 XSS Reflected — search parameter
🟡 Missing Headers — CSP not set

Sentinel Pro — @who_is_the_black_hat
```

Persistent service runs as systemd unit — survives laptop restart, auto-starts on boot.

---

## Continuous Learning Pipeline

```
Real scan result (bugbounty/recon/breach/person/nlp)
    ↓
scan_result_to_training_data()   ← PII stripped automatically
    ↓
scan_feedback.jsonl              ← JSONL training pool
    ↓
Every 50 new samples → auto_retrain_background()
    ↓
ModelTrainer.train_all()         ← daemon thread, non-blocking
    ↓
Updated models saved             ← used in next scan
    ↓
Performance logged               ← drift detection
```

Drift detection alerts when F1 drops significantly — prompts retraining.

---

## Decision Engine

After every scan, the Decision Engine analyzes results and suggests next actions:

```
bugbounty result → CORS found → suggest: recon deeper
breach result   → stealer logs → suggest: person OSINT
person result   → 3+ platforms → suggest: breach check emails
recon result    → subdomain takeover → auto: Telegram alert
metasploit      → successful exploit → suggest: forensics
forensics       → YARA match → suggest: breach investigation
```

Auto actions execute immediately. Pending actions shown as suggestions in CLI.

---

## API Keys (Optional)

```bash
cp .env.example .env
nano .env
```

| Key | Service |
|-----|---------|
| `GROQ_API_KEY` | Groq LLM — llama-3.3-70b (primary brain) |
| `SHODAN_API_KEY` | Shodan host intelligence |
| `GITHUB_TOKEN` | GitHub dorking |
| `SERPAPI_KEY` | Google dorking |
| `NVD_API_KEY` | CVE lookup |
| `HIBP_API_KEY` | HaveIBeenPwned |
| `DEHASHED_EMAIL` + `DEHASHED_API_KEY` | Dehashed passwords |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Instant alerts |
| `NUMVERIFY_API_KEY` | Phone OSINT |
| `ABSTRACTAPI_PHONE_KEY` | Phone carrier lookup |
| `SECURITYTRAILS_API_KEY` | DNS history |
| `TOR_PASSWORD` | Tor control port auth |

---

## Technology Stack

| Language | Version | Role |
|----------|---------|------|
| Python | 3.10+ | Primary — orchestration, ML, OSINT, reporting |
| Go | 1.21+ | Network services — scraping, fuzzing, proxying |
| Rust | 1.70+ | CPU-intensive parallel tasks — proxy, fuzzing, analysis |

### Key Python Dependencies

```
torch>=2.0.0          — SentinelNet + Seq2Seq + SentinelLM
scikit-learn>=1.3.0   — ML classifiers + clustering
lightgbm              — Log analysis
networkx>=3.1.0       — GNN entity graphs
nltk>=3.8.0           — NLP analysis
spacy>=3.7.0          — Named entity recognition
rich>=13.0.0          — Terminal UI
requests[socks]       — HTTP with Tor support
groq                  — Groq LLM API
weasyprint>=60.0      — PDF generation
```

### Key Rust Dependencies (proxy core)

```
tokio          — async runtime
hyper          — HTTP/1.1 + HTTP/2
rustls         — TLS 1.2/1.3 MITM
tokio-rustls   — async TLS
dashmap        — concurrent hashmap (cert cache, intercept)
rayon          — parallel fuzzer
regex          — match & replace engine
serde_json     — IPC JSON events
```

---

## Project Structure

```
osints/
├── main.py                    ← CLI orchestrator — entry point
├── config.py                  ← Centralized config + API keys
├── sentinel                   ← Shell launcher script
├── setup.sh                   ← Installation script
├── requirements.txt           ← Python dependencies
├── .env / .env.example        ← API key configuration
│
├── sentinel_brain/            ← Autonomous AI core
│   ├── brain.py               ← ReAct loop orchestrator v2.0
│   ├── kali_controller.py     ← PTY terminal control (19 tools)
│   ├── rl_agent.py            ← Q-Learning RL agent
│   ├── advanced_ml.py         ← GNN + IsoForest + DBSCAN + LightGBM + Genetic
│   ├── memory.py              ← Long-term SQLite memory
│   ├── monitor.py             ← 24/7 background monitoring
│   ├── monitor_daemon.py      ← Daemon process
│   ├── persistent_monitor.py  ← systemd service manager
│   ├── terminal.py            ← Terminal utilities
│   └── agents/                ← 18 autonomous agents
│
├── modules/
│   ├── bugbounty/             ← 29 vulnerability scanners
│   │   ├── ssl_checker.py     ├── headers_checker.py
│   │   ├── port_scanner.py    ├── endpoint_scanner.py
│   │   ├── vuln_scanner.py    ├── js_analyzer.py
│   │   ├── shodan_scanner.py  ├── cve_lookup.py
│   │   ├── subdomain_takeover.py ├── cors_scanner.py
│   │   ├── open_redirect.py   ├── nuclei_bridge.py
│   │   ├── smuggler_bridge.py ├── dirbuster_bridge.py
│   │   ├── cookie_analyzer.py ├── dns_zone_transfer.py
│   │   ├── fuzzer_bridge.py   ├── tech_fingerprint.py
│   │   ├── auth_bypass.py     ├── api_scanner.py
│   │   ├── lfi_scanner.py     ├── xxe_scanner.py
│   │   ├── ssti_scanner.py    ├── clickjacking.py
│   │   ├── prototype_pollution.py ├── oauth_scanner.py
│   │   ├── rust_analyzer_bridge.py ├── screenshot.py
│   │   └── payload_loader.py
│   │
│   ├── recon/                 ← 20 recon modules
│   │   ├── whois_lookup.py    ├── subdomain_enum.py
│   │   ├── go_scraper_bridge.py ├── wayback.py
│   │   ├── dns_history.py     ├── google_dorker.py
│   │   ├── github_dorker.py   ├── asn_mapper.py
│   │   ├── cloud_assets.py    ├── cert_transparency.py
│   │   ├── job_osint.py       ├── email_osint.py
│   │   ├── phone_osint.py     ├── person_osint.py
│   │   ├── image_osint.py     ├── relation_mapper.py
│   │   └── report.py (+ email/phone/person reports)
│   │
│   ├── breach/                ← 7-source breach checker
│   │   ├── breach_checker.py
│   │   └── report.py
│   │
│   ├── ml_engine/             ← ML pipeline
│   │   ├── sentinel_net.py        ← SentinelNet v5.0
│   │   ├── trainer.py             ← Training + continuous learning
│   │   ├── decision_engine.py     ← Autonomous decision making
│   │   ├── autonomous_loop.py     ← 24h background retrain loop
│   │   ├── groq_llm.py            ← Groq LLM singleton
│   │   ├── nlp_analyzer.py        ← NLP text profiling
│   │   ├── entity_matcher.py      ← TF-IDF similarity matching
│   │   ├── identity_scorer.py     ← Bayesian identity scoring
│   │   ├── username_clusterer.py  ← DBSCAN clustering
│   │   ├── writing_fingerprinter.py ← Authorship attribution
│   │   ├── timeline_analyzer.py   ← Activity pattern analysis
│   │   ├── sentinel_lm.py         ← SentinelLM
│   │   ├── real_data_collector.py ← MalwareBazaar/CISA/OTX collector
│   │   └── bulk_collector.py / bulk_processor.py
│   │
│   ├── database.py            ← Unified SQLite interface
│   ├── notifications.py       ← Telegram alert system
│   ├── utils.py               ← Rate limiter, Tor session
│   ├── cli_interface.py       ← Interactive CLI shell
│   ├── agent_core.py          ← Base agent functionality
│   ├── evidence_manager.py    ← Legal evidence chain of custody
│   ├── pdf_export.py          ← PDF report generation
│   ├── reporting_engine.py    ← Unified report engine
│   ├── darkweb_crawler.py     ← Tor/.onion crawling
│   ├── stealth_manager.py     ← Stealth/evasion management
│   ├── fake_profile_detector.py ← ML fake profile detection
│   ├── anomaly_analyzer.py    ← Anomaly detection
│   ├── digital_footprint.py   ← Digital footprint mapping
│   ├── financial_analyzer.py  ← Financial data analysis
│   ├── media_validator.py     ← Media file validation
│   ├── semantic_analyzer.py   ← Semantic text analysis
│   ├── attack_chain.py        ← Attack chain orchestration
│   ├── autonomous.py          ← Autonomous scan orchestration
│   ├── forensics_integration.py ← Metasploit + YARA + memory
│   ├── metasploit_integration.py ← Metasploit MSF integration
│   ├── privilege_manager.py   ← Sudo/privilege management
│   ├── secure_file_manager.py ← Encrypted file operations
│   ├── bugbounty_scanner.py   ← Legacy scanner wrapper
│   └── tool_registry.py       ← Tool registration
│
├── sentinel_proxy/            ← SentinelProxy v2.0
│   ├── main.py                ← Entry point
│   ├── rust_core/             ← Rust proxy engine
│   │   └── src/
│   │       ├── main.rs        ← tokio entry point
│   │       ├── proxy.rs       ← HTTP/HTTPS/HTTP2/WS handler
│   │       ├── tls.rs         ← rustls MITM + ALPN
│   │       ├── cert_store.rs  ← openssl dynamic cert + wildcard
│   │       ├── intercept.rs   ← FWD/DROP + scope filter
│   │       ├── ipc.rs         ← bidirectional Unix socket IPC
│   │       ├── match_replace.rs ← regex M&R engine
│   │       ├── websocket.rs   ← WebSocket intercept (wired)
│   │       └── types.rs       ← shared JSON structs
│   ├── rust_fuzzer/           ← Rust parallel fuzzer (rayon)
│   ├── core/
│   │   ├── rust_bridge.py     ← IPC receiver (Rust→Python)
│   │   └── rust_fuzzer_bridge.py ← Fuzzer bridge
│   ├── ai/
│   │   ├── analyzer.py        ← Pattern + SentinelNet + Groq
│   │   └── proxy_ml_engine.py ← 10 ML algorithms (wired)
│   ├── db/
│   │   └── proxy_db.py        ← SQLite (all tables in _init_db)
│   ├── ui/
│   │   ├── app.py             ← Tkinter UI — 22 tabs
│   │   └── tabs/
│   │       ├── websocket_tab.py
│   │       ├── target_tab.py
│   │       ├── organizer_tab.py
│   │       ├── collaborator_tab.py
│   │       ├── ai_payload_tab.py
│   │       ├── csrf_tab.py
│   │       ├── param_miner_tab.py
│   │       └── race_condition_tab.py
│   └── payloads/              ← 34,311 payloads, 31 categories
│
├── scraper/                   ← Go HTTP scraper
├── analyzer/                  ← Rust parallel analyzer
├── fuzzer/                    ← Rust parallel fuzzer
├── media_analyzer/            ← Rust media analysis
├── dirbuster/                 ← Go directory bruster
├── network_mapper/            ← Go network mapper
├── predictor/                 ← Go predictor service
├── smuggler/                  ← Go HTTP smuggler
├── stealth_proxy/             ← Go stealth proxy
│
├── models/ml_engine/          ← Trained model artifacts
├── data/                      ← SQLite databases
├── reports/                   ← Generated scan reports
├── investigations/            ← Per-target investigation data
├── screenshots/               ← Web screenshots
├── evidence/                  ← Legal evidence vault
├── logs/                      ← Application logs
└── targets/                   ← Target lists for bulk scans
```

---

## Roadmap

### Completed ✅
- [x] SentinelNet v5.0 — CNN+Transformer classifier (F1=0.83)
- [x] Seq2Seq v2.0 — CNN Encoder + Transformer Decoder
- [x] SentinelLM — Custom security language model
- [x] Groq integration — llama-3.3-70b as primary brain
- [x] 3-round curriculum training — 119K+ samples
- [x] SentinelProxy v2.0 — Rust core (tokio+hyper+rustls)
- [x] HTTP/2 support — ALPN negotiation
- [x] WebSocket intercept — full bidirectional (wired to proxy.rs)
- [x] Intercept FWD/DROP — tokio oneshot channels
- [x] Match & Replace — Rust regex engine
- [x] Parallel Fuzzer — Rust rayon (50x faster)
- [x] 22 tabs — WebSocket · Target · Organizer · Session · Active Scanner · Collaborator · AI Payloads · CSRF PoC · Param Miner · Race Condition
- [x] ProxyMLEngine — 10 algorithms wired to every request
- [x] Wildcard cert support — *.domain.com
- [x] Scope-based intercept filter — Rust level
- [x] Rust fuzzer response body — saved per result
- [x] pending_count fix — accurate intercept counter
- [x] collaborator_hits table — proper _init_db placement
- [x] 18 autonomous agents
- [x] Persistent monitoring — systemd service, survives reboot
- [x] Decision Engine — post-scan action suggestions
- [x] Continuous learning — auto-retrain every 50 samples
- [x] Drift detection — F1 drop alerts
- [x] Real data collector — MalwareBazaar/CISA/ExploitDB/URLhaus/OTX

### Planned 🔜
- [ ] SentinelNet v6.0 — larger vocab, more threat types
- [ ] Seq2Seq v3.0 — fine-tuning on real pentest data
- [ ] Full autonomous loop — Brain controls SentinelProxy
- [ ] SentinelProxy v2.1 — Blind SQLi/XSS out-of-band detection
- [ ] Plugin system — custom Python plugins per tab
- [ ] AI/LLM Security Module — prompt injection, jailbreak testing, model extraction (v4.0)
- [ ] Differential Analysis Engine — automated baseline + mutation testing
- [ ] Response Intelligence Model — error fingerprinting, data leakage detection
- [ ] Payload Effectiveness Scorer — tech stack aware ranking

---

## Legal Notice

This tool is intended for **authorized security testing and OSINT research only**.
Always obtain proper written authorization before scanning any target.
The authors are not responsible for misuse.

Legal compliance standards implemented:
- ISO 27037 — Digital evidence guidelines
- NIST SP 800-86 — Forensics guide
- RFC 3227 — Evidence collection and archiving

---

## Author

Made by [@who_is_the_black_hat](https://www.instagram.com/who_is_the_black_hat) · [GitHub](https://github.com/Mrsultan7890/osints)

---

## Kali Linux Tools — Integrated (19 tools)

KaliController v2.0 in tools ko real PTY terminal se directly control karta hai:

| Tool | Purpose |
|------|---------|
| `nmap` | Port scan, service detection, OS fingerprint |
| `masscan` | Fast port scanner |
| `subfinder` | Subdomain enumeration |
| `amass` | Attack surface mapping |
| `theHarvester` | Email, domain, IP harvesting |
| `nikto` | Web server scanner |
| `nuclei` | Template-based vulnerability scanner |
| `sqlmap` | SQL injection |
| `gobuster` | Directory/DNS/vhost brute-forcer |
| `ffuf` | Web fuzzer |
| `hydra` | Network login brute-forcer |
| `searchsploit` | ExploitDB search |
| `commix` | Command injection exploiter |
| `wpscan` | WordPress scanner |
| `sslscan` | SSL/TLS scanner |
| `wafw00f` | WAF detection |
| `whatweb` | Tech fingerprinting |
| `msfconsole` | Metasploit Framework |
| `msfvenom` | Payload generator |

Auto output parsing — nmap → ports, sqlmap → vulns, nuclei → findings, nikto → issues.
Tool chaining — nmap results automatically feed into sqlmap/nikto/gobuster.

---

## SentinelProxy Startup Flow

```
python3 sentinel_proxy/main.py
  ↓
1. Kill stale process on port 8082
2. Start Rust binary (sentinel_proxy_core)
   → Wait up to 5s for port ready
3. Start IPC bridge (RustCoreBridge)
   → Connect to Unix sockets
4. Launch Tkinter UI (SentinelProxyApp)
   → Wire bridge callbacks
   → Show onboarding splash
   → Build 22 tabs
5. Proxy ready — set browser to 127.0.0.1:8082
```

Or from main CLI:
```bash
sentinel-pro> proxy start    # launches sentinel_proxy/main.py
sentinel-pro> proxy stop     # kills port 8082
sentinel-pro> proxy restart  # kill + fresh start
sentinel-pro> proxy status   # check if running
```

---

## Environment Configuration

All settings via `.env` file:

```bash
cp .env.example .env
nano .env
```

```env
# API Keys
GROQ_API_KEY=your_groq_key
SHODAN_API_KEY=your_shodan_key
GITHUB_TOKEN=your_github_token
SERPAPI_KEY=your_serpapi_key
NVD_API_KEY=your_nvd_key
HIBP_API_KEY=your_hibp_key
DEHASHED_EMAIL=your@email.com
DEHASHED_API_KEY=your_dehashed_key
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
NUMVERIFY_API_KEY=your_numverify_key
ABSTRACTAPI_PHONE_KEY=your_abstractapi_key
SECURITYTRAILS_API_KEY=your_securitytrails_key
TOR_PASSWORD=your_tor_password

# Rate Limiting
OSINT_RATE_LIMIT=10
OSINT_RATE_PERIOD=60

# Timeouts
OSINT_TIMEOUT=10
OSINT_LONG_TIMEOUT=30

# Stealth
OSINT_MIN_DELAY=2.0
OSINT_MAX_DELAY=5.0

# Tor
TOR_PROXY=socks5h://127.0.0.1:9050
TOR_CONTROL_PORT=9051

# ML Engine
ML_CONFIDENCE_THRESHOLD=0.50
ML_CLUSTER_EPS=0.35

# Logging
OSINT_LOG_LEVEL=INFO
```
