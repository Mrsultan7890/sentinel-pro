# The Sentinel Pro v3.0

```
 _____ _____ _   _ _____ _____ _   _  _____ _
/  ___|  ___| \ | |_   _|_   _| \ | ||  ___| |
\ `--.| |__ |  \| | | |   | | |  \| || |__ | |
 `--. \  __|| . ` | | |   | | | . ` ||  __|| |
/\__/ / |___| |\  | | |  _| |_| |\  || |___| |____
\____/\____/\_| \_/ \_/  \___/\_| \_/\____/\_____/

  ██████╗ ██████╗  ██████╗     ██╗   ██╗██████╗     ██╗
  ██╔══██╗██╔══██╗██╔═══██╗    ██║   ██║╚════██╗   ███║
  ██████╔╝██████╔╝██║   ██║    ██║   ██║ █████╔╝   ╚██║
  ██╔═══╝ ██╔══██╗██║   ██║    ╚██╗ ██╔╝██╔═══╝     ██║
  ██║     ██║  ██║╚██████╔╝     ╚████╔╝ ███████╗    ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝       ╚═══╝  ╚══════╝    ╚═╝
```

> **Professional OSINT · Bug Bounty · Threat Intelligence · Autonomous AI Platform**
> Multi-language: **Python** · **Go** · **Rust**
> Built-in **Autonomous AI Brain** with ReAct Loop · Q-Learning RL · Custom Neural Network

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red)](https://kali.org)
[![Model](https://img.shields.io/badge/SentinelNet-v4.0%20F1%3D0.83-orange)](models/)
[![RL](https://img.shields.io/badge/RL-Q--Learning%20462%20states-purple)](sentinel_brain/)

---

## What Makes This Different

This is **not** a script collection. This is a fully autonomous AI security platform where:

- The AI **thinks** — ReAct loop: Reason → Act → Observe → Reason again
- The AI **learns** — Q-Learning RL trains on your real targets
- The AI **generates** — Custom neural network (SentinelNet v4.0, F1=0.83)
- The AI **remembers** — Long-term SQLite memory across sessions
- The AI **monitors** — 24/7 background monitoring with Telegram alerts
- Everything runs on **your machine** — no cloud, no API keys required for core features

---

## Architecture

```
sentinel-pro> brain investigate target.com
        ↓
┌─────────────────────────────────────────────┐
│           SENTINEL BRAIN v2.0               │
│         ReAct Autonomous Loop               │
│                                             │
│  Reason → Act → Observe → Reason again      │
│                                             │
│  SentinelNet v4.0 (CNN+Transformer)         │
│  ├── threat_label   (LOW/MEDIUM/HIGH/CRIT)  │
│  ├── threat_type    (recon/web_vuln/breach) │
│  ├── action_hint    (patch_now/escalate)    │
│  └── confidence     (0-1)                   │
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
│  GNN          — Entity relationship graph   │
│  Isolation Forest — Anomaly detection       │
│  DBSCAN       — Username/IP clustering      │
│  LightGBM     — Log analysis               │
│  Genetic Algo — Tool sequence optimizer     │
│  Q-Learning   — RL autonomous tool select  │
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
| **RL Agent** | Q-Learning, 19 tools, 462+ states learned, epsilon-greedy |
| **SentinelNet v4.0** | CNN+Transformer, F1=0.83, threat/type/action/confidence |
| **Advanced ML** | GNN, Isolation Forest, DBSCAN, LightGBM, Genetic Algorithm |
| **OSINT** | 40+ social platforms, person/email/phone/image profiling |
| **Bug Bounty** | SSL/TLS · Headers · Ports · SQLi/XSS/SSRF · LFI/RFI · XXE · SSTI · CORS · OAuth · JWT |
| **Recon** | WHOIS · DNS · Subdomains · Wayback · GitHub/Google dorking · ASN · Cloud assets |
| **Breach** | HaveIBeenPwned · HudsonRock · LeakCheck · IntelX · Dehashed · Paste Monitor |
| **24/7 Monitor** | Continuous target monitoring, new finding → auto Telegram alert |
| **Dark Web** | Tor integration · .onion crawling · Stealth mode |
| **Legal** | Chain of custody · Evidence vault · Court-grade HTML/PDF reports |

---

## Requirements

- **OS:** Kali Linux (recommended)
- **Python:** 3.10+
- **Go:** 1.21+
- **Rust/Cargo:** 1.70+
- **Chromium:** for screenshots

---

## Installation

```bash
git clone https://github.com/Mrsultan7890/osints.git
cd osints
bash setup.sh
sentinel
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
```

---

## Commands

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

### 24/7 Monitor
```
sentinel-pro> monitor add <target>           # Add target to monitor
sentinel-pro> monitor interval <seconds>     # Set scan interval
sentinel-pro> monitor status                 # Monitor status
sentinel-pro> monitor stop                   # Stop monitoring
```

### Bug Bounty
```
sentinel-pro> bugbounty <domain>
```
SSL/TLS · Headers · Ports · SQLi/XSS/SSRF · Blind SQLi · DOM XSS · SSTI · CORS · LFI/RFI · XXE · Clickjacking · OAuth · JWT · Nuclei · DirBuster · Rust Fuzzer

### Recon
```
sentinel-pro> recon <domain>
```
WHOIS · DNS · Subdomains · Go Scraper · Wayback · DNS History · Google Dorks · GitHub Dorks · ASN · Cloud Assets · Cert Transparency · Job OSINT

### Breach Check
```
sentinel-pro> breach <email or username>
```
HIBP · HudsonRock · LeakCheck · IntelX · Dehashed · Paste Monitor

### OSINT
```
sentinel-pro> email <email>
sentinel-pro> phone <number>
sentinel-pro> person <name/email/phone>
sentinel-pro> image <path>
sentinel-pro> collect <target>
```

### ML Training
```
sentinel-pro> train status
sentinel-pro> train collect
sentinel-pro> train run
sentinel-pro> train save
sentinel-pro> train eval
```

### System
```
sentinel-pro> tor on / off / status / newip
sentinel-pro> telegram test / status
sentinel-pro> pdf
sentinel-pro> clear
```

---

## SentinelNet v4.0 — Custom Neural Network

**Completely custom — built from scratch. No GPT, no OpenAI, no external models.**

```
Architecture: Embedding → CNN (k=3,5,7) → LayerNorm → Multi-Head Classifier
Outputs:
  ├── threat_label   : LOW / MEDIUM / HIGH / CRITICAL
  ├── threat_type    : recon / web_vuln / breach / malware / phishing / apt
  ├── action_hint    : patch_now / escalate / investigate / monitor / block_ip
  └── confidence     : 0.0 - 1.0

Training:
  ├── 50,000+ samples
  ├── NVD CVE database
  ├── GitHub security advisories
  ├── MITRE ATT&CK
  ├── Real scan feedback (continuous learning)
  └── Synthetic security samples

Performance:
  ├── F1 Score     : 0.8335
  ├── Accuracy     : 83.3%
  └── Model size   : 8.55 MB
```

---

## RL Agent — Q-Learning

```
State  : [tools_used, findings, ports, subdomains, risk_level]
Actions: nmap, nikto, nuclei, gobuster, ffuf, sqlmap, amass,
         whatweb, wafw00f, sslscan, theHarvester, searchsploit, breach

Reward:
  +20  Critical finding
  +10  High finding
  +5   Medium finding
  +3   New subdomain
  +2   New port
  -1   Nothing found
  -2   Tool error

Current Stats:
  States learned : 462
  Best reward    : 24.0
  Avg reward     : 8.04
  Epsilon        : 0.05
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

---

## Unified Database

All components write to single SQLite database:

```
data/sentinel.db
├── scans        — every scan record
├── findings     — all vulnerabilities
├── iocs         — IPs, domains, emails, hashes
├── decisions    — brain decisions + RL episodes
├── memory       — long-term target memory
├── rl_episodes  — RL training history
└── tool_stats   — tool effectiveness (feeds Genetic optimizer)
```

---

## 24/7 Autonomous Monitoring

```python
# Monitor runs in separate xterm window
# Main terminal stays clean
sentinel-pro> monitor add target.com
sentinel-pro> monitor interval 3600    # every hour
```

New finding detected → automatic Telegram alert:
```
🔔 MONITOR ALERT
Target : target.com
Time   : 2026-04-15 08:00
New    : 3 finding(s)

NEW FINDINGS:
🔴 SQL Injection — login form parameter
🟠 XSS Reflected — search parameter
🟡 Missing Headers — CSP not set

Sentinel Pro — @who_is_the_black_hat
```

---

## Project Structure

```
main.py                      ← CLI orchestrator
config.py                    ← Centralized config + API keys
sentinel_brain/
  brain.py                   ← ReAct autonomous orchestrator v2.0
  kali_controller.py         ← Full Kali Linux control + output parsing
  memory.py                  ← Long-term SQLite memory
  monitor.py                 ← 24/7 autonomous monitoring
  rl_agent.py                ← Q-Learning RL agent
  advanced_ml.py             ← GNN + IsoForest + DBSCAN + LightGBM + Genetic
  agents/
    recon_agent.py           ← Reconnaissance
    exploit_agent.py         ← Bug bounty / exploitation
    osint_agent.py           ← OSINT investigation
    breach_agent.py          ← Credential leak checking
    report_agent.py          ← Report generation + Telegram
modules/
  bugbounty/                 ← 25+ bug bounty scanners
  recon/                     ← 15+ recon modules
  breach/                    ← 7-source breach checker
  ml_engine/
    sentinel_net.py          ← SentinelNet v4.0 neural network
    trainer.py               ← Training pipeline + continuous learning
    decision_engine.py       ← Autonomous decision making
    autonomous_loop.py       ← 24h background retrain loop
    nlp_analyzer.py          ← NLP profiling
    entity_matcher.py        ← TF-IDF similarity
    identity_scorer.py       ← Bayesian identity scoring
    username_clusterer.py    ← DBSCAN clustering
  database.py                ← Unified SQLite database
  notifications.py           ← Telegram alerts
  utils.py                   ← Rate limiter + Tor session
scraper/                     ← Go HTTP scraper
analyzer/                    ← Rust parallel analyzer
fuzzer/                      ← Rust parallel fuzzer
models/
  ml_engine/
    sentinel_threat_net.pt   ← SentinelNet v4.0 weights
    sentinel_vocab.json      ← Tokenizer vocabulary
    rl_qtable.json           ← Q-Learning table
    threat_classifier.joblib ← TF-IDF + LogReg classifier
    fake_detector.joblib     ← Random Forest fake detector
```

---

## API Keys (Optional)

```bash
cp .env.example .env
nano .env
```

| Key | Service |
|-----|---------|
| `SHODAN_API_KEY` | Shodan host intelligence |
| `GITHUB_TOKEN` | GitHub dorking |
| `SERPAPI_KEY` | Google dorking |
| `NVD_API_KEY` | CVE lookup |
| `HIBP_API_KEY` | HaveIBeenPwned |
| `DEHASHED_EMAIL` + `DEHASHED_API_KEY` | Dehashed passwords |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Instant alerts |

---

## Roadmap

- [ ] SentinelNet v5.0 — Encoder-Decoder generative model
- [ ] Command generation — model generates exact commands
- [ ] Full autonomous loop — no human input needed
- [ ] Fine-tuning on real pentest data

---

## Legal Notice

This tool is intended for **authorized security testing and OSINT research only**.
Always obtain proper written authorization before scanning any target.
The authors are not responsible for misuse.

---

## Author

Made by [@who_is_the_black_hat](https://www.instagram.com/who_is_the_black_hat) · [GitHub](https://github.com/Mrsultan7890/osints)
