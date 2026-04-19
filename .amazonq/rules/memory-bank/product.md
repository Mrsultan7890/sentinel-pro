# The Sentinel Pro v3.0 — Product Overview

## Purpose
Fully autonomous AI-driven security platform for OSINT, bug bounty hunting, and threat intelligence. Runs entirely on-device (Kali Linux) — no cloud, no external AI APIs required for core features.

## Value Proposition
- Not a script collection — an autonomous AI that reasons, acts, observes, and learns
- Self-improving via Q-Learning RL trained on real scan results
- Custom neural network (SentinelNet v4.0, F1=0.83) for threat classification
- Long-term memory across sessions via SQLite
- 24/7 background monitoring with Telegram alerts

## Key Features

### Autonomous Brain (ReAct Loop)
- Reason → Act → Observe → Reason cycle
- Adaptive planning with retry logic
- ML-driven tool selection and chaining
- Full Kali Linux PTY terminal control (19 tools integrated)

### SentinelNet v4.0 (Custom Neural Network)
- Architecture: Embedding → CNN (k=3,5,7) → LayerNorm → Multi-Head Classifier
- Outputs: threat_label (LOW/MEDIUM/HIGH/CRITICAL), threat_type, action_hint, confidence
- Trained on 50,000+ samples: NVD CVE, GitHub advisories, MITRE ATT&CK
- F1=0.8335, model size 8.55 MB, no external model dependencies

### RL Agent (Q-Learning)
- State: [tools_used, findings, ports, subdomains, risk_level]
- 19 actions (nmap, nikto, nuclei, gobuster, ffuf, sqlmap, amass, etc.)
- 462+ states learned, epsilon-greedy exploration (ε=0.05)
- Reward: +20 critical finding → -2 tool error

### Advanced ML Engine
- GNN — entity relationship graph (domain→IP→subdomain→email)
- Isolation Forest — anomaly detection (unusual ports, weird responses)
- DBSCAN — username/IP clustering across platforms
- LightGBM — log analysis and attack pattern detection
- Genetic Algorithm — tool sequence optimization

### OSINT Capabilities
- 40+ social platforms profiling
- Person / email / phone / image investigation
- Digital footprint mapping, fake profile detection
- Writing fingerprinting, identity scoring (Bayesian)

### Bug Bounty Scanning (25+ scanners)
- SSL/TLS, headers, ports, SQLi/XSS/SSRF, blind SQLi, DOM XSS
- SSTI, CORS, LFI/RFI, XXE, clickjacking, OAuth, JWT
- Nuclei integration, DirBuster, Rust fuzzer, HTTP smuggling

### Recon (15+ modules)
- WHOIS, DNS, subdomain enumeration, Wayback Machine
- Google/GitHub dorking, ASN mapping, cloud asset discovery
- Certificate transparency, job OSINT

### Breach Intelligence (7 sources)
- HaveIBeenPwned, HudsonRock, LeakCheck, IntelX, Dehashed, Paste Monitor

### Reporting
- HTML/PDF court-grade reports with chain of custody
- Evidence vault with media preservation
- Telegram instant alerts for new findings

## Target Users
- Security researchers and bug bounty hunters
- Penetration testers on Kali Linux
- Threat intelligence analysts
- OSINT investigators

## Use Cases
- Autonomous target investigation: `brain investigate <target>`
- Continuous 24/7 monitoring: `monitor add <target>`
- Bug bounty automation: `bugbounty <domain>`
- Person/identity OSINT: `person <name/email/phone>`
- Breach checking: `breach <email>`
- RL-driven adaptive scanning: `rl run <target>`
