# The Sentinel Pro v3.0 — Project Structure

## Root Layout
```
osints/
├── main.py                    # CLI orchestrator — entry point
├── config.py                  # Centralized config + API keys
├── sentinel                   # Shell launcher script
├── setup.sh                   # Installation script
├── requirements.txt           # Python dependencies
├── Dockerfile / docker-compose.yml
├── .env / .env.example        # API key configuration
├── sentinel_brain/            # Autonomous AI core
├── modules/                   # Feature modules (Python)
├── scraper/                   # Go HTTP scraper
├── analyzer/                  # Rust parallel analyzer
├── fuzzer/                    # Rust parallel fuzzer
├── media_analyzer/            # Rust media analysis
├── dirbuster/                 # Go directory bruster
├── network_mapper/            # Go network mapper
├── predictor/                 # Go predictor service
├── smuggler/                  # Go HTTP smuggler
├── stealth_proxy/             # Go stealth proxy
├── models/ml_engine/          # Trained model artifacts
├── data/                      # SQLite databases
├── reports/                   # Generated scan reports
├── investigations/            # Per-target investigation data
├── screenshots/               # Web screenshots
├── evidence/                  # Legal evidence vault
├── logs/                      # Application logs
└── scripts/                   # Utility/training scripts
```

## Core Components

### sentinel_brain/ — Autonomous AI Core
```
sentinel_brain/
├── brain.py           # ReAct loop orchestrator v2.0 — main reasoning engine
├── kali_controller.py # PTY terminal control, tool execution, output parsing
├── rl_agent.py        # Q-Learning RL agent — autonomous tool selection
├── advanced_ml.py     # GNN, Isolation Forest, DBSCAN, LightGBM, Genetic Algo
├── memory.py          # Long-term SQLite memory across sessions
├── monitor.py         # 24/7 background monitoring daemon
├── terminal.py        # Terminal utilities
└── agents/
    ├── recon_agent.py    # Reconnaissance orchestration
    ├── exploit_agent.py  # Bug bounty / exploitation
    ├── osint_agent.py    # OSINT investigation
    ├── breach_agent.py   # Credential leak checking
    └── report_agent.py   # Report generation + Telegram alerts
```

### modules/ — Feature Modules
```
modules/
├── bugbounty/         # 25+ vulnerability scanners
│   ├── vuln_scanner.py, ssl_checker.py, headers_checker.py
│   ├── cors_scanner.py, ssti_scanner.py, xxe_scanner.py
│   ├── lfi_scanner.py, oauth_scanner.py, js_analyzer.py
│   ├── nuclei_bridge.py, fuzzer_bridge.py, dirbuster_bridge.py
│   └── rust_analyzer_bridge.py, smuggler_bridge.py, ...
├── recon/             # 15+ recon modules
│   ├── whois_lookup.py, subdomain_enum.py, dns_history.py
│   ├── google_dorker.py, github_dorker.py, wayback.py
│   ├── asn_mapper.py, cloud_assets.py, cert_transparency.py
│   └── email_osint.py, phone_osint.py, person_osint.py, image_osint.py
├── breach/            # 7-source breach checker
│   ├── breach_checker.py
│   └── report.py
├── ml_engine/         # ML pipeline
│   ├── sentinel_net.py        # SentinelNet v4.0 neural network
│   ├── trainer.py             # Training pipeline + continuous learning
│   ├── decision_engine.py     # Autonomous decision making
│   ├── autonomous_loop.py     # 24h background retrain loop
│   ├── nlp_analyzer.py        # NLP text profiling
│   ├── entity_matcher.py      # TF-IDF similarity matching
│   ├── identity_scorer.py     # Bayesian identity scoring
│   ├── username_clusterer.py  # DBSCAN clustering
│   ├── writing_fingerprinter.py
│   ├── timeline_analyzer.py
│   └── bulk_collector.py / bulk_processor.py / real_data_collector.py
├── database.py        # Unified SQLite database interface
├── notifications.py   # Telegram alert system
├── utils.py           # Rate limiter, Tor session management
├── cli_interface.py   # Interactive CLI shell
├── agent_core.py      # Base agent functionality
├── enhanced_profile_extractor.py  # Deep profile extraction
├── evidence_manager.py            # Legal evidence chain of custody
├── pdf_export.py                  # PDF report generation
├── reporting_engine.py            # Unified report engine
├── darkweb_crawler.py             # Tor/.onion crawling
├── stealth_manager.py             # Stealth/evasion management
├── fake_profile_detector.py       # ML fake profile detection
├── anomaly_analyzer.py            # Anomaly detection
├── digital_footprint.py           # Digital footprint mapping
├── financial_analyzer.py          # Financial data analysis
├── media_validator.py             # Media file validation
├── semantic_analyzer.py           # Semantic text analysis
├── attack_chain.py                # Attack chain orchestration
├── autonomous.py                  # Autonomous scan orchestration
└── tool_registry.py               # Tool registration and management
```

### Go Services (compiled binaries included)
| Directory | Binary | Purpose |
|-----------|--------|---------|
| scraper/ | scraper | HTTP scraping with Go concurrency |
| dirbuster/ | dirbuster | Directory/path brute-forcing |
| network_mapper/ | network_mapper | Network topology mapping |
| predictor/ | predictor | Prediction service |
| smuggler/ | smuggler | HTTP request smuggling |
| stealth_proxy/ | stealth_proxy | Stealth proxy routing |

### Rust Services (compiled binaries included)
| Directory | Binary | Purpose |
|-----------|--------|---------|
| analyzer/ | analyzer | Parallel content analysis |
| fuzzer/ | fuzzer | Parallel parameter fuzzing |
| media_analyzer/ | media_analyzer | Media file analysis |

### models/ml_engine/ — Model Artifacts
```
models/ml_engine/
├── sentinel_threat_net.pt    # SentinelNet v4.0 weights (8.55 MB)
├── sentinel_vocab.json       # Tokenizer vocabulary
├── rl_qtable.json            # Q-Learning Q-table (462 states)
├── threat_classifier.joblib  # TF-IDF + LogReg classifier
├── fake_detector.joblib      # Random Forest fake profile detector
├── ga_fitness.json           # Genetic algorithm fitness data
├── metadata.json             # Model metadata
└── training_data/            # JSONL training datasets
```

### data/ — Unified Database
```
data/
├── sentinel.db         # Main SQLite DB: scans, findings, iocs, decisions,
│                       # memory, rl_episodes, tool_stats
└── sentinel_memory.db  # Long-term memory database
```

## Architectural Patterns

### Multi-Language Architecture
- Python — orchestration, ML, OSINT, reporting (primary language)
- Go — high-performance network services (concurrent HTTP, scraping)
- Rust — CPU-intensive parallel tasks (fuzzing, analysis)
- Bridges in Python call compiled Go/Rust binaries via subprocess

### ReAct Autonomous Loop
```
brain.py → kali_controller.py → tool execution
    ↑              ↓
  Reason      Parse output
    ↑              ↓
  Observe ← findings/results
```

### Data Flow
```
Scan/OSINT → modules/ → database.py → sentinel.db
                ↓
         ml_engine/ → SentinelNet → threat classification
                ↓
         notifications.py → Telegram
                ↓
         reporting_engine.py → HTML/PDF reports
```

### Bridge Pattern
Python modules call Go/Rust binaries via subprocess bridges:
- `fuzzer_bridge.py` → `fuzzer/fuzzer`
- `dirbuster_bridge.py` → `dirbuster/dirbuster`
- `rust_analyzer_bridge.py` → `analyzer/analyzer`
- `go_scraper_bridge.py` → `scraper/scraper`
- `smuggler_bridge.py` → `smuggler/smuggler`
