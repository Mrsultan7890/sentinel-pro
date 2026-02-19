# 🛡️ The Sentinel - Professional OSINT Tool

A multi-language, AI-powered OSINT intelligence platform optimized for Kali NetHunter environments.

## Features

- **Professional CLI Interface** with animated banner and interactive commands
- **Multi-Language Architecture**: Go (scraping/prediction), Rust (analysis), Python (coordination/AI)
- **Real-Time Data Collection** from multiple sources without external APIs
- **AI-Powered Behavioral Analysis** using machine learning models
- **Network Correlation Engine** built in Rust for high-performance analysis
- **Comprehensive Intelligence Reports** with visualizations and predictions

## Quick Start

```bash
# Setup (run once)
chmod +x setup.sh
./setup.sh

# Run The Sentinel
python3 main.py
```

## Usage

```
sentinel> collect john.doe@example.com    # Collect data on target
sentinel> collect @suspicious_user        # Collect data on username
sentinel> analyze                         # Run correlation analysis
sentinel> report                          # Generate intelligence report
sentinel> status                          # Show session status
sentinel> help                            # Show all commands
```

## Architecture

### Module 1: Digital Footprint Collector
- **Go Scraper**: High-performance concurrent web scraping with goroutines
- **Python Extractor**: Entity extraction using BeautifulSoup and regex patterns
- **Rate Limiting**: Human-like browsing behavior to avoid detection

### Module 2: Web Anomaly Analyzer  
- **Rust Engine**: High-performance correlation analysis with parallel processing
- **AI Behavioral Modeling**: TF-IDF vectorization and DBSCAN clustering
- **Risk Scoring**: Multi-factor risk assessment algorithm

### Module 3: Predictive & Reporting Engine
- **Go Predictor**: Next-step recommendation engine
- **Python Reporter**: HTML report generation with network visualizations
- **Intelligence Timeline**: Chronological investigation tracking

## Output

Reports are generated in `reports/` directory containing:
- Executive summary with risk assessment
- Key findings and entity correlations  
- Network visualization graphs
- Predictive recommendations for next steps
- Professional HTML format for briefings

## Requirements

- Python 3.8+
- Go 1.19+
- Rust 1.60+
- Kali Linux (recommended)

## Legal Notice

This tool is for legitimate OSINT research and cybersecurity purposes only. Users are responsible for compliance with applicable laws and regulations.# osints
