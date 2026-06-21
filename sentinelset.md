# SentinelSET - Modern Social Engineering Toolkit

> **Next-gen SET integrated into Sentinel Pro v3.1**  
> AI-powered · Multi-language · Autonomous · Evasive

---

## 🎯 Project Overview

**Goal:** Modernize Social Engineering Toolkit with AI, better evasion, and multi-language performance.

**Status:** Planning Phase  
**Timeline:** 6 weeks  
**Languages:** Python (orchestration), Rust (security/speed), Go (concurrency)

---

## 📁 Directory Structure

```
sentinel_se/                          
├── core/                             [Python]
│   ├── manager.py                    # Main SE orchestrator
│   ├── target_profiler.py            # AI target analysis (Groq)
│   └── evasion_engine.py             # Anti-detection logic
│
├── phishing/                         [Python + Go]
│   ├── email_spoofer.py              # SMTP manipulation
│   ├── sms_sender.py                 # SMS gateway APIs
│   ├── template_generator.py         # Groq AI template gen
│   ├── credential_harvester.py       # Flask server
│   ├── website_cloner.go             # Fast site cloning
│   └── qr_generator.py               # QR code phishing
│
├── messaging/                        [Rust]
│   └── anonymous_messenger/
│       ├── src/
│       │   ├── tor_client.rs         # Arti Tor integration
│       │   ├── onion_service.rs      # Hidden service
│       │   ├── matrix_client.rs      # Matrix protocol
│       │   └── pgp_crypto.rs         # End-to-end encryption
│       └── Cargo.toml
│
├── payload/                          [Python + Rust]
│   ├── payload_generator.py          # Metasploit integration
│   ├── obfuscator.rs                 # AV evasion (polymorphic)
│   ├── dropper_builder.py            # Multi-stage payloads
│   └── encoder.py                    # Base64/XOR/AES encoding
│
├── c2/                               [Go]
│   ├── server.go                     # Lightweight C2 server
│   ├── agent.go                      # Implant client
│   ├── protocol.go                   # Custom protocol
│   └── encryption.go                 # AES-256-GCM
│
├── evasion/                          [Rust]
│   ├── av_bypass.rs                  # Signature evasion
│   ├── sandbox_detect.rs             # VM detection
│   ├── proxy_rotator.rs              # Multi-proxy rotation
│   └── traffic_shaper.rs             # Traffic masking
│
├── templates/                        [HTML/CSS/JS]
│   ├── phishing_pages/               # 100+ login clones
│   ├── emails/                       # 50+ email templates
│   └── sms/                          # 30+ SMS templates
│
└── reports/                          [Python]
    ├── campaign_tracker.py           # Success tracking
    ├── analytics.py                  # ML analytics
    └── export.py                     # Report generation
```

---

## 🔥 Core Features

### 1. Anonymous Messaging [Rust]

**Libraries:**
- `arti` (Tor client)
- `matrix-sdk` (E2EE chat)
- `sequoia-openpgp` (PGP)

**Features:**
- Tor hidden service (.onion)
- Matrix E2EE chat
- PGP encryption
- Self-destructing messages
- Metadata stripping
- Disposable emails (API integration)

**Commands:**
```bash
sentinel-pro> se message start                    # Start Tor service
sentinel-pro> se message send <target> <msg>      # Encrypted send
sentinel-pro> se message receive                  # Check inbox
```

---

### 2. Phishing Templates [Python + Go]

**Python:**
- Groq AI template generation
- Email spoofing (SMTP)
- Flask credential harvester

**Go:**
- Fast website cloning
- Concurrent mass mailer
- QR code generation

**Features:**
- 100+ phishing page templates (Facebook, Google, Microsoft, LinkedIn, etc.)
- 50+ email templates (password reset, invoice, security alert)
- 30+ SMS templates (bank OTP, delivery notifications)
- AI-generated personalized templates (Groq)
- Auto-inject credential harvester
- SPF/DKIM bypass techniques

**Commands:**
```bash
sentinel-pro> se phish campaign <targets.txt>     # Full campaign
sentinel-pro> se phish template list              # List templates
sentinel-pro> se phish template generate <type>   # AI generate
sentinel-pro> se phish clone <url>                # Clone website
sentinel-pro> se phish email <target> <template>  # Send email
sentinel-pro> se phish sms <number> <template>    # Send SMS
sentinel-pro> se phish qr <url>                   # QR phishing
```

---

### 3. Credential Harvester [Python Flask]

**Features:**
- Real-time credential capture
- IP logging + User-Agent
- Telegram alerts on capture
- Auto-redirect to real site
- Admin dashboard (http://127.0.0.1:8080/admin)
- CSV/JSON export

**Commands:**
```bash
sentinel-pro> se harvest start                    # Start server
sentinel-pro> se harvest status                   # Captured creds
sentinel-pro> se harvest export                   # Export CSV/JSON
```

---

### 4. Payload Generator [Python + Rust]

**Python:**
- Metasploit integration (PyMetasploit3)
- Payload encoding chains
- Dropper builder

**Rust:**
- Polymorphic code generation
- String encryption (AES-256)
- AMSI bypass (Windows)
- Syscall direct invocation

**Features:**
- Reverse shell / Bind shell
- Meterpreter payloads
- Multi-stage droppers
- AV evasion testing
- Obfuscation levels: low/medium/high/extreme

**Commands:**
```bash
sentinel-pro> se payload generate                 # Interactive
sentinel-pro> se payload obfuscate <file>         # Obfuscate
sentinel-pro> se payload test <file>              # AV test
```

---

### 5. C2 Server [Go]

**Features:**
- HTTP/HTTPS/DNS tunneling
- AES-256-GCM encryption
- Multi-agent management
- Command execution
- File upload/download
- Screenshot capture
- Keylogger integration
- Jitter (random sleep intervals)

**Commands:**
```bash
sentinel-pro> se c2 start --port 443              # Start server
sentinel-pro> se c2 agents                        # List agents
sentinel-pro> se c2 execute <id> <cmd>            # Run command
sentinel-pro> se c2 upload <id> <file>            # Upload file
sentinel-pro> se c2 screenshot <id>               # Capture screen
```

---

### 6. Evasion Engine [Rust]

**Features:**
- AV signature scanning
- Sandbox/VM detection
- AMSI bypass (Windows)
- ETW patching
- Proxy rotation
- Traffic fingerprint masking
- Polymorphic code mutation

---

### 7. AI Target Profiler [Python]

**Features:**
- LinkedIn/Twitter/GitHub scraping
- Interest detection (NLP)
- Job role analysis
- Likely click prediction
- Personalized template selection

**Groq Integration:**
```python
def generate_phishing_template(target_profile):
    """AI generates personalized phishing email"""
    prompt = f"""
    Target: {target_profile['name']}
    Company: {target_profile['company']}
    Interests: {target_profile['interests']}
    
    Generate convincing phishing email with urgency.
    """
    return groq.generate(prompt)
```

---

## 🔒 Legal & Ethical Safeguards

```python
class SocialEngineeringManager:
    def __init__(self):
        self.consent_mode = True     # Force confirmation
        self.legal_banner = True     # Show warning
        self.audit_log = True        # Log all ops
        self.whitelist_only = False  # Only authorized targets
```

**Features:**
- Legal disclaimer on first use
- Target confirmation prompt
- Audit logging (who, what, when)
- Whitelist mode (authorized targets only)
- Auto-stop on suspicious activity

---

## 🚀 Implementation Phases

### Phase 1: Phishing Core (Week 1)
- [ ] Email spoofer (Python)
- [ ] Template system (100+ pages)
- [ ] Credential harvester (Flask)
- [ ] AI template generator (Groq)

### Phase 2: Website Cloning (Week 2)
- [ ] Website cloner (Go)
- [ ] Auto-inject harvester
- [ ] Mass mailer (Go)
- [ ] QR code phishing

### Phase 3: Anonymous Messaging (Week 3-4)
- [ ] Tor client integration (Rust)
- [ ] Onion service (Rust)
- [ ] Matrix client (Rust)
- [ ] PGP encryption (Rust)
- [ ] Disposable emails

### Phase 4: Payload & C2 (Week 5)
- [ ] Payload generator (Python)
- [ ] Obfuscator (Rust)
- [ ] C2 server (Go)
- [ ] Agent implant (Go)
- [ ] AV evasion testing

### Phase 5: Testing & Integration (Week 6)
- [ ] End-to-end testing
- [ ] CLI integration
- [ ] Documentation
- [ ] Legal safeguards
- [ ] Report generation

---

## 📊 CLI Commands Summary

```bash
# Anonymous Messaging
se message start / send / receive

# Phishing
se phish campaign / template / clone / email / sms / qr

# Harvesting
se harvest start / status / export

# Payload
se payload generate / obfuscate / test

# C2
se c2 start / agents / execute / upload / screenshot

# Profiling
se profile <target>                           # AI profiling
se profile social <username>                  # Social scraping
```

---

## 🎨 Technology Stack

| Component | Language | Why? |
|-----------|----------|------|
| **Orchestration** | Python | Easy Groq/Metasploit integration |
| **Messaging** | Rust | Security-critical, memory safety |
| **Website Cloner** | Go | Fast HTTP, concurrency |
| **Payload Obfuscation** | Rust | Low-level control, speed |
| **C2 Server** | Go | Lightweight, goroutines |
| **Evasion** | Rust | Speed-critical, polymorphic code |
| **Templates** | HTML/CSS/JS | Standard web stack |

---

## 🔥 Advantages over Old SET

1. **AI-Powered** - Groq generates personalized phishing
2. **Faster** - Go/Rust for speed-critical ops
3. **Modern Templates** - 2024 UI/UX designs
4. **Better Evasion** - ML-based AV bypass
5. **Anonymous** - Tor + PGP + disposable emails
6. **Integrated** - Works with existing Sentinel modules
7. **Autonomous** - Brain can run campaigns automatically
8. **Real C2** - Lightweight Go server vs old SET listener

---

## 📝 Next Steps

1. Create `sentinel_se/` directory structure
2. Implement Phase 1 (phishing core)
3. Test email spoofing + harvester
4. Build website cloner in Go
5. Integrate with main CLI

---

**Status:** Ready to implement  
**First Priority:** Phishing core (email spoofer + templates + harvester)  
**ETA:** 6 weeks for full implementation

