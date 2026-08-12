# Sentinel Pro v3.1 — User Guide

> **Complete step-by-step guide for beginners**
> From installation to advanced features



## Table of Contents

1. [Quick Start (5 Minutes)](#quick-start-5-minutes)
2. [Installation Guide](#installation-guide)
3. [First Steps](#first-steps)
4. [Tutorials](#tutorials)
5. [Common Use Cases](#common-use-cases)
6. [Troubleshooting](#troubleshooting)
7. [FAQ](#faq)

---

## Quick Start (5 Minutes)

### Step 1: Install

```bash
git clone https://github.com/Mrsultan7890/sentinel-pro.git
cd osints
bash setup.sh
```

### Step 2: Configure (Optional)

```bash
cp .env.example .env
nano .env
# Add your API keys (optional for basic features)
```

### Step 3: Run Your First Scan

```bash
sentinel
sentinel-pro> bugbounty example.com
```

**That's it!** You just ran your first security scan! 🎉

---

## Installation Guide

### Prerequisites

- **OS:** Kali Linux (recommended) or Ubuntu/Debian
- **Python:** 3.10 or higher
- **Go:** 1.21+ (for Go services)
- **Rust:** 1.70+ (for Rust services)
- **Disk Space:** 2GB minimum
- **RAM:** 8GB recommended

### Step-by-Step Installation

#### 1. Clone Repository

```bash
git clone https://github.com/Mrsultan7890/sentinel-pro.git
cd osints
```

#### 2. Run Setup Script

```bash
bash setup.sh
```

This will:
- Install Python dependencies
- Build Go services
- Build Rust services
- Create necessary directories
- Set up configuration files

#### 3. Verify Installation

```bash
sentinel
sentinel-pro> status
```

You should see:
```
✓ Python: 3.10+
✓ Models: 4 loaded
✓ Agents: 19 active
✓ Tools: 19 integrated
```

#### 4. Configure API Keys (Optional)

```bash
# Copy example config
cp .env.example .env

# Edit config
nano .env

# Add your keys (see API Keys section)
```

**Minimum Required:**
- `GROQ_API_KEY` — For AI features (get from [groq.com](https://console.groq.com))

**Recommended:**
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` — For alerts
- `SHODAN_API_KEY` — For enhanced recon
- `GITHUB_TOKEN` — For GitHub dorking

---

## First Steps

### Launch Sentinel Pro

```bash
sentinel
```

You'll see:
```
  ██████╗ ██████╗  ██████╗     ██╗   ██╗██████╗     ██╗
  ██╔══██╗██╔══██╗██╔═══██╗    ██║   ██║╚════██╗   ███║
  ██████╔╝██████╔╝██║   ██║    ██║   ██║ █████╔╝   ╚██║
  ██╔═══╝ ██╔══██╗██║   ██║    ╚██╗ ██╔╝██╔═══╝     ██║
  ██║     ██║  ██║╚██████╔╝     ╚████╔╝ ███████╗    ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝       ╚═══╝  ╚══════╝    ╚═╝

Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform

sentinel-pro>
```

### Check System Status

```bash
sentinel-pro> status
```

### Get Help

```bash
sentinel-pro> help
sentinel-pro> ?
```

### Exit

```bash
sentinel-pro> exit
# or
sentinel-pro> quit
# or
sentinel-pro> q
```

---

## Tutorials

### Tutorial 1: Your First Bug Bounty Scan

**Goal:** Find vulnerabilities in a website

**Time:** 5-10 minutes

**Steps:**

1. Launch Sentinel Pro:
```bash
sentinel
```

2. Run bug bounty scan:
```bash
sentinel-pro> bugbounty example.com
```

3. Wait for scan to complete (2-5 minutes)

4. View results:
```bash
sentinel-pro> report
```

5. Export to PDF:
```bash
sentinel-pro> pdf
```

**What it scans:**
- SSL/TLS configuration
- Security headers
- Open ports
- SQL injection
- XSS vulnerabilities
- SSRF, SSTI, LFI, XXE
- CORS misconfigurations
- Subdomain takeover
- And 20+ more checks!

**Output:**
- Terminal summary
- JSON report in `reports/`
- HTML report in `reports/`
- PDF report (if requested)

---

### Tutorial 2: OSINT Investigation

**Goal:** Gather intelligence on a person/email/phone

**Time:** 3-5 minutes

#### Email Investigation

```bash
sentinel-pro> email target@example.com
```

**What it finds:**
- Data breaches
- Social media profiles
- Domain information
- Disposable email detection
- Email validation

#### Phone Investigation

```bash
sentinel-pro> phone +1234567890
```

**What it finds:**
- Carrier information
- Country/location
- Line type (mobile/landline)
- Social media hints
- Reputation score

#### Person Investigation

```bash
sentinel-pro> person "John Doe"
# or
sentinel-pro> person john.doe@example.com
# or
sentinel-pro> person +1234567890
```

**What it finds:**
- All emails associated
- All phone numbers
- Social media profiles (40+ platforms)
- Username variations
- Relation graph
- Digital footprint

---

### Tutorial 3: Breach Check

**Goal:** Check if email/username was in data breaches

**Time:** 1-2 minutes

```bash
sentinel-pro> breach user@example.com
```

**Sources checked:**
- HaveIBeenPwned (HIBP)
- HudsonRock (Stealer logs)
- LeakCheck
- IntelX
- Dehashed
- Paste Monitor

**Output:**
```
💀 BREACH CHECK RESULTS

Target: user@example.com
Risk Level: HIGH

Breaches Found: 5
├─ LinkedIn (2021) - 700M users
├─ Facebook (2019) - 533M users
├─ Adobe (2013) - 153M users
└─ ...

Stealer Logs: 2
├─ RedLine (2023) - Passwords exposed
└─ Raccoon (2022) - Cookies stolen

Recommendations:
1. Change all passwords immediately
2. Enable 2FA on all accounts
3. Monitor for suspicious activity
```

---

### Tutorial 4: Reconnaissance

**Goal:** Gather information about a domain

**Time:** 5-10 minutes

```bash
sentinel-pro> recon example.com
```

**What it does:**
- WHOIS lookup
- DNS records
- Subdomain enumeration
- Wayback Machine history
- DNS history
- Google dorking
- GitHub dorking
- ASN mapping
- Cloud assets discovery
- Certificate transparency
- Technology fingerprinting

**Output:**
```
🔍 RECON RESULTS

Domain: example.com
Risk Level: MEDIUM

Subdomains Found: 47
├─ admin.example.com (CRITICAL - Admin panel exposed)
├─ api.example.com
├─ dev.example.com (HIGH - Development server)
└─ ...

Technologies:
├─ Nginx 1.18.0
├─ PHP 7.4.3
├─ WordPress 5.8
└─ MySQL

Cloud Assets:
├─ AWS S3: example-backups (PUBLIC!)
└─ Azure: example-storage
```

---

### Tutorial 5: Sentinel Intel (Graph Intelligence)

**Goal:** Visual OSINT investigation like Maltego

**Time:** 10-15 minutes

#### Launch Sentinel Intel

```bash
# From terminal
cd sentinel_intel
python3 main.py

# Or from Sentinel Pro CLI
sentinel-pro> intel
```

#### Basic Workflow

1. **Add Entity:**
   - Click "Quick Add" button
   - Enter email/phone/domain/IP
   - Press Enter

2. **Run Transform:**
   - Right-click entity
   - Select transform (e.g., "Email → Breaches")
   - Wait for results

3. **Auto-Chain (AI-Powered):**
   - Select entity
   - Click "Auto-Chain" button
   - AI suggests next transforms
   - Click suggested transform

4. **Visualize:**
   - Drag nodes to organize
   - Click "Auto Layout" for automatic arrangement
   - Zoom in/out with mouse wheel
   - Color indicates risk level

5. **Export:**
   - File → Export PNG (high-res)
   - File → Export JSON (save graph)

#### Example Investigation

**Scenario:** Investigate suspicious email

1. Add email: `suspicious@example.com`
2. Run "Email → Breaches" — Found in 3 breaches
3. Run "Email → Social Profiles" — Found Twitter, LinkedIn
4. Run "Email → Domain Info" — Domain registered in Russia
5. Run "Domain → WHOIS" — Privacy protected
6. **Conclusion:** High-risk email, likely malicious

---

### Tutorial 6: SentinelProxy (Burp Suite Alternative)

**Goal:** Intercept and analyze HTTP traffic

**Time:** 10-15 minutes

#### Launch SentinelProxy

```bash
# From terminal
cd sentinel_proxy
python3 main.py

# Or from Sentinel Pro CLI
sentinel-pro> proxy start
```

#### Configure Browser

**Firefox:**
1. Settings → Network Settings
2. Manual proxy configuration
3. HTTP Proxy: `127.0.0.1`, Port: `8082`
4. Check "Use this proxy for HTTPS"
5. OK

**Chrome:**
```bash
chromium --proxy-server=http://127.0.0.1:8082
```

#### Install CA Certificate

1. Open: `http://mitm.it` in browser
2. Download certificate for your OS
3. Install certificate
4. Trust for identifying websites

#### Basic Usage

**Intercept Traffic:**
1. Click "INTERCEPT: ON" in toolbar
2. Browse any website
3. Request appears in Proxy tab
4. Modify request if needed
5. Click "FWD" to forward or "DROP" to drop

**Scan for Vulnerabilities:**
1. Browse target website normally
2. Go to "Scanner" tab
3. Click "Scan All Requests"
4. Wait for AI analysis
5. View findings with severity

**Fuzz Parameters:**
1. Right-click request in Proxy tab
2. Send to Intruder
3. Select attack type (Sniper/Battering Ram/etc.)
4. Mark injection points with §param§
5. Select payload type (SQLi/XSS/etc.)
6. Click "Start Attack"
7. View results sorted by response code/length

---

### Tutorial 7: Autonomous Brain

**Goal:** Let AI do the hacking for you

**Time:** 10-30 minutes

```bash
sentinel-pro> brain investigate example.com
```

**What happens:**
1. AI analyzes target
2. Decides which tools to use
3. Executes tools automatically
4. Parses output
5. Chains tools based on findings
6. Generates report
7. Sends Telegram alert

**Example Flow:**
```
Brain: "Let me investigate example.com"
  ↓
Brain: "Running nmap to find open ports..."
  ↓ Found: 80, 443, 22
Brain: "Port 80 open, running nikto..."
  ↓ Found: Outdated Apache
Brain: "Searching exploits with searchsploit..."
  ↓ Found: 3 exploits
Brain: "Running nuclei for known CVEs..."
  ↓ Found: CVE-2021-41773
Brain: "Generating report..."
  ↓
Brain: "Investigation complete! Found 5 vulnerabilities."
```

**Advanced:**
```bash
# Direct tool execution
sentinel-pro> brain nmap -sV example.com

# Full attack chain
sentinel-pro> brain full hack example.com

# Autonomous mode (no confirmation)
sentinel-pro> auto example.com --auto
```

---

### Tutorial 8: 24/7 Monitoring

**Goal:** Continuous monitoring with auto-alerts

**Time:** 5 minutes setup

#### Setup Monitor

```bash
sentinel-pro> monitor add example.com
sentinel-pro> monitor interval 3600    # Check every hour
sentinel-pro> monitor start
```

#### Make it Persistent (Survives Reboot)

```bash
sentinel-pro> monitor persistent install
```

#### Check Status

```bash
sentinel-pro> monitor status
```

**Output:**
```
📊 MONITOR STATUS

Active: YES
Targets: 1
  └─ example.com (last scan: 5 min ago)

Interval: 3600 seconds (1 hour)
Next scan: in 55 minutes

Persistent: YES (systemd service)
  └─ Auto-starts on boot

Total scans: 47
New findings: 3 (last 24h)
```

#### When New Finding Detected

**Automatic Telegram Alert:**
```
🔔 MONITOR ALERT

Target: example.com
Time: 2026-05-26 14:30
New: 2 finding(s)

🔴 SQL Injection — /login.php?id=
🟠 XSS Reflected — /search?q=

Sentinel Pro v3.1
```

---

## Common Use Cases

### Use Case 1: Bug Bounty Hunting

**Workflow:**
```bash
# 1. Recon
sentinel-pro> recon target.com

# 2. Find vulnerabilities
sentinel-pro> bugbounty target.com

# 3. Deep scan specific findings
sentinel-pro> brain investigate admin.target.com

# 4. Generate report
sentinel-pro> report
sentinel-pro> pdf
```

**Time:** 15-30 minutes  
**Output:** Professional PDF report with findings

---

### Use Case 2: OSINT Investigation

**Workflow:**
```bash
# 1. Start with email
sentinel-pro> email target@example.com

# 2. Check breaches
sentinel-pro> breach target@example.com

# 3. Full person profile
sentinel-pro> person target@example.com

# 4. Visual investigation
sentinel-pro> intel
# Then use graph to explore connections
```

**Time:** 10-20 minutes  
**Output:** Complete digital footprint

---

### Use Case 3: Penetration Testing

**Workflow:**
```bash
# 1. Network scan
sentinel-pro> brain nmap -sV -p- target.com

# 2. Web vulnerabilities
sentinel-pro> bugbounty target.com

# 3. Exploit search
sentinel-pro> metasploit search target.com

# 4. Attack chain
sentinel-pro> attackchain target.com

# 5. Evidence collection
sentinel-pro> evidence
```

**Time:** 30-60 minutes  
**Output:** Court-grade evidence + report

---

### Use Case 4: Threat Intelligence

**Workflow:**
```bash
# 1. Monitor targets
sentinel-pro> monitor add target1.com
sentinel-pro> monitor add target2.com
sentinel-pro> monitor persistent install

# 2. CVE monitoring
sentinel-pro> cve monitor target.com

# 3. Dark web monitoring
sentinel-pro> darkweb target.com

# 4. Automated alerts
# (Telegram alerts sent automatically)
```

**Time:** 5 min setup, then automatic  
**Output:** Real-time threat alerts

---

## Troubleshooting

### Issue 1: "Command not found: sentinel"

**Solution:**
```bash
# Add to PATH
echo 'export PATH="$PATH:/home/kali/osints"' >> ~/.bashrc
source ~/.bashrc

# Or run directly
cd /home/kali/osints
python3 main.py
```

---

### Issue 2: "GROQ_API_KEY not set"

**Solution:**
```bash
# Get free API key from groq.com
# Then add to .env
nano .env
# Add: GROQ_API_KEY=your_key_here

# Or use CLI
sentinel-pro> cred add GROQ_API_KEY your_key_here
```

---

### Issue 3: "Telegram alerts not working"

**Solution:**
```bash
# 1. Create bot with @BotFather on Telegram
# 2. Get bot token
# 3. Send /start to your bot
# 4. Get chat ID from: https://api.telegram.org/bot<TOKEN>/getUpdates

# 5. Add to .env
nano .env
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
TELEGRAM_CHAT_ID=123456789

# 6. Test
sentinel-pro> telegram test
```

---

### Issue 4: "Models not loading"

**Solution:**
```bash
# Check if models exist
ls -lh models/ml_engine/*.pt

# If missing, models will be created on first use
# Or download from releases page
```

---

### Issue 5: "Permission denied" errors

**Solution:**
```bash
# Fix permissions
chmod +x sentinel
chmod +x setup.sh

# For sudo tools (nmap, etc.)
sudo -v
```

---

### Issue 6: "Port 8082 already in use" (SentinelProxy)

**Solution:**
```bash
# Kill existing process
sentinel-pro> proxy stop

# Or manually
sudo lsof -ti:8082 | xargs kill -9

# Restart
sentinel-pro> proxy start
```

---

### Issue 7: "Wordlists not found"

**Solution:**
```bash
# Install SecLists
sudo apt update
sudo apt install seclists

# Install wordlists
sudo apt install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

---

### Issue 8: "Go/Rust binaries not found"

**Solution:**
```bash
# Rebuild Go services
cd scraper && go build -o scraper . && cd ..
cd dirbuster && go build -o dirbuster . && cd ..

# Rebuild Rust services
cd analyzer && cargo build --release && cd ..
cd fuzzer && cargo build --release && cd ..
```

---

## FAQ

### Q1: Is Sentinel Pro free?

**A:** Yes! Sentinel Pro is free and open source under the MIT license.

---

### Q2: Do I need API keys?

**A:** 
- **Minimum:** GROQ_API_KEY (for AI features)
- **Recommended:** Telegram, Shodan, GitHub (for enhanced features)
- **Optional:** 30+ other keys for specific features

Tool works without keys but with limited functionality.

---

### Q3: Can I use this for bug bounty?

**A:** Yes! Sentinel Pro is designed for:
- Bug bounty hunting
- Penetration testing
- OSINT investigations
- Security research

**Always get proper authorization before scanning!**

---

### Q4: What's the difference between Sentinel Pro and Burp Suite?

**A:**

| Feature | Burp Suite Pro | Sentinel Pro |
|---------|----------------|--------------|
| Price | $449/year | Free (Open Source) |
| Proxy | ✓ | ✓ (Rust core, faster) |
| Scanner | ✓ | ✓ (AI-powered) |
| OSINT | ✗ | ✓ (40+ platforms) |
| Autonomous AI | ✗ | ✓ (ReAct loop) |
| ML Models | ✗ | ✓ (4 custom models) |
| Graph Intel | ✗ | ✓ (Maltego-style) |
| 24/7 Monitor | ✗ | ✓ |

---

### Q5: Can I run this on Windows/Mac?

**A:** 
- **Best:** Kali Linux (native)
- **Good:** Ubuntu/Debian
- **Possible:** WSL2 on Windows, Docker
- **Not recommended:** macOS (some tools missing)

---

### Q6: How much disk space needed?

**A:**
- **Minimum:** 2GB
- **Recommended:** 5GB (with wordlists)
- **With data:** 10GB+ (scan results, evidence)

---

### Q7: Is this legal?

**A:** Yes, but:
- ✅ Use on your own systems
- ✅ Use with written authorization
- ✅ Use on bug bounty programs
- ❌ Don't scan without permission
- ❌ Don't use for illegal activities

**You are responsible for how you use this tool.**

---

### Q8: How do I update?

**A:**
```bash
cd /home/kali/osints
git pull
bash setup.sh
```

---

### Q9: Can I contribute?

**A:** Yes! Contributions are welcome. Open a pull request or issue on GitHub.

---

### Q10: Where can I get support?

**A:**
- **Documentation:** README.md + USER_GUIDE.md
- **Video Tutorial:** [Link]
- **Issues:** GitHub Issues
- **Contact:** [@who_is_the_black_hat](https://www.instagram.com/who_is_the_black_hat)

---

## Next Steps

1. ✅ Complete installation
2. ✅ Configure API keys
3. ✅ Run first scan
4. ✅ Watch video tutorial
5. ✅ Try all tutorials
6. ✅ Explore advanced features
7. ✅ Join community

---

## Additional Resources

- **README.md** — Technical reference
- **Video Tutorial** — 10-minute walkthrough
- **GitHub** — [github.com/Mrsultan7890/sentinel-pro](https://github.com/Mrsultan7890/sentinel-pro)
- **Instagram** — [@who_is_the_black_hat](https://www.instagram.com/who_is_the_black_hat)

---

## License

This software is open source under the MIT License.

**Copyright © 2026 @who_is_the_black_hat. All rights reserved.**

---

**Made with ❤️ by [@who_is_the_black_hat](https://www.instagram.com/who_is_the_black_hat)**
