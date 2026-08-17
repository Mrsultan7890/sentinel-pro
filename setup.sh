#!/bin/bash
set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
ORG='\033[0;33m'

p()  { echo -e "$1"; }
ok() { p "  ${GREEN}✓${RESET}  $1"; }
warn() { p "  ${YELLOW}⚠${RESET}  $1"; }
fail() { p "  ${RED}✗${RESET}  $1"; }
info() { p "  ${CYAN}→${RESET}  $1"; }

clear

# ── Banner ────────────────────────────────────────────────────────────────────
p ""
p "${ORG}${BOLD}  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ${RESET}"
p "${ORG}${BOLD}  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ${RESET}"
p "${ORG}${BOLD}  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ${RESET}"
p "${ORG}${BOLD}  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ${RESET}"
p "${ORG}${BOLD}  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ${RESET}"
p "${ORG}${BOLD}  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ${RESET}"
p "${DIM}                    P R O   v 3 . 1   —   S e t u p${RESET}"
p ""
p "${DIM}  ─────────────────────────────────────────────────────────────────${RESET}"
p "  ${CYAN}Professional OSINT · Bug Bounty · Threat Intelligence · AI Platform${RESET}"
p "${DIM}  ─────────────────────────────────────────────────────────────────${RESET}"
p ""

# ── OS check ──────────────────────────────────────────────────────────────────
p "${BOLD}  ▶  System Check${RESET}"
p ""
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ $ID == "kali" ]]; then
        ok "OS: Kali Linux $VERSION_ID"
    else
        warn "OS: $PRETTY_NAME — Kali Linux recommended"
    fi
fi

# ── Requirements check ────────────────────────────────────────────────────────
RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
RAM_GB=$(echo "scale=1; $RAM_KB/1048576" | bc)
DISK_FREE=$(df -BG . | awk 'NR==2{print $4}' | tr -d 'G')
CPU_CORES=$(nproc)

RAM_OK=true; DISK_OK=true
(( RAM_KB < 3145728 )) && RAM_OK=false
(( DISK_FREE < 5 ))    && DISK_OK=false

$RAM_OK  && ok  "RAM:  ${RAM_GB} GB available  (minimum 3 GB)" \
         || warn "RAM:  ${RAM_GB} GB available  — minimum 3 GB recommended"
$DISK_OK && ok  "Disk: ${DISK_FREE} GB free  (minimum 5 GB)" \
         || warn "Disk: ${DISK_FREE} GB free  — minimum 5 GB required"
ok "CPU:  ${CPU_CORES} cores"

# ── Storage permission ────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Storage Allocation${RESET}"
p ""
p "  The tool will create the following on your system:"
p ""
p "  ${DIM}Location                   Size (approx)   Purpose${RESET}"
p "  ${DIM}────────────────────────────────────────────────────────────${RESET}"
p "  $(pwd)/venv              ~500 MB         Python dependencies"
p "  $(pwd)/models/           ~450 MB         SentinelOctopus-0.5B model"
p "  $(pwd)/data/             ~5 MB           SQLite databases"
p "  $(pwd)/reports/          grows           Scan reports + PDFs"
p "  ~/.local/bin/sentinel    <1 KB           Global command symlink"
p ""
p "  ${YELLOW}Total estimated: ~1 GB minimum  (grows with scan data)${RESET}"
p ""

if ! $DISK_OK; then
    p "  ${RED}${BOLD}WARNING: Low disk space (${DISK_FREE} GB free) — minimum 5 GB required${RESET}"
    p ""
    read -rp "  Continue anyway? [y/N] " _disk_ans
    [[ "$_disk_ans" =~ ^[Yy]$ ]] || { p "  Aborted."; exit 1; }
fi

read -rp "  Allow Sentinel Pro to use this storage? [Y/n] " _storage_ans
[[ -z "$_storage_ans" || "$_storage_ans" =~ ^[Yy]$ ]] || { p "  Aborted."; exit 1; }

if ! $RAM_OK; then
    p ""
    p "  ${YELLOW}${BOLD}WARNING: Low RAM (${RAM_GB} GB) — SentinelOctopus needs ~1.5 GB${RESET}"
    p "  ${YELLOW}Tool will still work — falls back to Groq LLM when RAM is low.${RESET}"
    p ""
    read -rp "  Continue with limited RAM? [Y/n] " _ram_ans
    [[ -z "$_ram_ans" || "$_ram_ans" =~ ^[Yy]$ ]] || { p "  Aborted."; exit 1; }
fi

p ""

# ── System packages ───────────────────────────────────────────────────────────
p "${BOLD}  ▶  Installing system packages...${RESET}"
p ""
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go \
    chromium \
    tor \
    libssl-dev \
    2>/dev/null || true
ok "System packages installed"

# ── Rust ──────────────────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    source "$HOME/.cargo/env"
    ok "Rust installed"
else
    ok "Rust $(cargo --version)"
fi

# ── Python venv ───────────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Python Environment${RESET}"
p ""
info "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
info "Installing torch (CPU-only ~200MB)..."
pip install torch --index-url https://download.pytorch.org/whl/cpu -q
info "Installing Python dependencies..."
pip install -r requirements.txt -q
ok "Python dependencies installed"

# ── NLTK Data Download ────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  ML Data${RESET}"
p ""
info "Downloading NLTK data..."
python3 -c "
import nltk
pkgs = ['punkt', 'punkt_tab', 'stopwords', 'averaged_perceptron_tagger',
        'averaged_perceptron_tagger_eng', 'maxent_ne_chunker',
        'maxent_ne_chunker_tab', 'words']
for p in pkgs:
    nltk.download(p, quiet=True)
    print(f'  ✓ nltk:{p}')
" 2>/dev/null || echo "  ⚠ NLTK download failed — run manually: python3 -c \"import nltk; nltk.download('all')\""

# ── spaCy Model Download ──────────────────────────────────────────────────────
info "Downloading spaCy model..."
python3 -m spacy download en_core_web_sm -q 2>/dev/null && ok "spaCy en_core_web_sm" || warn "spaCy download failed — NER will use NLTK fallback"

# ── .env file ─────────────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Configuration${RESET}"
p ""
if [[ ! -f .env ]]; then
    cp .env.example .env
    ok "Created .env from .env.example"
    info "Edit .env to add your API keys before first run"
else
    ok ".env already exists"
fi

# ── Go binaries ───────────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Building Go binaries${RESET}"
p ""

build_go() {
    local dir=$1
    if [[ -d "$dir" && -f "$dir/main.go" ]]; then
        (cd "$dir" && go build -o "$(basename $dir)" .) && ok "$dir" || fail "$dir (build failed)"
    else
        p "  ${DIM}-  $dir (skipped)${RESET}"
    fi
}

build_go scraper
build_go predictor
build_go stealth_proxy
build_go network_mapper
build_go smuggler
build_go dirbuster

# ── Rust binaries ─────────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Building Rust binaries${RESET}"
p ""

build_rust() {
    local dir=$1
    if [[ -d "$dir" && -f "$dir/Cargo.toml" ]]; then
        (cd "$dir" && cargo build --release -q 2>&1) && ok "$dir" || fail "$dir (build failed)"
    else
        p "  ${DIM}-  $dir (skipped)${RESET}"
    fi
}

build_rust analyzer
build_rust media_analyzer
build_rust fuzzer
build_rust sentinel_proxy/rust_core
build_rust sentinel_proxy/rust_fuzzer

# ── SentinelOctopus-0.5B Model ───────────────────────────────────────────────
p ""
p "${BOLD}  ▶  SentinelOctopus-0.5B Model${RESET}"
p ""
MODEL_DIR="models/sentineloctopus-0.5b"
MODEL_BIN="$MODEL_DIR/pytorch_model.bin"

if [[ -f "$MODEL_BIN" ]]; then
    ok "SentinelOctopus-0.5B already present"
else
    info "Downloading SentinelOctopus-0.5B from GitHub Releases (~450MB)..."
    mkdir -p "$MODEL_DIR"
    ZIP_URL="https://github.com/Mrsultan7890/sentinel-pro/releases/download/v3.1/sentineloctopus-v1.1.zip"
    ZIP_TMP="/tmp/sentineloctopus-v1.1.zip"
    if curl -fL --progress-bar -o "$ZIP_TMP" "$ZIP_URL"; then
        info "Extracting model..."
        unzip -q -o "$ZIP_TMP" -d "$MODEL_DIR"
        INNER=$(find "$MODEL_DIR" -name "pytorch_model.bin" ! -path "$MODEL_BIN" 2>/dev/null | head -1)
        if [[ -n "$INNER" ]]; then
            mv "$(dirname $INNER)/"* "$MODEL_DIR/"
            rmdir "$(dirname $INNER)" 2>/dev/null || true
        fi
        rm -f "$ZIP_TMP"
        ok "SentinelOctopus-0.5B ready"
    else
        fail "Download failed — check internet or GitHub Release v3.1"
        warn "Tool will still work — falls back to Groq LLM"
        rm -f "$ZIP_TMP"
    fi
fi

# ── Chromium check ────────────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Optional Tools${RESET}"
p ""
CHROMIUM_BIN=$(command -v chromium || command -v chromium-browser || echo "")
if [[ -n "$CHROMIUM_BIN" ]]; then
    ok "Chromium: $CHROMIUM_BIN"
else
    warn "Chromium not found — screenshot feature disabled"
    info "Install: sudo apt install chromium"
fi

# ── Directory structure ───────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Directories & Databases${RESET}"
p ""
mkdir -p reports screenshots investigations evidence logs models models/ml_engine config data
chmod +x main.py setup.sh 2>/dev/null || true
ok "Directories created"
info "Initializing databases..."
python3 - <<'PYEOF'
import sqlite3, os
base = os.path.join(os.getcwd(), 'data')

conn = sqlite3.connect(f'{base}/sentinel.db')
conn.execute('CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, target TEXT, scan_type TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.execute('CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, scan_id INTEGER, vuln_type TEXT, severity TEXT, detail TEXT)')
conn.commit(); conn.close()

conn = sqlite3.connect(f'{base}/sentinel_memory.db')
conn.execute('CREATE TABLE IF NOT EXISTS memory (id INTEGER PRIMARY KEY, session TEXT, key TEXT, value TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.execute('CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY, target TEXT, action TEXT, result TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.commit(); conn.close()

conn = sqlite3.connect(f'{base}/sentinel_proxy.db')
conn.execute('CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, method TEXT, url TEXT, headers TEXT, body TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.execute('CREATE TABLE IF NOT EXISTS responses (id INTEGER PRIMARY KEY, request_id INTEGER, status INTEGER, headers TEXT, body TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.execute('CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, url TEXT, vuln_type TEXT, severity TEXT, detail TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
conn.commit(); conn.close()

print('  \033[0;32m✓\033[0m  sentinel.db')
print('  \033[0;32m✓\033[0m  sentinel_memory.db')
print('  \033[0;32m✓\033[0m  sentinel_proxy.db')
PYEOF

# ── Global sentinel command ──────────────────────────────────────────────────────
p ""
p "${BOLD}  ▶  Global Command${RESET}"
p ""
mkdir -p "$HOME/.local/bin"
ln -sf "$(pwd)/sentinel" "$HOME/.local/bin/sentinel"
if ! grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi
if ! grep -q '.local/bin' "$HOME/.zshrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
fi
ok "'sentinel' command installed → ~/.local/bin/sentinel"
info "Run: source ~/.bashrc  (or open new terminal)"

# ── Config files ──────────────────────────────────────────────────────────────
cat > config/stealth_config.json << 'EOF'
{
  "proxy_rotation_interval": 5,
  "user_agent_randomization": true,
  "tor_integration": true,
  "anti_detection_mode": true,
  "request_delays": {"min": 1, "max": 5}
}
EOF

cat > config/legal_config.json << 'EOF'
{
  "evidence_standards": ["ISO 27037", "NIST SP 800-86", "RFC 3227"],
  "chain_of_custody_required": true,
  "cryptographic_integrity": true,
  "legal_admissibility_mode": true,
  "jurisdiction": "international"
}
EOF

# ── Tor ───────────────────────────────────────────────────────────────────────
sudo systemctl enable tor 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
p ""
p "${DIM}  ─────────────────────────────────────────────────────────────────${RESET}"
p ""
p "${GREEN}${BOLD}  █████████████████████████████████████████████████████████${RESET}"
p "${GREEN}${BOLD}  ██╔════════════════════════════════════════════════════════║${RESET}"
p "${GREEN}${BOLD}  ██║   ✅  Setup Complete — The Sentinel Pro v3.1          ██║${RESET}"
p "${GREEN}${BOLD}  ██╚════════════════════════════════════════════════════════╝${RESET}"
p ""
p "  ${BOLD}Quick Start:${RESET}"
p "  ${CYAN}source venv/bin/activate${RESET}"
p "  ${CYAN}python3 main.py${RESET}"
p ""
p "  ${BOLD}SentinelProxy v2.0:${RESET}"
p "  ${CYAN}python3 sentinel_proxy/main.py${RESET}   ${DIM}# or: sentinel-pro> proxy start${RESET}"
p "  ${DIM}Browser proxy → 127.0.0.1:8082${RESET}"
p ""
p "  ${BOLD}Direct CLI:${RESET}"
p "  ${CYAN}python3 main.py --bugbounty example.com${RESET}"
p "  ${CYAN}python3 main.py --recon    example.com${RESET}"
p "  ${CYAN}python3 main.py --breach   user@example.com${RESET}"
p ""
p "  ${BOLD}API Keys ${DIM}(optional — edit .env):${RESET}"
p "  ${DIM}SHODAN_API_KEY · GITHUB_TOKEN · SERPAPI_KEY · NVD_API_KEY${RESET}"
p ""
p "  ${YELLOW}⚠  Edit .env and add your API keys before first run${RESET}"
p "  ${DIM}See README.md for full documentation${RESET}"
p ""
