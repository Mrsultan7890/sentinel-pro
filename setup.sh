#!/bin/bash
set -e

echo "🛡️  The Sentinel Pro v2.1 — Setup"
echo "==================================="

# ── OS check ──────────────────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ $ID == "kali" ]]; then
        echo "✓ Kali Linux detected"
    else
        echo "⚠  Not Kali Linux — some features may behave differently"
    fi
fi

# ── System packages ───────────────────────────────────────────────────────────
echo ""
echo "📦 Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go \
    chromium \
    tor \
    libssl-dev \
    2>/dev/null || true

# ── Rust ──────────────────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "✓ Rust $(cargo --version)"
fi

# ── Python venv ───────────────────────────────────────────────────────────────
echo ""
echo "🐍 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✓ Python dependencies installed"

# ── NLTK Data Download ────────────────────────────────────────────────────────
echo ""
echo "🧠 Downloading NLTK data for ML engine..."
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
echo ""
echo "🧠 Downloading spaCy model (better NER accuracy)..."
python3 -m spacy download en_core_web_sm 2>/dev/null && echo "  ✓ spaCy en_core_web_sm" || echo "  ⚠ spaCy model download failed — NER will use NLTK fallback"

# ── .env file ─────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "✓ Created .env from .env.example — edit it to add your API keys"
else
    echo "✓ .env already exists"
fi

# ── Go binaries ───────────────────────────────────────────────────────────────
echo ""
echo "🔨 Building Go binaries..."

build_go() {
    local dir=$1
    if [[ -d "$dir" && -f "$dir/main.go" ]]; then
        (cd "$dir" && go build -o "$(basename $dir)" main.go) && echo "  ✓ $dir" || echo "  ✗ $dir (build failed)"
    else
        echo "  - $dir (skipped — not found)"
    fi
}

build_go scraper
build_go predictor
build_go stealth_proxy
build_go network_mapper
build_go smuggler
build_go dirbuster

# ── Rust binaries ─────────────────────────────────────────────────────────────
echo ""
echo "🔨 Building Rust binaries..."

build_rust() {
    local dir=$1
    if [[ -d "$dir" && -f "$dir/Cargo.toml" ]]; then
        (cd "$dir" && cargo build --release -q) && echo "  ✓ $dir" || echo "  ✗ $dir (build failed)"
    else
        echo "  - $dir (skipped — not found)"
    fi
}

build_rust analyzer
build_rust media_analyzer
build_rust fuzzer

# ── Chromium check ────────────────────────────────────────────────────────────
echo ""
CHROMIUM_BIN=$(command -v chromium || command -v chromium-browser || echo "")
if [[ -n "$CHROMIUM_BIN" ]]; then
    echo "✓ Chromium found: $CHROMIUM_BIN"
else
    echo "⚠  Chromium not found — screenshot feature will be disabled"
    echo "   Install with: sudo apt install chromium"
fi

# ── Directory structure ───────────────────────────────────────────────────────
echo ""
echo "📁 Creating directories..."
mkdir -p reports screenshots investigations evidence logs models models/ml_engine config
chmod +x main.py setup.sh 2>/dev/null || true

# ── Global sentinel command ──────────────────────────────────────────────────────
echo ""
echo "🔗 Setting up 'sentinel' command..."
mkdir -p "$HOME/.local/bin"
ln -sf "$(pwd)/sentinel" "$HOME/.local/bin/sentinel"
if ! grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi
if ! grep -q '.local/bin' "$HOME/.zshrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
fi
echo "  ✓ 'sentinel' command installed"
echo "  Run: source ~/.bashrc  (or open new terminal)"

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
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅  The Sentinel Pro — Setup Complete               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "🚀 Quick Start:"
echo "   source venv/bin/activate"
echo "   python3 main.py"
echo ""
echo "⚡ Direct CLI:"
echo "   python3 main.py --bugbounty example.com"
echo "   python3 main.py --recon example.com"
echo "   python3 main.py --breach user@example.com"
echo "   python3 main.py --email user@example.com"
echo "   python3 main.py --scan-all example.com"
echo "   python3 main.py --help"
echo ""
echo "🔑 API Keys (optional — edit .env):"
echo "   SHODAN_API_KEY        → Shodan host intelligence"
echo "   GITHUB_TOKEN          → GitHub code dorking"
echo "   SERPAPI_KEY           → Google dork auto-execute"
echo "   SECURITYTRAILS_API_KEY → DNS history"
echo "   NVD_API_KEY           → CVE lookup (higher rate limit)"
echo ""
echo "🧠 ML Engine (no API key needed):"
echo "   person <name>         → Entity matching + DBSCAN clustering"
echo "   nlp <text>            → NLP profiling + writing fingerprint"
echo "   nlp session           → Analyze collected session data"
echo ""
echo "📄 See README.md for full documentation"
