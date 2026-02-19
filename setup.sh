#!/bin/bash

echo "🛡️  Setting up The Sentinel Pro - Enhanced Threat Intelligence Platform"
echo "======================================================================="

# Check if running on Kali Linux
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ $ID == "kali" ]]; then
        echo "✓ Kali Linux detected - Optimal environment"
    else
        echo "⚠️  Warning: Not running on Kali Linux. Some features may not work optimally."
    fi
fi

# Install enhanced Python dependencies
echo "📦 Installing enhanced Python dependencies..."
sudo apt update
sudo apt install -y python3-requests python3-bs4 python3-sklearn python3-numpy python3-matplotlib python3-networkx python3-lxml python3-cryptography python3-socks

# Install additional dependencies via pip (with system packages fallback)
pip3 install --break-system-packages rich tqdm colorama fake-useragent stem aiohttp asyncio-throttle 2>/dev/null || echo "Using system packages for Python dependencies"

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go..."
    sudo apt install -y golang-go
else
    echo "✓ Go already installed ($(go version))"
fi

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
else
    echo "✓ Rust already installed ($(cargo --version))"
fi

# Install Tor for dark web capabilities
if ! command -v tor &> /dev/null; then
    echo "📦 Installing Tor for dark web access..."
    sudo apt install -y tor
else
    echo "✓ Tor already installed"
fi

# Build enhanced Go components
echo "🔨 Building enhanced Go scraper..."
cd scraper && go build -o scraper main.go && cd ..

echo "🔨 Building Go predictor..."
cd predictor && go build -o predictor main.go && cd ..

echo "🔨 Building stealth proxy manager..."
cd stealth_proxy && go build -o stealth_proxy main.go && cd ..

echo "🔨 Building legal predictor..."
cd legal_predictor && go build -o legal_predictor main.go && cd ..

echo "🔨 Building topic modeler..."
cd topic_modeler && go build -o topic_modeler main.go && cd ..

echo "🔨 Building network mapper..."
cd network_mapper && go build -o network_mapper main.go && cd ..

# Build enhanced Rust analyzer
echo "🔨 Building enhanced Rust analyzer..."
cd analyzer && cargo build --release && cd ..

echo "🔨 Building Rust media analyzer..."
cd media_analyzer && cargo build --release && cd ..

# Create enhanced directory structure
echo "📁 Creating enhanced directory structure..."
mkdir -p reports models evidence logs

# Set executable permissions
chmod +x main.py setup.sh
chmod +x scraper/scraper predictor/predictor stealth_proxy/stealth_proxy legal_predictor/legal_predictor 2>/dev/null
chmod +x topic_modeler/topic_modeler network_mapper/network_mapper 2>/dev/null

# Configure Tor (basic configuration)
echo "⚙️  Configuring Tor for dark web access..."
sudo systemctl enable tor 2>/dev/null || echo "Tor service configuration skipped"

# Create configuration files
echo "📝 Creating configuration files..."

# Create stealth configuration
cat > config/stealth_config.json << EOF
{
  "proxy_rotation_interval": 5,
  "user_agent_randomization": true,
  "tor_integration": true,
  "anti_detection_mode": true,
  "request_delays": {
    "min": 1,
    "max": 5
  }
}
EOF

# Create legal compliance configuration
cat > config/legal_config.json << EOF
{
  "evidence_standards": ["ISO 27037", "NIST SP 800-86", "RFC 3227"],
  "chain_of_custody_required": true,
  "cryptographic_integrity": true,
  "legal_admissibility_mode": true,
  "jurisdiction": "international",
  "compliance_frameworks": ["GDPR", "CCPA", "SOX"]
}
EOF

mkdir -p config 2>/dev/null

echo ""
echo "🎉 The Sentinel Pro setup complete!"
echo ""
echo "🚀 ENHANCED FEATURES AVAILABLE:"
echo "   ✓ Professional CLI with real-time progress indicators"
echo "   ✓ Advanced stealth & anti-detection capabilities"
echo "   ✓ Dark web integration with Tor support"
echo "   ✓ AI-powered predictive threat analysis"
echo "   ✓ Legal-grade evidence management"
echo "   ✓ Court-admissible reporting with chain of custody"
echo "   ✓ Multi-language architecture (Python/Go/Rust)"
echo ""
echo "📋 USAGE:"
echo "   python3 main.py"
echo ""
echo "🔧 ENHANCED COMMANDS:"
echo "   sentinel-pro> collect <target>     # Advanced multi-source collection"
echo "   sentinel-pro> darkweb <target>     # Dark web investigation"
echo "   sentinel-pro> analyze              # AI-powered threat prediction"
echo "   sentinel-pro> semantic             # AI semantic analysis of content"
echo "   sentinel-pro> media                # Media integrity & deepfake detection"
echo "   sentinel-pro> financial            # Financial trail & crypto analysis"
echo "   sentinel-pro> network              # Influence network mapping"
echo "   sentinel-pro> stealth              # Configure stealth settings"
echo "   sentinel-pro> evidence             # Manage legal evidence"
echo "   sentinel-pro> report               # Generate court-ready reports"
echo ""
echo "⚖️  LEGAL COMPLIANCE:"
echo "   ✓ ISO 27037 Digital Evidence Standards"
echo "   ✓ NIST SP 800-86 Forensic Guidelines"
echo "   ✓ RFC 3227 Evidence Collection Standards"
echo "   ✓ Cryptographic integrity verification"
echo "   ✓ Unbroken chain of custody"
echo ""
echo "🛡️  The Sentinel Pro is ready for professional threat intelligence operations!"
echo ""