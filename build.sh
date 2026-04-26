#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  The Sentinel Pro v3.0 — Build Script
#  Usage: bash build.sh
#  Output: dist/sentinel_v3.0_linux.zip
# ═══════════════════════════════════════════════════════════════
set -e

VERSION="3.0"
OUT_DIR="dist/sentinel_v${VERSION}"

echo "🛡️  The Sentinel Pro v${VERSION} — Build"
echo "======================================="

# ── 1. Build Go binaries ──────────────────────────────────────
echo ""
echo "🔨 Building Go binaries..."
for dir in scraper dirbuster network_mapper predictor smuggler stealth_proxy; do
    if [ -f "$dir/main.go" ]; then
        (cd "$dir" && go build -ldflags="-s -w" -o "$dir" . 2>/dev/null) \
            && echo "  ✓ $dir" || echo "  ✗ $dir (failed)"
    fi
done

# ── 2. Build Rust binaries ────────────────────────────────────
echo ""
echo "🔨 Building Rust binaries..."
for dir in analyzer fuzzer media_analyzer sentinel_proxy/rust_core sentinel_proxy/rust_fuzzer; do
    if [ -f "$dir/Cargo.toml" ]; then
        (cd "$dir" && cargo build --release -q 2>/dev/null) \
            && echo "  ✓ $dir" || echo "  ✗ $dir (failed)"
    fi
done

# ── 3. PyInstaller ────────────────────────────────────────────
echo ""
echo "🐍 Building Python binary (PyInstaller)..."
source venv/bin/activate 2>/dev/null || true
pip install pyinstaller -q
pyinstaller sentinel.spec --clean --noconfirm
echo "  ✓ Python binary built"

# ── 4. Package everything ─────────────────────────────────────
echo ""
echo "📦 Packaging..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Python binary
cp -r dist/sentinel/* "$OUT_DIR/"

# Go binaries
for bin in scraper/scraper dirbuster/dirbuster network_mapper/network_mapper \
           predictor/predictor smuggler/smuggler stealth_proxy/stealth_proxy; do
    [ -f "$bin" ] && cp "$bin" "$OUT_DIR/" && echo "  ✓ $(basename $bin)"
done

# Rust binaries
for bin in analyzer/target/release/analyzer \
           fuzzer/target/release/fuzzer \
           media_analyzer/target/release/media_analyzer \
           sentinel_proxy/rust_core/target/release/sentinel_proxy_core \
           sentinel_proxy/rust_fuzzer/target/release/sentinel_fuzzer; do
    [ -f "$bin" ] && cp "$bin" "$OUT_DIR/" && echo "  ✓ $(basename $bin)"
done

# .env.example + README
cp .env.example "$OUT_DIR/"
cp README.md "$OUT_DIR/"

# Make binary executable
chmod +x "$OUT_DIR/sentinel"

# ── 5. Create ZIP ─────────────────────────────────────────────
echo ""
echo "🗜️  Creating ZIP..."
cd dist
zip -r "sentinel_v${VERSION}_linux.zip" "sentinel_v${VERSION}/" -q
cd ..

SIZE=$(du -sh "dist/sentinel_v${VERSION}_linux.zip" | cut -f1)
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅  Build Complete                                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Output : dist/sentinel_v${VERSION}_linux.zip  ($SIZE)"
echo ""
echo "  User instructions:"
echo "  1. unzip sentinel_v${VERSION}_linux.zip"
echo "  2. cd sentinel_v${VERSION}"
echo "  3. ./sentinel"
echo "  4. sentinel-pro> cred add GROQ_API_KEY your_key"
