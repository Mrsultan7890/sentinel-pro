#!/bin/bash

echo "🔧 Sentinel Pro Configuration Setup"

# Create .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file"
fi

# Set executable permissions
chmod +x sentinel
echo "✅ Made sentinel executable"

# Create necessary directories
mkdir -p targets reports investigations evidence logs screenshots
echo "✅ Created directories"

# Check binaries
echo "🔍 Checking binaries..."
for binary in scraper/scraper analyzer/target/release/analyzer fuzzer/target/release/fuzzer; do
    if [ -f "$binary" ]; then
        echo "✅ $binary found"
    else
        echo "❌ $binary missing"
    fi
done

echo "🎯 Configuration complete!"
echo "Edit .env file for API keys"
echo "Edit targets/*.txt files for your targets"