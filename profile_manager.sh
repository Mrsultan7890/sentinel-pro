#!/bin/bash

# Sentinel Pro Profile Manager

PROFILES_FILE="config_profiles.json"
OUTPUT_FILE="output_formats.json"

show_profiles() {
    echo "🎯 Available Profiles:"
    echo "1. stealth    - Maximum stealth (slow, Tor enabled)"
    echo "2. fast       - Fast scanning (quick, no Tor)"
    echo "3. balanced   - Balanced speed/stealth"
    echo "4. monitoring - 24/7 monitoring optimized"
}

show_outputs() {
    echo "📊 Available Output Formats:"
    echo "1. minimal    - Only critical findings"
    echo "2. standard   - Balanced detail"
    echo "3. detailed   - Complete information"
    echo "4. legal      - Court-ready format"
}

set_profile() {
    case $1 in
        "stealth")
            export OSINT_MIN_DELAY=5.0
            export OSINT_MAX_DELAY=10.0
            export OSINT_RATE_LIMIT=5
            export TOR_ENABLED=true
            echo "✅ Stealth profile activated"
            ;;
        "fast")
            export OSINT_MIN_DELAY=0.5
            export OSINT_MAX_DELAY=2.0
            export OSINT_RATE_LIMIT=20
            export TOR_ENABLED=false
            echo "✅ Fast profile activated"
            ;;
        "balanced")
            export OSINT_MIN_DELAY=2.0
            export OSINT_MAX_DELAY=5.0
            export OSINT_RATE_LIMIT=10
            export TOR_ENABLED=false
            echo "✅ Balanced profile activated"
            ;;
        "monitoring")
            export OSINT_MIN_DELAY=3.0
            export OSINT_MAX_DELAY=7.0
            export OSINT_RATE_LIMIT=8
            export TOR_ENABLED=true
            echo "✅ Monitoring profile activated"
            ;;
        *)
            echo "❌ Unknown profile: $1"
            show_profiles
            ;;
    esac
}

case $1 in
    "list")
        show_profiles
        echo ""
        show_outputs
        ;;
    "set")
        set_profile $2
        ;;
    "current")
        echo "Current settings:"
        echo "MIN_DELAY: ${OSINT_MIN_DELAY:-2.0}"
        echo "MAX_DELAY: ${OSINT_MAX_DELAY:-5.0}"
        echo "RATE_LIMIT: ${OSINT_RATE_LIMIT:-10}"
        echo "TOR: ${TOR_ENABLED:-false}"
        ;;
    *)
        echo "Usage: $0 {list|set <profile>|current}"
        echo "Example: $0 set stealth"
        ;;
esac