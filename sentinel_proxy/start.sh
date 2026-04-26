#!/bin/bash
# SentinelProxy v2.0 — Clean restart
echo "[*] Killing stale proxy processes..."
kill -9 $(lsof -t -i:8082) 2>/dev/null
sleep 0.5
echo "[*] Starting SentinelProxy..."
cd /home/kali/osints/sentinel_proxy
python3 main.py
