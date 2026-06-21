#!/bin/bash
# Quick fix for persistent monitor service

echo "[*] Fixing Sentinel Monitor Service..."

# Stop service
sudo systemctl stop sentinel-monitor 2>/dev/null

# Update service file with correct log path
LOG_FILE="$HOME/.sentinel_monitor.log"

sudo tee /etc/systemd/system/sentinel-monitor.service > /dev/null << EOF
[Unit]
Description=Sentinel Pro 24/7 Monitoring Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/kali/osints
Environment=PYTHONPATH=/home/kali/osints
Environment=DISPLAY=:0
Environment=HOME=$HOME
ExecStart=/usr/bin/python3 /home/kali/osints/sentinel_brain/monitor_daemon.py
Restart=always
RestartSec=10
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Restart service
sudo systemctl restart sentinel-monitor

# Check status
sleep 2
if systemctl is-active --quiet sentinel-monitor; then
    echo "[✓] Service is now running!"
    systemctl status sentinel-monitor --no-pager -l
else
    echo "[!] Service failed to start"
    journalctl -u sentinel-monitor --no-pager -n 10
fi
