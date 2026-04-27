#!/usr/bin/env python3
# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Sentinel Monitor Daemon — Background Service
Boot time pe automatically start hoti hai
"""

import os
import sys
import json
import time
import signal
import logging
from pathlib import Path
from datetime import datetime

# Add project to path
_base = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
sys.path.insert(0, str(_base))

import config
from sentinel_brain.monitor import SentinelMonitor
from sentinel_brain.brain import SentinelBrain

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/sentinel-monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MonitorDaemon:
    def __init__(self):
        self.config_file = Path.home() / '.sentinel_monitor_config.json'
        self.running = True
        self.monitor = None
        
        # Signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.monitor:
            self.monitor.stop()
    
    def load_config(self) -> dict:
        """Saved configuration load karo."""
        if not self.config_file.exists():
            return {'targets': [], 'interval': 3600, 'tor_enabled': False}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Config load error: {e}")
            return {'targets': [], 'interval': 3600, 'tor_enabled': False}
    
    def run(self):
        """Main daemon loop."""
        logger.info("Sentinel Monitor Daemon starting...")
        
        while self.running:
            try:
                # Load configuration
                config_data = self.load_config()
                targets = config_data.get('targets', [])
                interval = config_data.get('interval', 3600)
                tor_enabled = config_data.get('tor_enabled', False)
                
                if not targets:
                    logger.info("No targets configured, waiting...")
                    time.sleep(60)
                    continue
                
                # Setup Tor if enabled
                if tor_enabled:
                    config.tor_on()
                    logger.info("Tor enabled for monitoring")
                else:
                    config.tor_off()
                
                # Create brain and monitor
                brain = SentinelBrain(console=logger.info)
                self.monitor = SentinelMonitor(brain, interval=interval)
                
                # Add targets
                for target_info in targets:
                    target = target_info.get('target', '')
                    mode = target_info.get('mode', 'full')
                    if target:
                        self.monitor.add_target(target, mode)
                        logger.info(f"Added target: {target} (mode: {mode})")
                
                # Start monitoring
                self.monitor.start()
                logger.info(f"Monitoring started - {len(targets)} targets, interval: {interval}s")
                
                # Keep running until config changes or shutdown
                last_config_check = time.time()
                while self.running and self.monitor.is_running():
                    time.sleep(30)  # Check every 30 seconds
                    
                    # Check for config changes every 5 minutes
                    if time.time() - last_config_check > 300:
                        new_config = self.load_config()
                        if new_config != config_data:
                            logger.info("Configuration changed, restarting monitor...")
                            self.monitor.stop()
                            break
                        last_config_check = time.time()
                
                if self.monitor:
                    self.monitor.stop()
                    
            except Exception as e:
                logger.error(f"Daemon error: {e}")
                time.sleep(60)  # Wait before retry
        
        logger.info("Sentinel Monitor Daemon stopped")

if __name__ == '__main__':
    daemon = MonitorDaemon()
    daemon.run()
