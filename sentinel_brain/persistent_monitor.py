"""
Persistent Monitor — 24/7 System Service
Laptop restart ke baad bhi automatically chalu ho jata hai
Author: @who_is_the_black_hat
"""

import os
import sys
import json
import time
import logging
import subprocess
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class PersistentMonitor:
    """
    System service banata hai jo boot time pe automatically start hoti hai.
    Laptop restart ke baad bhi monitoring continue rehti hai.
    """
    
    def __init__(self):
        self.config_file = Path.home() / '.sentinel_monitor_config.json'
        self.service_name = 'sentinel-monitor'
        self.service_file = f'/etc/systemd/system/{self.service_name}.service'
        self.script_path = Path(__file__).parent / 'monitor_daemon.py'
        
    def install_service(self) -> bool:
        """System service install karo jo boot time pe start hogi."""
        try:
            # Service file content
            service_content = f"""[Unit]
Description=Sentinel Pro 24/7 Monitoring Service
After=network.target
Wants=network.target

[Service]
Type=simple
User={os.getenv('USER', 'kali')}
WorkingDirectory={Path(__file__).parent.parent}
Environment=PYTHONPATH={Path(__file__).parent.parent}
Environment=DISPLAY=:0
ExecStart=/usr/bin/python3 {self.script_path}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
            
            # Create daemon script
            self._create_daemon_script()
            
            # Write service file (requires sudo)
            print(f"[Persistent] Installing system service...")
            print(f"[Persistent] This requires sudo access...")
            
            # Write service file
            cmd1 = f"echo '{service_content}' | sudo tee {self.service_file}"
            result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
            
            if result1.returncode != 0:
                logger.error(f"Failed to create service file: {result1.stderr}")
                return False
            
            # Reload systemd and enable service
            commands = [
                "sudo systemctl daemon-reload",
                f"sudo systemctl enable {self.service_name}",
                f"sudo systemctl start {self.service_name}"
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error(f"Command failed: {cmd} - {result.stderr}")
                    return False
            
            print(f"[Persistent] ✅ Service installed successfully!")
            print(f"[Persistent] Service will start automatically on boot")
            print(f"[Persistent] Check status: sudo systemctl status {self.service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Service installation failed: {e}")
            return False
    
    def uninstall_service(self) -> bool:
        """System service remove karo."""
        try:
            commands = [
                f"sudo systemctl stop {self.service_name}",
                f"sudo systemctl disable {self.service_name}",
                f"sudo rm -f {self.service_file}",
                "sudo systemctl daemon-reload"
            ]
            
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Remove daemon script
            if self.script_path.exists():
                self.script_path.unlink()
            
            print(f"[Persistent] ✅ Service uninstalled successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Service uninstall failed: {e}")
            return False
    
    def _create_daemon_script(self):
        """Background daemon script banao."""
        daemon_content = '''#!/usr/bin/env python3
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
sys.path.insert(0, str(Path(__file__).parent.parent))

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
'''
        
        # Write daemon script
        with open(self.script_path, 'w') as f:
            f.write(daemon_content)
        
        # Make executable
        os.chmod(self.script_path, 0o755)
    
    def save_config(self, targets: list, interval: int, tor_enabled: bool):
        """Configuration save karo jo daemon use karega."""
        config_data = {
            'targets': targets,
            'interval': interval,
            'tor_enabled': tor_enabled,
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            logger.info(f"Configuration saved: {len(targets)} targets")
            return True
        except Exception as e:
            logger.error(f"Config save error: {e}")
            return False
    
    def get_service_status(self) -> dict:
        """Service status check karo."""
        try:
            result = subprocess.run(
                f"systemctl is-active {self.service_name}",
                shell=True, capture_output=True, text=True
            )
            active = result.stdout.strip() == 'active'
            
            result2 = subprocess.run(
                f"systemctl is-enabled {self.service_name}",
                shell=True, capture_output=True, text=True
            )
            enabled = result2.stdout.strip() == 'enabled'
            
            # Get logs
            result3 = subprocess.run(
                f"journalctl -u {self.service_name} --no-pager -n 5",
                shell=True, capture_output=True, text=True
            )
            logs = result3.stdout.strip()
            
            return {
                'installed': Path(self.service_file).exists(),
                'active': active,
                'enabled': enabled,
                'logs': logs
            }
        except Exception as e:
            logger.error(f"Status check error: {e}")
            return {'installed': False, 'active': False, 'enabled': False, 'logs': ''}
    
    def restart_service(self) -> bool:
        """Service restart karo."""
        try:
            result = subprocess.run(
                f"sudo systemctl restart {self.service_name}",
                shell=True, capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Service restart error: {e}")
            return False