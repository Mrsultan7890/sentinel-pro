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
Privilege Manager - Handle sudo/root access for security tools
Secure password management with multiple authentication methods
"""

import os
import sys
import subprocess
import getpass
import logging
from pathlib import Path
from typing import Optional, Dict, List
import threading
import time

# keyring — optional, graceful fallback to in-memory storage
try:
    import keyring as _keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _keyring = None
    _KEYRING_AVAILABLE = False

logger = logging.getLogger(__name__)

class PrivilegeManager:
    """
    Secure privilege escalation manager for security tools.
    
    Features:
    - Secure password storage (keyring)
    - Multiple auth methods (password, key, token)
    - Session caching
    - Tool-specific privilege requirements
    - Audit logging
    """
    
    def __init__(self):
        self.service_name = "sentinel-pro"
        self.username = os.getenv('USER', 'kali')
        self._sudo_cache = {}
        self._cache_timeout = 900  # 15 minutes
        self._lock = threading.Lock()
        
        # Tools that require root/sudo
        self.privileged_tools = {
            # Network tools
            'nmap': {'reason': 'SYN scan, OS detection', 'level': 'sudo'},
            'masscan': {'reason': 'Raw socket access', 'level': 'sudo'},
            'hping3': {'reason': 'Raw packet crafting', 'level': 'sudo'},
            'tcpdump': {'reason': 'Network capture', 'level': 'sudo'},
            'wireshark': {'reason': 'Network analysis', 'level': 'sudo'},
            
            # Password tools
            'john': {'reason': 'Password cracking', 'level': 'sudo'},
            'hashcat': {'reason': 'GPU password cracking', 'level': 'sudo'},
            'hydra': {'reason': 'Brute force attacks', 'level': 'sudo'},
            'medusa': {'reason': 'Parallel brute force', 'level': 'sudo'},
            
            # Forensics tools
            'volatility': {'reason': 'Memory analysis', 'level': 'sudo'},
            'autopsy': {'reason': 'Disk forensics', 'level': 'sudo'},
            'sleuthkit': {'reason': 'File system analysis', 'level': 'sudo'},
            'foremost': {'reason': 'File carving', 'level': 'sudo'},
            'binwalk': {'reason': 'Firmware analysis', 'level': 'sudo'},
            'dd': {'reason': 'Disk imaging', 'level': 'sudo'},
            
            # Metasploit
            'msfconsole': {'reason': 'Exploit framework', 'level': 'sudo'},
            'msfvenom': {'reason': 'Payload generation', 'level': 'sudo'},
            'msfdb': {'reason': 'Database operations', 'level': 'sudo'},
            
            # System tools
            'aircrack-ng': {'reason': 'WiFi security', 'level': 'sudo'},
            'airmon-ng': {'reason': 'Monitor mode', 'level': 'sudo'},
            'reaver': {'reason': 'WPS attacks', 'level': 'sudo'},
            'ettercap': {'reason': 'MITM attacks', 'level': 'sudo'},
        }
    
    def setup_keyring(self) -> bool:
        """Setup secure keyring for password storage."""
        if not _KEYRING_AVAILABLE:
            return False
        try:
            _keyring.get_password(self.service_name, "test")
            return True
        except Exception as e:
            logger.warning(f"Keyring setup failed: {e}")
            return False
    
    def store_password(self, password: str) -> bool:
        """Store sudo password securely in keyring."""
        if not _KEYRING_AVAILABLE:
            # Fallback: in-memory only
            self._memory_password = password
            return True
        try:
            _keyring.set_password(self.service_name, self.username, password)
            logger.info("Password stored securely in keyring")
            return True
        except Exception as e:
            logger.error(f"Failed to store password: {e}")
            return False
    
    def get_stored_password(self) -> Optional[str]:
        """Retrieve stored password from keyring."""
        if not _KEYRING_AVAILABLE:
            return getattr(self, '_memory_password', None)
        try:
            return _keyring.get_password(self.service_name, self.username)
        except Exception as e:
            logger.debug(f"Failed to retrieve password: {e}")
            return None
    
    def prompt_password(self, tool: str, reason: str) -> Optional[str]:
        """Prompt user for sudo password with context."""
        try:
            print(f"\n🔐 Tool '{tool}' requires sudo access")
            print(f"   Reason: {reason}")
            print(f"   User: {self.username}")
            
            password = getpass.getpass("Enter sudo password: ")
            
            # Test password
            if self._test_sudo_password(password):
                # Ask if user wants to store it
                store = input("Store password securely? (y/N): ").lower().startswith('y')
                if store:
                    self.store_password(password)
                return password
            else:
                print("❌ Invalid password")
                return None
                
        except KeyboardInterrupt:
            print("\n❌ Password prompt cancelled")
            return None
        except Exception as e:
            logger.error(f"Password prompt error: {e}")
            return None
    
    def _test_sudo_password(self, password: str) -> bool:
        """Test if sudo password is valid."""
        try:
            process = subprocess.Popen(
                ['sudo', '-S', 'true'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=password + '\n', timeout=10)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning("Sudo password test timed out")
            return False
        except Exception as e:
            logger.debug(f"Sudo password test failed: {e}")
            return False
    
    def get_sudo_password(self, tool: str) -> Optional[str]:
        """Get sudo password for tool (cached or prompt)."""
        with self._lock:
            # Check cache first
            if tool in self._sudo_cache:
                cached_time, cached_password = self._sudo_cache[tool]
                if time.time() - cached_time < self._cache_timeout:
                    return cached_password
                else:
                    del self._sudo_cache[tool]
            
            # Try stored password
            stored_password = self.get_stored_password()
            if stored_password and self._test_sudo_password(stored_password):
                self._sudo_cache[tool] = (time.time(), stored_password)
                return stored_password
            
            # Prompt for password
            if tool in self.privileged_tools:
                reason = self.privileged_tools[tool]['reason']
                password = self.prompt_password(tool, reason)
                if password:
                    self._sudo_cache[tool] = (time.time(), password)
                    return password
            
            return None
    
    def needs_privilege(self, tool: str) -> bool:
        """Check if tool needs privilege escalation."""
        return tool in self.privileged_tools
    
    def get_privilege_level(self, tool: str) -> str:
        """Get required privilege level for tool."""
        if tool in self.privileged_tools:
            return self.privileged_tools[tool]['level']
        return 'user'
    
    def execute_privileged(self, command: List[str], tool: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """Execute command with privilege escalation if needed."""
        if not self.needs_privilege(tool):
            # No privilege needed
            return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        
        # Get sudo password
        password = self.get_sudo_password(tool)
        if not password:
            raise PermissionError(f"Cannot obtain sudo access for {tool}")
        
        # Execute with sudo
        sudo_command = ['sudo', '-S'] + command
        
        try:
            process = subprocess.Popen(
                sudo_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=password + '\n', timeout=timeout)
            
            # Log privileged execution
            logger.info(f"Privileged execution: {tool} - {' '.join(command[:3])}")
            
            return subprocess.CompletedProcess(
                sudo_command, process.returncode, stdout, stderr
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            raise TimeoutError(f"Privileged command timeout: {tool}")
    
    def clear_cache(self):
        """Clear password cache."""
        with self._lock:
            self._sudo_cache.clear()
            logger.info("Password cache cleared")
    
    def remove_stored_password(self):
        """Remove stored password from keyring."""
        if not _KEYRING_AVAILABLE:
            self._memory_password = None
            return True
        try:
            _keyring.delete_password(self.service_name, self.username)
            logger.info("Stored password removed")
            return True
        except Exception as e:
            logger.error(f"Failed to remove password: {e}")
            return False
    
    def status(self) -> Dict:
        """Get privilege manager status."""
        return {
            'keyring_available': _KEYRING_AVAILABLE and self.setup_keyring(),
            'stored_password': bool(self.get_stored_password()),
            'cached_tools': list(self._sudo_cache.keys()),
            'privileged_tools_count': len(self.privileged_tools),
            'username': self.username
        }

# Global instance
privilege_manager = PrivilegeManager()