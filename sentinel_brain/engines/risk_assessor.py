"""
Risk Assessor - Determines isolation level for operations
"""
from enum import Enum
from typing import Dict, List
import re

class RiskLevel(Enum):
    LOW = 1       # Layer 1-2: Language safety + syscall filtering
    MEDIUM = 2    # Layer 1-3: + Process isolation
    HIGH = 3      # Layer 1-4: + Container isolation
    CRITICAL = 4  # Layer 1-5: + VM isolation

class RiskAssessor:
    # High-risk tools that need strong isolation
    CRITICAL_TOOLS = {
        'sqlmap', 'metasploit', 'msfconsole', 'msfvenom',
        'exploit', 'payload', 'shell', 'reverse_shell'
    }
    
    HIGH_RISK_TOOLS = {
        'nmap', 'nikto', 'nuclei', 'hydra', 'john',
        'hashcat', 'aircrack', 'wpscan', 'burpsuite'
    }
    
    MEDIUM_RISK_TOOLS = {
        'gobuster', 'ffuf', 'dirb', 'wfuzz', 'amass',
        'subfinder', 'sublist3r', 'whatweb', 'wafw00f'
    }
    
    # Dangerous command patterns
    DANGEROUS_PATTERNS = [
        r'rm\s+-rf',
        r'dd\s+if=',
        r'mkfs\.',
        r':(){ :|:& };:',  # Fork bomb
        r'chmod\s+777',
        r'chown\s+root',
        r'sudo\s+',
        r'/dev/(sd|hd|nvme)',
        r'iptables\s+',
        r'systemctl\s+(stop|disable)',
    ]
    
    # Network operations
    NETWORK_OPERATIONS = [
        r'curl\s+',
        r'wget\s+',
        r'nc\s+',
        r'netcat\s+',
        r'telnet\s+',
        r'ssh\s+',
        r'ftp\s+',
    ]
    
    def assess_command(self, command: str) -> RiskLevel:
        """Assess risk level of a command"""
        cmd_lower = command.lower()
        
        # Check for critical tools
        for tool in self.CRITICAL_TOOLS:
            if tool in cmd_lower:
                return RiskLevel.CRITICAL
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return RiskLevel.CRITICAL
        
        # Check for high-risk tools
        for tool in self.HIGH_RISK_TOOLS:
            if tool in cmd_lower:
                return RiskLevel.HIGH
        
        # Check for medium-risk tools
        for tool in self.MEDIUM_RISK_TOOLS:
            if tool in cmd_lower:
                return RiskLevel.MEDIUM
        
        # Check for network operations
        for pattern in self.NETWORK_OPERATIONS:
            if re.search(pattern, command, re.IGNORECASE):
                return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    def assess_file_operation(self, path: str, operation: str) -> RiskLevel:
        """Assess risk of file operations"""
        critical_paths = [
            '/etc/', '/boot/', '/sys/', '/proc/',
            '/dev/', '/root/', '/var/log/'
        ]
        
        high_risk_paths = [
            '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
            '/lib/', '/lib64/'
        ]
        
        if operation in ('write', 'delete', 'execute'):
            for cpath in critical_paths:
                if path.startswith(cpath):
                    return RiskLevel.CRITICAL
            
            for hpath in high_risk_paths:
                if path.startswith(hpath):
                    return RiskLevel.HIGH
        
        return RiskLevel.LOW
    
    def assess_network_operation(self, target: str, port: int = None) -> RiskLevel:
        """Assess risk of network operations"""
        # Internal/localhost = higher risk (SSRF potential)
        internal_patterns = [
            r'^127\.',
            r'^localhost$',
            r'^0\.0\.0\.0$',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^169\.254\.',
        ]
        
        for pattern in internal_patterns:
            if re.match(pattern, target):
                return RiskLevel.HIGH
        
        # Sensitive ports
        sensitive_ports = {22, 23, 3389, 5900, 3306, 5432, 27017, 6379}
        if port and port in sensitive_ports:
            return RiskLevel.HIGH
        
        return RiskLevel.MEDIUM
    
    def get_isolation_layers(self, risk: RiskLevel) -> List[str]:
        """Get required isolation layers for risk level"""
        layers = {
            RiskLevel.LOW: ['language_safety', 'syscall_filter'],
            RiskLevel.MEDIUM: ['language_safety', 'syscall_filter', 'process_isolation'],
            RiskLevel.HIGH: ['language_safety', 'syscall_filter', 'process_isolation', 'container'],
            RiskLevel.CRITICAL: ['language_safety', 'syscall_filter', 'process_isolation', 'container', 'vm'],
        }
        return layers.get(risk, layers[RiskLevel.LOW])
    
    def get_resource_limits(self, risk: RiskLevel) -> Dict:
        """Get resource limits based on risk"""
        limits = {
            RiskLevel.LOW: {
                'cpu_percent': 50,
                'memory_mb': 512,
                'disk_mb': 1024,
                'network_mbps': 10,
                'timeout_sec': 300,
            },
            RiskLevel.MEDIUM: {
                'cpu_percent': 30,
                'memory_mb': 256,
                'disk_mb': 512,
                'network_mbps': 5,
                'timeout_sec': 180,
            },
            RiskLevel.HIGH: {
                'cpu_percent': 20,
                'memory_mb': 128,
                'disk_mb': 256,
                'network_mbps': 2,
                'timeout_sec': 120,
            },
            RiskLevel.CRITICAL: {
                'cpu_percent': 10,
                'memory_mb': 64,
                'disk_mb': 128,
                'network_mbps': 1,
                'timeout_sec': 60,
            },
        }
        return limits.get(risk, limits[RiskLevel.LOW])
