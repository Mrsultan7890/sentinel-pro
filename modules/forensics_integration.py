"""
Forensics Tools Integration - Digital Investigation Suite
Memory analysis, disk forensics, file carving, and evidence collection
"""

import os
import json
import subprocess
import tempfile
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class ForensicsToolkit:
    """
    Complete digital forensics toolkit integration.
    
    Features:
    - Memory analysis (Volatility)
    - Disk forensics (Sleuthkit, Autopsy)
    - File carving (Foremost, Scalpel)
    - Network forensics (Wireshark, tcpdump)
    - Mobile forensics (Android/iOS)
    - Malware analysis (YARA, strings)
    """
    
    def __init__(self):
        import config as _cfg
        self.evidence_dir = _cfg.EVIDENCE_DIR / 'forensics_cases'
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Forensics tools configuration
        self.tools = {
            'volatility': {
                'binary': 'volatility',
                'version_cmd': ['volatility', '--info'],
                'profiles': ['Win7SP1x64', 'Win10x64', 'LinuxUbuntu1604x64']
            },
            'sleuthkit': {
                'binary': 'fls',
                'tools': ['fls', 'icat', 'mmls', 'fsstat', 'blkstat']
            },
            'autopsy': {
                'binary': 'autopsy',
                'port': 9999
            },
            'foremost': {
                'binary': 'foremost',
                'config': '/etc/foremost.conf'
            },
            'scalpel': {
                'binary': 'scalpel',
                'config': '/etc/scalpel/scalpel.conf'
            },
            'binwalk': {
                'binary': 'binwalk',
                'extract_dir': '/tmp/binwalk_extracted'
            },
            'wireshark': {
                'binary': 'tshark',
                'gui': 'wireshark'
            },
            'yara': {
                'binary': 'yara',
                'rules_dir': '/usr/share/yara-rules'
            }
        }
        
        # Common file signatures for carving
        self.file_signatures = {
            'images': ['jpg', 'png', 'gif', 'bmp', 'tiff'],
            'documents': ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt'],
            'archives': ['zip', 'rar', '7z', 'tar', 'gz'],
            'executables': ['exe', 'dll', 'so', 'elf'],
            'media': ['mp3', 'mp4', 'avi', 'wav', 'mov']
        }
    
    def check_tool_availability(self) -> Dict:
        """Check which forensics tools are available."""
        availability = {}
        
        for tool_name, config in self.tools.items():
            binary = config['binary']
            try:
                result = subprocess.run(['which', binary], capture_output=True, text=True)
                availability[tool_name] = {
                    'available': result.returncode == 0,
                    'path': result.stdout.strip() if result.returncode == 0 else None
                }
            except Exception:
                availability[tool_name] = {'available': False, 'path': None}
        
        return availability
    
    def create_evidence_case(self, case_name: str, description: str = "") -> Dict:
        """Create new forensics case directory structure."""
        try:
            case_dir = self.evidence_dir / case_name
            case_dir.mkdir(exist_ok=True)
            
            # Create standard forensics directory structure
            subdirs = [
                'images',      # Disk/memory images
                'carved',      # Carved files
                'extracted',   # Extracted data
                'reports',     # Analysis reports
                'logs',        # Tool logs
                'timeline',    # Timeline analysis
                'network',     # Network captures
                'malware'      # Malware samples
            ]
            
            for subdir in subdirs:
                (case_dir / subdir).mkdir(exist_ok=True)
            
            # Create case metadata
            metadata = {
                'case_name': case_name,
                'description': description,
                'created': datetime.now().isoformat(),
                'investigator': os.getenv('USER', 'unknown'),
                'evidence_items': [],
                'chain_of_custody': []
            }
            
            with open(case_dir / 'case_metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                'success': True,
                'case_dir': str(case_dir),
                'case_name': case_name,
                'subdirs': subdirs
            }
            
        except Exception as e:
            logger.error(f"Case creation error: {e}")
            return {'success': False, 'error': str(e)}
    
    def add_evidence_item(self, case_name: str, evidence_path: str, 
                         evidence_type: str, description: str = "") -> Dict:
        """Add evidence item to case with chain of custody."""
        try:
            case_dir = self.evidence_dir / case_name
            if not case_dir.exists():
                return {'success': False, 'error': 'Case does not exist'}
            
            evidence_file = Path(evidence_path)
            if not evidence_file.exists():
                return {'success': False, 'error': 'Evidence file does not exist'}
            
            # Calculate hashes
            md5_hash = self._calculate_hash(evidence_path, 'md5')
            sha256_hash = self._calculate_hash(evidence_path, 'sha256')
            
            # Copy evidence to case directory
            evidence_name = f"{evidence_type}_{evidence_file.name}"
            dest_path = case_dir / 'images' / evidence_name
            shutil.copy2(evidence_path, dest_path)
            
            # Update case metadata
            metadata_file = case_dir / 'case_metadata.json'
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            evidence_item = {
                'id': len(metadata['evidence_items']) + 1,
                'original_path': evidence_path,
                'case_path': str(dest_path),
                'type': evidence_type,
                'description': description,
                'size': evidence_file.stat().st_size,
                'md5': md5_hash,
                'sha256': sha256_hash,
                'added': datetime.now().isoformat(),
                'added_by': os.getenv('USER', 'unknown')
            }
            
            metadata['evidence_items'].append(evidence_item)
            metadata['chain_of_custody'].append({
                'action': 'evidence_added',
                'item_id': evidence_item['id'],
                'timestamp': datetime.now().isoformat(),
                'user': os.getenv('USER', 'unknown'),
                'details': f"Added {evidence_type}: {evidence_file.name}"
            })
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                'success': True,
                'evidence_id': evidence_item['id'],
                'md5': md5_hash,
                'sha256': sha256_hash,
                'case_path': str(dest_path)
            }
            
        except Exception as e:
            logger.error(f"Evidence addition error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _calculate_hash(self, file_path: str, algorithm: str) -> str:
        """Calculate file hash."""
        hash_func = hashlib.md5() if algorithm == 'md5' else hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def analyze_memory_dump(self, case_name: str, dump_path: str, profile: str = None) -> Dict:
        """Analyze memory dump using Volatility."""
        try:
            from modules.privilege_manager import privilege_manager
            
            case_dir = self.evidence_dir / case_name
            output_dir = case_dir / 'extracted' / 'memory_analysis'
            output_dir.mkdir(exist_ok=True)
            
            # Auto-detect profile if not provided
            if not profile:
                profile = self._detect_memory_profile(dump_path)
            
            if not profile:
                return {'success': False, 'error': 'Could not detect memory profile'}
            
            # Run common Volatility plugins
            plugins = [
                'imageinfo',
                'pslist',
                'psscan',
                'connections',
                'connscan',
                'sockets',
                'netscan',
                'filescan',
                'cmdline',
                'consoles',
                'hivelist',
                'hashdump'
            ]
            
            results = {}
            
            for plugin in plugins:
                try:
                    output_file = output_dir / f"{plugin}_output.txt"
                    
                    cmd = [
                        'volatility',
                        '-f', dump_path,
                        '--profile', profile,
                        plugin
                    ]
                    
                    result = privilege_manager.execute_privileged(
                        cmd, 'volatility', timeout=300
                    )
                    
                    if result.returncode == 0:
                        with open(output_file, 'w') as f:
                            f.write(result.stdout)
                        
                        results[plugin] = {
                            'success': True,
                            'output_file': str(output_file),
                            'summary': self._summarize_volatility_output(plugin, result.stdout)
                        }
                    else:
                        results[plugin] = {
                            'success': False,
                            'error': result.stderr
                        }
                        
                except Exception as e:
                    results[plugin] = {
                        'success': False,
                        'error': str(e)
                    }
            
            return {
                'success': True,
                'profile': profile,
                'output_dir': str(output_dir),
                'plugins': results,
                'case_name': case_name
            }
            
        except Exception as e:
            logger.error(f"Memory analysis error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _detect_memory_profile(self, dump_path: str) -> Optional[str]:
        """Auto-detect memory dump profile."""
        try:
            from modules.privilege_manager import privilege_manager
            
            result = privilege_manager.execute_privileged(
                ['volatility', '-f', dump_path, 'imageinfo'], 'volatility', timeout=60
            )
            
            if result.returncode == 0:
                # Parse suggested profiles
                for line in result.stdout.split('\n'):
                    if 'Suggested Profile(s)' in line:
                        profiles = line.split(':')[1].strip().split(',')
                        return profiles[0].strip()
            
            return None
            
        except Exception:
            return None
    
    def _summarize_volatility_output(self, plugin: str, output: str) -> Dict:
        """Summarize Volatility plugin output."""
        summary = {'plugin': plugin, 'items_found': 0}
        
        lines = output.split('\n')
        
        if plugin == 'pslist':
            processes = [line for line in lines if re.match(r'^\w+\s+\d+', line)]
            summary['items_found'] = len(processes)
            summary['processes'] = len(processes)
            
        elif plugin == 'connections':
            connections = [line for line in lines if ':' in line and '->' in line]
            summary['items_found'] = len(connections)
            summary['network_connections'] = len(connections)
            
        elif plugin == 'filescan':
            files = [line for line in lines if '\\' in line or '/' in line]
            summary['items_found'] = len(files)
            summary['files_found'] = len(files)
            
        elif plugin == 'hashdump':
            hashes = [line for line in lines if ':' in line and len(line.split(':')) >= 4]
            summary['items_found'] = len(hashes)
            summary['password_hashes'] = len(hashes)
        
        return summary
    
    def carve_files(self, case_name: str, image_path: str, file_types: List[str] = None) -> Dict:
        """Carve files from disk image using Foremost."""
        try:
            from modules.privilege_manager import privilege_manager
            
            case_dir = self.evidence_dir / case_name
            output_dir = case_dir / 'carved' / 'foremost_output'
            output_dir.mkdir(parents=True, exist_ok=True)
            
            cmd = ['foremost', '-i', image_path, '-o', str(output_dir)]
            
            # Add specific file types if requested
            if file_types:
                type_string = ','.join(file_types)
                cmd.extend(['-t', type_string])
            
            result = privilege_manager.execute_privileged(
                cmd, 'foremost', timeout=1800  # 30 minutes
            )
            
            if result.returncode == 0:
                # Parse audit file
                audit_file = output_dir / 'audit.txt'
                carved_summary = self._parse_foremost_audit(audit_file)
                
                return {
                    'success': True,
                    'output_dir': str(output_dir),
                    'carved_files': carved_summary,
                    'case_name': case_name
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            logger.error(f"File carving error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_foremost_audit(self, audit_file: Path) -> Dict:
        """Parse Foremost audit file."""
        summary = {'total_files': 0, 'by_type': {}}
        
        try:
            if audit_file.exists():
                with open(audit_file, 'r') as f:
                    content = f.read()
                
                # Extract file counts by type
                for line in content.split('\n'):
                    if 'FILES EXTRACTED' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            file_type = parts[0].lower()
                            count = int(parts[2])
                            summary['by_type'][file_type] = count
                            summary['total_files'] += count
        
        except Exception as e:
            logger.error(f"Audit parsing error: {e}")
        
        return summary
    
    def analyze_network_capture(self, case_name: str, pcap_path: str) -> Dict:
        """Analyze network capture using tshark."""
        try:
            from modules.privilege_manager import privilege_manager
            
            case_dir = self.evidence_dir / case_name
            output_dir = case_dir / 'network' / 'analysis'
            output_dir.mkdir(parents=True, exist_ok=True)
            
            analyses = {}
            
            # Protocol hierarchy
            cmd = ['tshark', '-r', pcap_path, '-q', '-z', 'io,phs']
            result = privilege_manager.execute_privileged(cmd, 'wireshark', timeout=60)
            
            if result.returncode == 0:
                with open(output_dir / 'protocol_hierarchy.txt', 'w') as f:
                    f.write(result.stdout)
                analyses['protocol_hierarchy'] = str(output_dir / 'protocol_hierarchy.txt')
            
            # Conversations
            cmd = ['tshark', '-r', pcap_path, '-q', '-z', 'conv,ip']
            result = privilege_manager.execute_privileged(cmd, 'wireshark', timeout=60)
            
            if result.returncode == 0:
                with open(output_dir / 'conversations.txt', 'w') as f:
                    f.write(result.stdout)
                analyses['conversations'] = str(output_dir / 'conversations.txt')
            
            # HTTP requests
            cmd = ['tshark', '-r', pcap_path, '-Y', 'http.request', '-T', 'fields', 
                   '-e', 'http.host', '-e', 'http.request.uri', '-e', 'http.user_agent']
            result = privilege_manager.execute_privileged(cmd, 'wireshark', timeout=60)
            
            if result.returncode == 0:
                with open(output_dir / 'http_requests.txt', 'w') as f:
                    f.write(result.stdout)
                analyses['http_requests'] = str(output_dir / 'http_requests.txt')
            
            # DNS queries
            cmd = ['tshark', '-r', pcap_path, '-Y', 'dns.flags.response == 0', 
                   '-T', 'fields', '-e', 'dns.qry.name']
            result = privilege_manager.execute_privileged(cmd, 'wireshark', timeout=60)
            
            if result.returncode == 0:
                with open(output_dir / 'dns_queries.txt', 'w') as f:
                    f.write(result.stdout)
                analyses['dns_queries'] = str(output_dir / 'dns_queries.txt')
            
            return {
                'success': True,
                'output_dir': str(output_dir),
                'analyses': analyses,
                'case_name': case_name
            }
            
        except Exception as e:
            logger.error(f"Network analysis error: {e}")
            return {'success': False, 'error': str(e)}
    
    def scan_with_yara(self, case_name: str, target_path: str, rules_path: str = None) -> Dict:
        """Scan files with YARA rules for malware detection."""
        try:
            from modules.privilege_manager import privilege_manager
            
            case_dir = self.evidence_dir / case_name
            output_dir = case_dir / 'malware' / 'yara_scan'
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Use default rules if not specified
            if not rules_path:
                rules_path = '/usr/share/yara-rules'
            
            if not Path(rules_path).exists():
                return {'success': False, 'error': 'YARA rules not found'}
            
            # Scan with YARA
            output_file = output_dir / 'yara_results.txt'
            
            cmd = ['yara', '-r', rules_path, target_path]
            result = privilege_manager.execute_privileged(cmd, 'yara', timeout=300)
            
            if result.returncode == 0:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                # Parse results
                matches = self._parse_yara_results(result.stdout)
                
                return {
                    'success': True,
                    'output_file': str(output_file),
                    'matches': matches,
                    'total_matches': len(matches),
                    'case_name': case_name
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_yara_results(self, output: str) -> List[Dict]:
        """Parse YARA scan results."""
        matches = []
        
        for line in output.split('\n'):
            if line.strip():
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    rule_name = parts[0]
                    file_path = parts[1]
                    
                    matches.append({
                        'rule': rule_name,
                        'file': file_path,
                        'timestamp': datetime.now().isoformat()
                    })
        
        return matches
    
    def generate_case_report(self, case_name: str) -> Dict:
        """Generate comprehensive forensics case report."""
        try:
            case_dir = self.evidence_dir / case_name
            if not case_dir.exists():
                return {'success': False, 'error': 'Case does not exist'}
            
            # Load case metadata
            metadata_file = case_dir / 'case_metadata.json'
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Collect analysis results
            report_data = {
                'case_info': metadata,
                'evidence_summary': self._summarize_evidence(case_dir),
                'analysis_summary': self._summarize_analyses(case_dir),
                'timeline': self._create_timeline(case_dir),
                'generated': datetime.now().isoformat()
            }
            
            # Generate HTML report
            report_file = case_dir / 'reports' / f"{case_name}_forensics_report.html"
            self._generate_html_report(report_data, report_file)
            
            return {
                'success': True,
                'report_file': str(report_file),
                'case_name': case_name,
                'evidence_items': len(metadata['evidence_items']),
                'chain_of_custody_entries': len(metadata['chain_of_custody'])
            }
            
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _summarize_evidence(self, case_dir: Path) -> Dict:
        """Summarize evidence in case."""
        summary = {
            'total_items': 0,
            'by_type': {},
            'total_size': 0
        }
        
        try:
            metadata_file = case_dir / 'case_metadata.json'
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            for item in metadata['evidence_items']:
                summary['total_items'] += 1
                summary['total_size'] += item['size']
                
                item_type = item['type']
                if item_type not in summary['by_type']:
                    summary['by_type'][item_type] = 0
                summary['by_type'][item_type] += 1
        
        except Exception as e:
            logger.error(f"Evidence summary error: {e}")
        
        return summary
    
    def _summarize_analyses(self, case_dir: Path) -> Dict:
        """Summarize completed analyses."""
        summary = {
            'memory_analysis': (case_dir / 'extracted' / 'memory_analysis').exists(),
            'file_carving': (case_dir / 'carved').exists(),
            'network_analysis': (case_dir / 'network' / 'analysis').exists(),
            'malware_scan': (case_dir / 'malware').exists()
        }
        
        return summary
    
    def _create_timeline(self, case_dir: Path) -> List[Dict]:
        """Create timeline of case activities."""
        timeline = []
        
        try:
            metadata_file = case_dir / 'case_metadata.json'
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Add chain of custody events
            for event in metadata['chain_of_custody']:
                timeline.append({
                    'timestamp': event['timestamp'],
                    'event': event['action'],
                    'details': event['details'],
                    'user': event['user']
                })
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x['timestamp'])
        
        except Exception as e:
            logger.error(f"Timeline creation error: {e}")
        
        return timeline
    
    def _generate_html_report(self, report_data: Dict, output_file: Path):
        """Generate HTML forensics report."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Forensics Case Report - {case_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .evidence {{ background: #f8f9fa; }}
                .timeline {{ background: #e8f5e9; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Digital Forensics Case Report</h1>
                <h2>Case: {case_name}</h2>
                <p>Generated: {generated}</p>
            </div>
            
            <div class="section">
                <h3>Case Information</h3>
                <p><strong>Description:</strong> {description}</p>
                <p><strong>Investigator:</strong> {investigator}</p>
                <p><strong>Created:</strong> {created}</p>
            </div>
            
            <div class="section evidence">
                <h3>Evidence Summary</h3>
                <p><strong>Total Items:</strong> {total_items}</p>
                <p><strong>Total Size:</strong> {total_size} bytes</p>
                <h4>Evidence by Type:</h4>
                <ul>
                {evidence_types}
                </ul>
            </div>
            
            <div class="section timeline">
                <h3>Chain of Custody Timeline</h3>
                <table>
                    <tr><th>Timestamp</th><th>Event</th><th>User</th><th>Details</th></tr>
                    {timeline_rows}
                </table>
            </div>
            
            <div class="section">
                <h3>Analysis Summary</h3>
                <ul>
                    <li>Memory Analysis: {memory_analysis}</li>
                    <li>File Carving: {file_carving}</li>
                    <li>Network Analysis: {network_analysis}</li>
                    <li>Malware Scan: {malware_scan}</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        # Format template
        case_info = report_data['case_info']
        evidence_summary = report_data['evidence_summary']
        analysis_summary = report_data['analysis_summary']
        timeline = report_data['timeline']
        
        evidence_types = '\n'.join([
            f"<li>{type_name}: {count} items</li>"
            for type_name, count in evidence_summary['by_type'].items()
        ])
        
        timeline_rows = '\n'.join([
            f"<tr><td>{event['timestamp']}</td><td>{event['event']}</td><td>{event['user']}</td><td>{event['details']}</td></tr>"
            for event in timeline
        ])
        
        html_content = html_template.format(
            case_name=case_info['case_name'],
            generated=report_data['generated'],
            description=case_info['description'],
            investigator=case_info['investigator'],
            created=case_info['created'],
            total_items=evidence_summary['total_items'],
            total_size=evidence_summary['total_size'],
            evidence_types=evidence_types,
            timeline_rows=timeline_rows,
            memory_analysis='✓' if analysis_summary['memory_analysis'] else '✗',
            file_carving='✓' if analysis_summary['file_carving'] else '✗',
            network_analysis='✓' if analysis_summary['network_analysis'] else '✗',
            malware_scan='✓' if analysis_summary['malware_scan'] else '✗'
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def status(self) -> Dict:
        """Get forensics toolkit status."""
        return {
            'evidence_dir': str(self.evidence_dir),
            'tools_available': self.check_tool_availability(),
            'active_cases': len([d for d in self.evidence_dir.iterdir() if d.is_dir()]),
            'supported_file_types': self.file_signatures
        }

# Global instance
forensics = ForensicsToolkit()