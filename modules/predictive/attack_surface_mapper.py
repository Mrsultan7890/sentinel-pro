"""
Attack Surface Mapper
Maps all exposed services, dependencies, and attack paths
"""

import subprocess
import json
import socket
from pathlib import Path
from typing import Dict, List, Set, Any
import networkx as nx
from datetime import datetime

class AttackSurfaceMapper:
    """Map attack surface and identify attack paths"""
    
    def __init__(self, target: str):
        self.target = target
        self.graph = nx.DiGraph()
        self.services: Dict[int, Dict] = {}
        self.dependencies: List[Dict] = []
        self.attack_paths: List[List[str]] = []
        
    def scan_ports(self, port_range: str = "1-1000") -> Dict[int, Dict]:
        """Scan open ports on target"""
        print(f"[*] Scanning ports {port_range} on {self.target}...")
        
        try:
            # Use nmap if available
            result = subprocess.run(
                ['nmap', '-p', port_range, '-sV', '--open', self.target],
                capture_output=True, text=True, timeout=300
            )
            
            # Parse nmap output
            services = self._parse_nmap_output(result.stdout)
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback: simple socket scan
            services = self._socket_scan(port_range)
        
        self.services = services
        
        # Add to graph
        for port, info in services.items():
            self.graph.add_node(f"port_{port}", type="service", **info)
            self.graph.add_edge(self.target, f"port_{port}", relation="exposes")
        
        return services
    
    def _parse_nmap_output(self, output: str) -> Dict[int, Dict]:
        """Parse nmap output"""
        services = {}
        
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    port = int(port_proto[0])
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    if state == "open":
                        services[port] = {
                            'port': port,
                            'service': service,
                            'state': state,
                            'protocol': port_proto[1] if len(port_proto) > 1 else 'tcp'
                        }
        
        return services
    
    def _socket_scan(self, port_range: str) -> Dict[int, Dict]:
        """Fallback socket scan"""
        services = {}
        start, end = map(int, port_range.split('-'))
        
        for port in range(start, min(end + 1, start + 100)):  # Limit to 100 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    services[port] = {
                        'port': port,
                        'service': 'unknown',
                        'state': 'open',
                        'protocol': 'tcp'
                    }
                
                sock.close()
            except:
                pass
        
        return services
    
    def map_dependencies(self) -> List[Dict]:
        """Map service dependencies"""
        print("[*] Mapping dependencies...")
        
        dependencies = []
        
        # Common dependency patterns
        dep_map = {
            80: ['443'],  # HTTP often with HTTPS
            443: ['80'],
            3306: ['80', '443'],  # MySQL with web
            5432: ['80', '443'],  # PostgreSQL with web
            6379: ['80', '443'],  # Redis with web
            27017: ['80', '443'],  # MongoDB with web
        }
        
        for port, info in self.services.items():
            if port in dep_map:
                for dep_port in dep_map[port]:
                    dep_port_int = int(dep_port)
                    if dep_port_int in self.services:
                        dep = {
                            'from': port,
                            'to': dep_port_int,
                            'type': 'likely_dependency'
                        }
                        dependencies.append(dep)
                        
                        # Add to graph
                        self.graph.add_edge(
                            f"port_{port}",
                            f"port_{dep_port_int}",
                            relation="depends_on"
                        )
        
        self.dependencies = dependencies
        return dependencies
    
    def identify_attack_paths(self) -> List[List[str]]:
        """Identify potential attack paths"""
        print("[*] Identifying attack paths...")
        
        attack_paths = []
        
        # Find all paths from target to services
        for port, info in self.services.items():
            service_node = f"port_{port}"
            
            # Check if path exists
            if nx.has_path(self.graph, self.target, service_node):
                path = nx.shortest_path(self.graph, self.target, service_node)
                
                # Calculate risk score
                risk = self._calculate_path_risk(path, info)
                
                attack_paths.append({
                    'path': path,
                    'target_port': port,
                    'service': info['service'],
                    'risk_score': risk,
                    'attack_vectors': self._get_attack_vectors(info)
                })
        
        # Sort by risk
        attack_paths.sort(key=lambda x: x['risk_score'], reverse=True)
        
        self.attack_paths = attack_paths
        return attack_paths
    
    def _calculate_path_risk(self, path: List[str], service_info: Dict) -> float:
        """Calculate risk score for attack path"""
        risk = 0.0
        
        # Base risk by service
        high_risk_services = ['ssh', 'ftp', 'telnet', 'mysql', 'postgresql', 'mongodb', 'redis']
        medium_risk_services = ['http', 'https', 'smtp', 'pop3', 'imap']
        
        service = service_info['service'].lower()
        
        if any(s in service for s in high_risk_services):
            risk += 0.7
        elif any(s in service for s in medium_risk_services):
            risk += 0.5
        else:
            risk += 0.3
        
        # Path length (shorter = higher risk)
        risk += 0.3 / len(path)
        
        # Common vulnerable ports
        vulnerable_ports = [21, 22, 23, 3306, 5432, 6379, 27017]
        if service_info['port'] in vulnerable_ports:
            risk += 0.2
        
        return min(risk, 1.0)
    
    def _get_attack_vectors(self, service_info: Dict) -> List[str]:
        """Get potential attack vectors for service"""
        vectors = []
        service = service_info['service'].lower()
        port = service_info['port']
        
        # Service-specific vectors
        vector_map = {
            'http': ['XSS', 'SQLi', 'CSRF', 'Directory Traversal'],
            'https': ['XSS', 'SQLi', 'CSRF', 'SSL/TLS Vulnerabilities'],
            'ssh': ['Brute Force', 'Key Theft', 'Version Exploits'],
            'ftp': ['Anonymous Login', 'Brute Force', 'Directory Traversal'],
            'mysql': ['SQLi', 'Brute Force', 'Privilege Escalation'],
            'postgresql': ['SQLi', 'Brute Force', 'Code Execution'],
            'mongodb': ['NoSQL Injection', 'Unauthorized Access'],
            'redis': ['Unauthorized Access', 'Code Execution'],
        }
        
        for key, vecs in vector_map.items():
            if key in service:
                vectors.extend(vecs)
        
        # Port-specific vectors
        if port in [80, 443, 8080, 8443]:
            vectors.append('Web Application Attacks')
        
        if port in [21, 22, 23]:
            vectors.append('Authentication Attacks')
        
        return list(set(vectors))  # Remove duplicates
    
    def visualize_graph(self, output_path: str = "attack_surface.json"):
        """Export attack surface graph"""
        print(f"[*] Exporting graph to {output_path}...")
        
        # Convert to JSON-serializable format
        graph_data = {
            'nodes': [
                {
                    'id': node,
                    'type': self.graph.nodes[node].get('type', 'unknown'),
                    **{k: v for k, v in self.graph.nodes[node].items() if k != 'type'}
                }
                for node in self.graph.nodes()
            ],
            'edges': [
                {
                    'source': u,
                    'target': v,
                    'relation': self.graph[u][v].get('relation', 'unknown')
                }
                for u, v in self.graph.edges()
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(graph_data, f, indent=2)
        
        return graph_data
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive attack surface report"""
        return {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'total_services': len(self.services),
                'total_dependencies': len(self.dependencies),
                'total_attack_paths': len(self.attack_paths),
                'high_risk_paths': sum(1 for p in self.attack_paths if p['risk_score'] > 0.7)
            },
            'services': self.services,
            'dependencies': self.dependencies,
            'attack_paths': self.attack_paths[:10],  # Top 10
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for high-risk services
        high_risk_ports = [21, 22, 23, 3306, 5432, 6379, 27017]
        exposed_high_risk = [p for p in self.services.keys() if p in high_risk_ports]
        
        if exposed_high_risk:
            recommendations.append(
                f"High-risk services exposed: {exposed_high_risk}. Consider firewall rules or VPN access."
            )
        
        # Check for web services
        web_ports = [p for p in self.services.keys() if p in [80, 443, 8080, 8443]]
        if web_ports:
            recommendations.append(
                "Web services detected. Ensure WAF, rate limiting, and input validation are in place."
            )
        
        # Check for database services
        db_ports = [p for p in self.services.keys() if p in [3306, 5432, 6379, 27017]]
        if db_ports:
            recommendations.append(
                "Database services exposed. Ensure strong authentication and network isolation."
            )
        
        if len(self.services) > 10:
            recommendations.append(
                f"Large attack surface ({len(self.services)} services). Consider reducing exposed services."
            )
        
        return recommendations


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    
    print(f"[*] Mapping attack surface for {target}...")
    
    mapper = AttackSurfaceMapper(target)
    
    # Scan
    services = mapper.scan_ports("1-1000")
    print(f"✓ Found {len(services)} open services")
    
    # Map dependencies
    deps = mapper.map_dependencies()
    print(f"✓ Identified {len(deps)} dependencies")
    
    # Identify attack paths
    paths = mapper.identify_attack_paths()
    print(f"✓ Found {len(paths)} attack paths")
    
    # Generate report
    report = mapper.generate_report()
    print(f"\n✓ Attack Surface Report:")
    print(f"  Total services: {report['summary']['total_services']}")
    print(f"  High-risk paths: {report['summary']['high_risk_paths']}")
    
    if report['recommendations']:
        print(f"\n✓ Recommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
    
    # Export graph
    mapper.visualize_graph()
    print(f"\n✓ Graph exported to attack_surface.json")
