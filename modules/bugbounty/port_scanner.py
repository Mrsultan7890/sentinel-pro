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
Port Scanner
Fast TCP scan + service banner grabbing + risk classification
"""

import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2181, 2375, 2376, 3000, 3306, 3389,
    4443, 4848, 5000, 5432, 5900, 5984, 6379, 6443, 7001, 7443,
    8000, 8080, 8081, 8443, 8888, 9000, 9200, 9300, 9443, 27017,
    28017, 50000
]

# Ports that are HIGH risk if open
HIGH_RISK_PORTS = {
    23:    'Telnet - plaintext protocol, critical risk',
    2375:  'Docker API (unauthenticated) - full container takeover',
    2376:  'Docker API (TLS) - verify auth',
    3389:  'RDP - brute force / BlueKeep risk',
    4848:  'GlassFish Admin - default creds common',
    5900:  'VNC - often no auth or weak password',
    6379:  'Redis - usually no auth, full data access',
    7001:  'WebLogic - multiple critical CVEs',
    9200:  'Elasticsearch - no auth by default, data exposure',
    9300:  'Elasticsearch transport - internal cluster port',
    27017: 'MongoDB - no auth by default',
    28017: 'MongoDB HTTP interface - deprecated, dangerous',
    50000: 'SAP / Jenkins alt port',
}

SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS',
    445: 'SMB', 465: 'SMTPS', 587: 'SMTP-Submission', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 2181: 'Zookeeper',
    2375: 'Docker-API', 2376: 'Docker-TLS', 3000: 'HTTP-Dev',
    3306: 'MySQL', 3389: 'RDP', 4443: 'HTTPS-Alt', 4848: 'GlassFish',
    5000: 'HTTP-Dev', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 6443: 'Kubernetes-API', 7001: 'WebLogic',
    7443: 'WebLogic-SSL', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
    8081: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
    9000: 'HTTP-Alt', 9200: 'Elasticsearch', 9300: 'ES-Transport',
    9443: 'HTTPS-Alt', 27017: 'MongoDB', 28017: 'MongoDB-HTTP',
    50000: 'SAP-Alt'
}


class PortScanner:

    def run(self, target: str, custom_ports: list = None) -> dict:
        if not target or not isinstance(target, str):
            return {
                'target': target,
                'error': 'Invalid target',
                'open_ports': [],
                'timestamp': datetime.now().isoformat()
            }
        
        target = target.strip().lower()
        if len(target) > 253:
            return {
                'target': target,
                'error': 'Target too long',
                'open_ports': [],
                'timestamp': datetime.now().isoformat()
            }
        
        # Validate custom_ports
        if custom_ports is not None:
            if not isinstance(custom_ports, list):
                custom_ports = None
            else:
                # Filter valid ports
                custom_ports = [p for p in custom_ports if isinstance(p, int) and 1 <= p <= 65535]
                if not custom_ports:
                    custom_ports = None
        
        ports = custom_ports or COMMON_PORTS

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            logger.error(f'DNS resolution failed for {target}: {e}')
            return {
                'target': target,
                'error': 'Could not resolve hostname',
                'open_ports': [],
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f'Unexpected DNS error for {target}: {e}')
            return {
                'target': target,
                'error': f'DNS error: {e}',
                'open_ports': [],
                'timestamp': datetime.now().isoformat()
            }

        result = {
            'target': target,
            'ip': ip,
            'open_ports': [],
            'high_risk_ports': [],
            'timestamp': datetime.now().isoformat()
        }

        def check_port(port):
            if not isinstance(port, int) or port < 1 or port > 65535:
                return None
            
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    banner = self._grab_banner(s, port)
                    return {
                        'port':    port,
                        'state':   'open',
                        'service': SERVICES.get(port, 'unknown'),
                        'banner':  banner,
                        'risk':    'HIGH' if port in HIGH_RISK_PORTS else 'LOW',
                        'risk_detail': HIGH_RISK_PORTS.get(port, '')
                    }
            except (socket.timeout, socket.error) as e:
                logger.debug(f'Port {port} check failed: {e}')
            except Exception as e:
                logger.error(f'Unexpected port check error for {port}: {e}')
            finally:
                if s:
                    try:
                        s.close()
                    except Exception as e:
                        logger.debug(f"port_scanner error: {e}")
            return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check_port, p): p for p in ports}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    result['open_ports'].append(r)
                    if r['risk'] == 'HIGH':
                        result['high_risk_ports'].append(r)

        result['open_ports'].sort(key=lambda x: x['port'])
        result['total_open'] = len(result['open_ports'])
        result['total_high_risk'] = len(result['high_risk_ports'])
        return result

    def _grab_banner(self, sock, port: int) -> str:
        """Try to grab service banner for fingerprinting"""
        if not sock or not isinstance(port, int):
            return ''
        
        try:
            sock.settimeout(2)
            # Send probe for HTTP ports
            if port in (80, 8080, 8000, 8888):
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            else:
                sock.send(b'\r\n')
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else ''
        except socket.timeout as e:
            logger.debug(f'Banner grab timeout for port {port}: {e}')
            return ''
        except (socket.error, OSError) as e:
            logger.debug(f'Banner grab socket error for port {port}: {e}')
            return ''
        except Exception as e:
            logger.error(f'Banner grab error for port {port}: {e}')
            return ''
