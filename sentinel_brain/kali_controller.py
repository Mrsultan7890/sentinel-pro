"""
Kali Linux Controller v2 — Full OS Control + Output Parsing + Tool Chaining
=============================================================================
- Real PTY terminal
- Auto output parsing (nmap → ports, sqlmap → vulns, etc.)
- Tool chaining (nmap results → sqlmap/nikto automatically)
- Auto tool selection based on target type
- Background process management

Author: @who_is_the_black_hat
"""

import os
import re
import pty
import select
import subprocess
import time
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_BLOCKED = [
    'rm -rf /', 'mkfs', ':(){:|:&};:', 'dd if=/dev/zero of=/dev/',
    'chmod -R 777 /', '> /dev/sda', 'shred /dev/', 'wipefs',
    'fdisk /dev/sd', 'parted /dev/sd',
]

KALI_TOOLS = {
    'nmap': 'Network scanner — port scan, service detection, OS fingerprint',
    'masscan': 'Fast port scanner',
    'subfinder': 'Subdomain enumeration',
    'amass': 'Attack surface mapping',
    'theHarvester': 'Email, domain, IP harvesting',
    'nikto': 'Web server scanner',
    'nuclei': 'Template-based vulnerability scanner',
    'sqlmap': 'SQL injection tool',
    'xsstrike': 'XSS scanner',
    'dalfox': 'XSS scanner',
    'gobuster': 'Directory/DNS/vhost brute-forcer',
    'ffuf': 'Web fuzzer',
    'feroxbuster': 'Directory brute-forcer',
    'dirb': 'Directory brute-forcer',
    'hydra': 'Network login brute-forcer',
    'john': 'Password cracker',
    'hashcat': 'GPU password cracker',
    'msfconsole': 'Metasploit Framework',
    'msfvenom': 'Payload generator',
    'msfdb': 'Metasploit database',
    'searchsploit': 'ExploitDB search',
    'commix': 'Command injection exploiter',
    'wpscan': 'WordPress scanner',
    'testssl.sh': 'SSL/TLS tester',
    'sslscan': 'SSL scanner',
    'sherlock': 'Username OSINT',
    'holehe': 'Email OSINT',
    'exiftool': 'Metadata extractor',
    'tcpdump': 'Packet capture',
    'netcat': 'Network utility',
    'nc': 'Netcat',
    'responder': 'LLMNR/NBT-NS poisoner',
    'bettercap': 'Network attack framework',
    'wireshark': 'Network protocol analyzer',
    'tshark': 'Terminal Wireshark',
    'volatility': 'Memory forensics',
    'volatility3': 'Memory forensics v3',
    'autopsy': 'Digital forensics platform',
    'sleuthkit': 'File system forensics',
    'foremost': 'File carving tool',
    'scalpel': 'File carving tool',
    'binwalk': 'Firmware analysis',
    'yara': 'Malware identification',
    'strings': 'Extract strings from files',
    'hexdump': 'Hex dump utility',
    'dd': 'Disk imaging tool',
    'dcfldd': 'Enhanced dd for forensics',
    'ewf-tools': 'Expert Witness Format tools',
    'afflib-tools': 'Advanced Forensic Format tools',
    'curl': 'HTTP client',
    'wget': 'File downloader',
    'whois': 'Domain registration info',
    'dig': 'DNS lookup',
    'dnsx': 'DNS toolkit',
    'httpx': 'HTTP probing',
    'waybackurls': 'Wayback Machine URL fetcher',
    'gau': 'Get all URLs',
    'katana': 'Web crawler',
    'python3': 'Python interpreter',
    'bash': 'Bash shell',
    'git': 'Version control',
    'docker': 'Container runtime',
    'ncat': 'Nmap netcat',
    'socat': 'Multipurpose relay',
    'arp-scan': 'ARP scanner',
    'netdiscover': 'Network discovery',
    'openssl': 'SSL/TLS toolkit',
    'hashid': 'Hash identifier',
    'cewl': 'Custom wordlist generator',
    'crunch': 'Wordlist generator',
    'medusa': 'Parallel login brute-forcer',
    'beef-xss': 'Browser exploitation framework',
    'ssrfmap': 'SSRF scanner',
    'wfuzz': 'Web fuzzer',
    'recon-ng': 'Web reconnaissance framework',
    'phoneinfoga': 'Phone number OSINT',
    'maigret': 'Username OSINT',
    'aircrack-ng': 'WiFi security auditing',
    'airmon-ng': 'WiFi monitor mode',
    'reaver': 'WPS attack tool',
    'ettercap': 'Network sniffer/interceptor',
    'hping3': 'Network tool',
}


class KaliController:
    """
    Full Kali Linux controller with:
    - Real PTY execution
    - Automatic output parsing
    - Tool chaining
    - Background process management
    """

    def __init__(self, workdir: str = None, timeout: int = 120):
        self.workdir   = workdir or str(Path.home())
        self.timeout   = timeout
        self._history: list[dict] = []
        self._bg_procs: dict[str, dict] = {}
        self._lock     = threading.Lock()
        self._chain_results: dict = {}

    # ── Core Execution ────────────────────────────────────────────────────────

    def run(self, command: str, timeout: int = None, cwd: str = None, privileged: bool = None) -> dict:
        timeout = timeout or self.timeout
        cwd     = cwd or self.workdir

        for blocked in _BLOCKED:
            if blocked in command:
                return self._result(command, False, '', f'BLOCKED: {blocked}', -1)

        # Check if command needs privilege escalation
        if privileged is None:
            privileged = self._needs_privilege(command)
        
        if privileged:
            try:
                from modules.privilege_manager import privilege_manager
                tool_name = command.split()[0]
                result = privilege_manager.execute_privileged(
                    command.split(), tool_name, timeout=timeout
                )
                parsed_result = self._result(
                    command, result.returncode == 0,
                    result.stdout[:15000], result.stderr, result.returncode
                )
                parsed_result['parsed'] = self._parse_output(command, result.stdout)
                with self._lock:
                    self._history.append(parsed_result)
                return parsed_result
            except Exception as e:
                logger.error(f"Privileged execution failed: {e}")
                return self._result(command, False, '', str(e), -1)

        logger.info(f"[KaliCtrl] $ {command}")

        try:
            master_fd, slave_fd = pty.openpty()
            proc = subprocess.Popen(
                command, shell=True,
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                cwd=cwd, close_fds=True,
                env={**os.environ, 'TERM': 'xterm', 'COLUMNS': '220',
                     'DEBIAN_FRONTEND': 'noninteractive'}
            )
            os.close(slave_fd)

            chunks = []
            deadline = time.time() + timeout

            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    proc.kill()
                    chunks.append('\n[TIMEOUT]')
                    break
                ready, _, _ = select.select([master_fd], [], [], min(remaining, 0.5))
                if ready:
                    try:
                        chunk = os.read(master_fd, 8192).decode('utf-8', errors='replace')
                        chunks.append(chunk)
                    except OSError:
                        break
                elif proc.poll() is not None:
                    try:
                        while True:
                            r2, _, _ = select.select([master_fd], [], [], 0.1)
                            if not r2:
                                break
                            chunk = os.read(master_fd, 8192).decode('utf-8', errors='replace')
                            chunks.append(chunk)
                    except OSError:
                        pass
                    break

            os.close(master_fd)
            try:
                proc.wait(timeout=5)
            except Exception:
                pass

            output = ''.join(chunks).strip()
            output = re.sub(r'\x1b\[[0-9;]*[mGKHFJA-Z]', '', output)
            output = re.sub(r'\x1b\[\?[0-9;]*[hl]', '', output)
            output = re.sub(r'\r\n', '\n', output)

            result = self._result(command, proc.returncode == 0,
                                  output[:15000], '', proc.returncode)
            # Auto parse output
            result['parsed'] = self._parse_output(command, output)

            with self._lock:
                self._history.append(result)
            return result

        except Exception as e:
            logger.exception(f"KaliCtrl error: {command}")
            return self._result(command, False, '', str(e), -1)

    def run_bg(self, command: str, name: str = None) -> dict:
        for blocked in _BLOCKED:
            if blocked in command:
                return {'success': False, 'error': f'Blocked: {blocked}'}

        log_file = f'/tmp/sentinel_bg_{int(time.time())}.log'
        try:
            with open(log_file, 'w') as lf:
                proc = subprocess.Popen(
                    command, shell=True, stdout=lf, stderr=lf,
                    cwd=self.workdir, start_new_session=True,
                    env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
                )
            key = name or f'bg_{proc.pid}'
            self._bg_procs[key] = {'proc': proc, 'log': log_file, 'cmd': command}
            logger.info(f"[KaliCtrl] BG PID {proc.pid}: {command}")
            return {'success': True, 'pid': proc.pid, 'log': log_file, 'name': key}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def bg_output(self, name: str, tail: int = 100) -> str:
        entry = self._bg_procs.get(name, {})
        log_file = entry.get('log', '')
        if log_file and Path(log_file).exists():
            try:
                lines = Path(log_file).read_text(errors='replace').splitlines()
                return '\n'.join(lines[-tail:])
            except Exception:
                pass
        return ''

    def bg_status(self) -> dict:
        status = {}
        for name, entry in self._bg_procs.items():
            proc = entry['proc']
            rc   = proc.poll()
            status[name] = {'pid': proc.pid, 'running': rc is None, 'returncode': rc, 'cmd': entry['cmd']}
        return status

    def kill_bg(self, name: str) -> bool:
        entry = self._bg_procs.get(name, {})
        proc  = entry.get('proc')
        if proc:
            try:
                proc.terminate()
                return True
            except Exception:
                pass
        return False

    # ── Output Parsers ────────────────────────────────────────────────────────

    def _parse_output(self, command: str, output: str) -> dict:
        cmd_lower = command.lower()
        if 'nmap' in cmd_lower:
            return self._parse_nmap(output)
        elif 'sqlmap' in cmd_lower:
            return self._parse_sqlmap(output)
        elif 'nikto' in cmd_lower:
            return self._parse_nikto(output)
        elif any(t in cmd_lower for t in ('gobuster','ffuf','wfuzz','dirb','feroxbuster')):
            return self._parse_dirbust(output)
        elif any(t in cmd_lower for t in ('subfinder','amass')):
            return self._parse_subdomains(output)
        elif 'nuclei' in cmd_lower:
            return self._parse_nuclei(output)
        elif any(t in cmd_lower for t in ('hydra','medusa')):
            return self._parse_bruteforce(output)
        elif 'searchsploit' in cmd_lower:
            return self._parse_searchsploit(output)
        elif any(t in cmd_lower for t in ('hashcat','john')):
            return self._parse_cracked(output)
        elif any(t in cmd_lower for t in ('dig','dnsx')):
            return self._parse_dns(output)
        elif any(t in cmd_lower for t in ('curl','httpx')):
            return self._parse_http(output)
        elif 'whatweb' in cmd_lower:
            return self._parse_whatweb(output)
        elif 'wafw00f' in cmd_lower:
            return self._parse_wafw00f(output)
        elif any(t in cmd_lower for t in ('sslscan','sslyze')):
            return self._parse_ssl(output)
        elif 'masscan' in cmd_lower:
            return self._parse_masscan(output)
        elif 'wpscan' in cmd_lower:
            return self._parse_wpscan(output)
        return {'raw': output[:500]}

    def _parse_nmap(self, output: str) -> dict:
        ports, services, os_info = [], [], ''
        for line in output.splitlines():
            # open ports
            m = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                ports.append({
                    'port': int(m.group(1)),
                    'proto': m.group(2),
                    'service': m.group(3),
                    'version': m.group(4).strip()
                })
            # OS detection
            if 'OS details:' in line or 'Running:' in line:
                os_info = line.split(':', 1)[-1].strip()
        return {'tool': 'nmap', 'open_ports': ports, 'os': os_info, 'total': len(ports)}

    def _parse_sqlmap(self, output: str) -> dict:
        vulns, dbs, tables = [], [], []
        for line in output.splitlines():
            l = line.strip()
            if not l:
                continue
            if 'is vulnerable' in l.lower() or ('parameter' in l.lower() and 'injectable' in l.lower()):
                vulns.append(l)
            m = re.match(r'\[\*\]\s+([a-zA-Z0-9_]+)\s*$', l)
            if m:
                dbs.append(m.group(1))
            if '|' in l and l.startswith('|') and 'Database' not in l:
                tables.append(l)
        return {'tool': 'sqlmap', 'vulnerable': len(vulns) > 0, 'vulns': vulns, 'databases': dbs[:10], 'tables': tables[:20]}

    def _parse_nikto(self, output: str) -> dict:
        SKIP = ('target ip', 'target hostname', 'target port', 'start time',
                'end time', 'server:', 'ssl info', 'platform:', 'no cgi',
                'retrieved x-powered', 'allowed http', 'anti-clickjacking',
                'uncommon header', 'nikto installation', 'alt-svc',
                'cloudflare detected', 'x-frame-options', 'x-content-type',
                'scan terminated', 'host(s) tested', '0 errors')
        findings = []
        for line in output.splitlines():
            if not line.startswith('+ '):
                continue
            text = line[2:].strip()
            if any(s in text.lower() for s in SKIP):
                continue
            if len(text) < 15:
                continue
            findings.append(text)
        return {'tool': 'nikto', 'findings': findings, 'total': len(findings)}

    def _parse_dirbust(self, output: str) -> dict:
        found = []
        for line in output.splitlines():
            m = re.search(r'(https?://\S+|/\S+)\s+\(Status:\s*(\d+)\)', line)
            if m:
                found.append({'url': m.group(1), 'status': int(m.group(2))})
            elif re.match(r'\d{3}\s+\S', line):
                parts = line.split()
                if len(parts) >= 2:
                    found.append({'url': parts[-1], 'status': int(parts[0])})
        return {'tool': 'dirbust', 'found': found, 'total': len(found)}

    def _parse_subdomains(self, output: str) -> dict:
        subs = []
        for line in output.splitlines():
            line = line.strip()
            if (line and '.' in line and not line.startswith('[')
                    and not line.startswith('#') and not line.startswith('Error')
                    and len(line) < 100):
                subs.append(line)
        return {'tool': 'subfinder', 'subdomains': list(set(subs)), 'total': len(set(subs))}

    def _parse_nuclei(self, output: str) -> dict:
        findings = []
        for line in output.splitlines():
            m = re.search(r'\[(critical|high|medium|low|info)\].*\[(.*?)\].*?(https?://\S+)', line, re.I)
            if m:
                findings.append({'severity': m.group(1).upper(), 'template': m.group(2), 'url': m.group(3)})
        return {'tool': 'nuclei', 'findings': findings, 'total': len(findings)}

    def _parse_bruteforce(self, output: str) -> dict:
        creds = []
        for line in output.splitlines():
            if 'login:' in line.lower() and 'password:' in line.lower():
                creds.append(line.strip())
        return {'tool': 'bruteforce', 'credentials': creds, 'found': len(creds) > 0}

    def _parse_searchsploit(self, output: str) -> dict:
        exploits = []
        for line in output.splitlines():
            if '|' in line and not line.startswith('-') and not 'Title' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2:
                    exploits.append({'title': parts[0], 'path': parts[1]})
        return {'tool': 'searchsploit', 'exploits': exploits, 'total': len(exploits)}

    def _parse_cracked(self, output: str) -> dict:
        cracked = []
        for line in output.splitlines():
            if ':' in line and ('cracked' in line.lower() or 'password' in line.lower()):
                cracked.append(line.strip())
        return {'tool': 'hashcrack', 'cracked': cracked, 'found': len(cracked) > 0}

    def _parse_dns(self, output: str) -> dict:
        records = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith(';'):
                records.append(line)
        return {'tool': 'dns', 'records': records}

    def _parse_http(self, output: str) -> dict:
        status = re.search(r'HTTP/\S+\s+(\d+)', output)
        headers = {}
        for line in output.splitlines():
            if ':' in line and not line.startswith('{'):
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()
        return {'tool': 'http', 'status': int(status.group(1)) if status else 0, 'headers': headers}

    def _parse_whatweb(self, output: str) -> dict:
        techs = []
        for line in output.splitlines():
            # WhatWeb format: URL [status] Tech1[version], Tech2
            m = re.search(r'\[\d+\](.+)', line)
            if m:
                parts = m.group(1).split(',')
                for p in parts:
                    t = p.strip()
                    if t and len(t) > 1:
                        techs.append(t)
        return {'tool': 'whatweb', 'technologies': techs, 'total': len(techs)}

    def _parse_wafw00f(self, output: str) -> dict:
        waf = None
        protected = False
        for line in output.splitlines():
            if 'is behind' in line.lower():
                m = re.search(r'is behind (.+?) WAF', line, re.I)
                if m:
                    waf = m.group(1).strip()
                    protected = True
            elif 'no waf detected' in line.lower():
                protected = False
        return {'tool': 'wafw00f', 'waf': waf, 'protected': protected}

    def _parse_ssl(self, output: str) -> dict:
        issues = []
        for line in output.splitlines():
            l = line.strip()
            if any(k in l.lower() for k in ('weak', 'vulnerable', 'deprecated',
                                              'sslv', 'tls 1.0', 'tls 1.1', 'rc4',
                                              'export', 'null', 'anonymous')):
                issues.append(l)
        return {'tool': 'sslscan', 'issues': issues, 'total': len(issues),
                'vulnerable': len(issues) > 0}

    def _parse_masscan(self, output: str) -> dict:
        ports = []
        for line in output.splitlines():
            m = re.search(r'Discovered open port (\d+)/(\w+)', line)
            if m:
                ports.append({'port': int(m.group(1)), 'proto': m.group(2)})
        return {'tool': 'masscan', 'open_ports': ports, 'total': len(ports)}

    def _parse_wpscan(self, output: str) -> dict:
        vulns, plugins, users = [], [], []
        for line in output.splitlines():
            l = line.strip()
            if '| [!]' in l or 'vulnerability' in l.lower():
                vulns.append(l)
            elif '[+] WordPress' in l or 'version' in l.lower():
                plugins.append(l)
            elif '[+] Username' in l or 'user found' in l.lower():
                users.append(l)
        return {'tool': 'wpscan', 'vulnerabilities': vulns, 'info': plugins,
                'users': users, 'total': len(vulns)}

    # ── Tool Chaining ─────────────────────────────────────────────────────────

    def chain_recon(self, target: str) -> dict:
        """
        Full recon chain:
        nmap → httpx → subfinder → nuclei
        Results automatically passed between tools
        """
        results = {}

        # Step 1: nmap
        logger.info(f"[Chain] nmap on {target}")
        r = self.run(f'nmap -sV -sC -T4 --open {target} 2>/dev/null', timeout=120)
        results['nmap'] = r['parsed']
        open_ports = [p['port'] for p in r['parsed'].get('open_ports', [])]

        # Step 2: httpx — agar 80/443/8080 open hai
        web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 8888)]
        if web_ports:
            logger.info(f"[Chain] httpx on {target}")
            r2 = self.run(f'httpx -u {target} -title -status-code -tech-detect -silent 2>/dev/null', timeout=30)
            results['httpx'] = r2['parsed']

        # Step 3: subfinder
        logger.info(f"[Chain] subfinder on {target}")
        r3 = self.run(f'subfinder -d {target} -silent 2>/dev/null | head -50', timeout=60)
        results['subfinder'] = r3['parsed']

        # Step 4: nuclei — agar web ports hain
        if web_ports:
            logger.info(f"[Chain] nuclei on {target}")
            r4 = self.run(
                f'nuclei -u https://{target} -severity critical,high -silent 2>/dev/null | head -30',
                timeout=120
            )
            results['nuclei'] = r4['parsed']

        self._chain_results[target] = results
        return results

    def chain_exploit(self, target: str, recon: dict = None) -> dict:
        """
        Exploit chain based on recon results:
        nikto → sqlmap (agar forms hain) → gobuster → searchsploit
        """
        results = {}
        recon = recon or self._chain_results.get(target, {})

        # nikto
        logger.info(f"[Chain] nikto on {target}")
        r = self.run(f'nikto -h https://{target} -maxtime 60 -nointeractive 2>/dev/null', timeout=90)
        results['nikto'] = r['parsed']

        # gobuster
        logger.info(f"[Chain] gobuster on {target}")
        wordlist = '/usr/share/wordlists/dirb/common.txt'
        if not Path(wordlist).exists():
            wordlist = '/usr/share/dirb/wordlists/common.txt'
        if Path(wordlist).exists():
            r2 = self.run(
                f'gobuster dir -u https://{target} -w {wordlist} -q -t 20 2>/dev/null | head -30',
                timeout=90
            )
            results['gobuster'] = r2['parsed']

        # searchsploit — nmap se service versions leke
        nmap_data = recon.get('nmap', {})
        for port_info in nmap_data.get('open_ports', [])[:5]:
            svc = port_info.get('service', '')
            ver = port_info.get('version', '').split()[0] if port_info.get('version') else ''
            if svc and svc not in ('http', 'https', 'ssh', 'unknown'):
                query = f'{svc} {ver}'.strip()
                r3 = self.run(f'searchsploit "{query}" 2>/dev/null | head -10', timeout=15)
                results[f'searchsploit_{svc}'] = r3['parsed']

        return results

    def chain_osint(self, target: str) -> dict:
        """OSINT chain: sherlock → holehe → theHarvester"""
        results = {}

        if self.tool_available('sherlock'):
            r = self.run(f'sherlock {target} --timeout 5 --print-found 2>/dev/null | head -20', timeout=60)
            results['sherlock'] = r['parsed']

        if self.tool_available('holehe') and '@' in target:
            r = self.run(f'holehe {target} 2>/dev/null | head -20', timeout=30)
            results['holehe'] = r['stdout']

        if self.tool_available('theHarvester'):
            domain = target.split('@')[-1] if '@' in target else target
            r = self.run(f'theHarvester -d {domain} -b all -l 50 2>/dev/null | tail -30', timeout=60)
            results['theHarvester'] = r['stdout']

        return results

    # ── Auto Tool Selection ───────────────────────────────────────────────────

    def auto_select_tools(self, target: str, goal: str) -> list:
        """
        Goal ke hisaab se best tools suggest karo
        goal: 'recon' | 'exploit' | 'osint' | 'password' | 'network'
        """
        goal = goal.lower()
        available = []

        tool_map = {
            'recon':    ['nmap', 'subfinder', 'amass', 'httpx', 'nuclei', 'theHarvester', 'dig', 'whois'],
            'exploit':  ['nikto', 'sqlmap', 'nuclei', 'gobuster', 'ffuf', 'commix', 'xsstrike', 'dalfox', 'msfconsole', 'msfvenom'],
            'osint':    ['sherlock', 'holehe', 'maigret', 'theHarvester', 'phoneinfoga', 'exiftool'],
            'password': ['hydra', 'medusa', 'john', 'hashcat', 'crunch', 'cewl'],
            'network':  ['nmap', 'masscan', 'arp-scan', 'netdiscover', 'tcpdump', 'responder', 'bettercap', 'hping3'],
            'forensics': ['volatility', 'autopsy', 'sleuthkit', 'foremost', 'scalpel', 'binwalk', 'yara', 'strings', 'dd'],
            'metasploit': ['msfconsole', 'msfvenom', 'msfdb', 'searchsploit'],
            'wireless': ['aircrack-ng', 'airmon-ng', 'reaver', 'ettercap'],
        }

        for tool in tool_map.get(goal, []):
            if self.tool_available(tool):
                available.append(tool)

        return available

    # ── File System ───────────────────────────────────────────────────────────

    def read_file(self, path: str, max_bytes: int = 50000) -> dict:
        try:
            content = Path(path).read_text(errors='replace')[:max_bytes]
            return {'success': True, 'content': content, 'path': path, 'size': Path(path).stat().st_size}
        except FileNotFoundError:
            return {'success': False, 'error': f'File not found: {path}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def write_file(self, path: str, content: str, mode: str = 'w') -> dict:
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, mode) as f:
                f.write(content)
            return {'success': True, 'path': path, 'bytes': len(content)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def find_files(self, pattern: str, directory: str = '/home') -> list:
        r = self.run(f'find {directory} -name "{pattern}" 2>/dev/null | head -50', timeout=30)
        return [l.strip() for l in r['stdout'].splitlines() if l.strip()]

    # ── Network ───────────────────────────────────────────────────────────────

    def tool_available(self, tool: str) -> bool:
        r = self.run(f'which {tool} 2>/dev/null', timeout=5)
        return r['success'] and bool(r['stdout'].strip())

    def get_local_ip(self) -> str:
        r = self.run("ip route get 1 2>/dev/null | awk '{print $7}' | head -1", timeout=5)
        return r['stdout'].strip() or 'unknown'

    def check_connectivity(self, host: str = '8.8.8.8') -> bool:
        r = self.run(f'ping -c 1 -W 3 {host} 2>/dev/null', timeout=10)
        return r['success']

    # ── History ───────────────────────────────────────────────────────────────

    def history(self, last: int = 20) -> list:
        with self._lock:
            return self._history[-last:]

    def history_text(self, last: int = 10) -> str:
        parts = []
        for h in self.history(last):
            parts.append(f"$ {h['command']}")
            if h['stdout']:
                parts.append(h['stdout'][:300])
        return '\n'.join(parts)

    def _needs_privilege(self, command: str) -> bool:
        """Check if command needs privilege escalation."""
        try:
            from modules.privilege_manager import privilege_manager
            tool_name = command.split()[0]
            return privilege_manager.needs_privilege(tool_name)
        except Exception:
            return False
    
    @staticmethod
    def _result(cmd, success, stdout, stderr, rc) -> dict:
        return {
            'command': cmd, 'success': success,
            'stdout': stdout, 'stderr': stderr,
            'returncode': rc, 'timestamp': time.time(),
        }
