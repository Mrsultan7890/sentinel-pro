"""
Real Data Collector — GitHub Malware + Threat Intelligence
==========================================================
Real malware samples, CVE exploits, threat reports se
training data collect karta hai.

Sources:
1. MalwareBazaar API — real malware samples + tags
2. GitHub malware analysis repos
3. ExploitDB — real CVE exploits
4. VirusTotal Intelligence (free tier)
5. CISA KEV — Known Exploited Vulnerabilities
6. AlienVault OTX — threat intelligence
"""

import json
import logging
import re
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

import config as _config
MODELS_DIR = _config.get_base_dir() / 'models' / 'ml_engine'
DATA_DIR   = MODELS_DIR / 'training_data'
DATA_DIR.mkdir(parents=True, exist_ok=True)

THREAT_PATH = DATA_DIR / 'threat_raw.jsonl'
REAL_DATA_LOG = DATA_DIR / 'real_data_sources.json'


class RealDataCollector:
    """
    Real-world threat intelligence se training data collect karta hai.
    Yeh data model ko real malware/exploit patterns sikhata hai.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SentinelThreatIntel/2.0 (Security Research)'
        })
        self._existing_urls = self._load_existing_urls()

    def _load_existing_urls(self) -> set:
        seen = set()
        if THREAT_PATH.exists():
            with open(THREAT_PATH) as f:
                for line in f:
                    try: seen.add(json.loads(line).get('url', ''))
                    except: pass
        return seen

    def _save_sample(self, text: str, label: str, url: str, source: str) -> bool:
        if url in self._existing_urls or len(text) < 30:
            return False
        text = text[:2000].strip()
        with open(THREAT_PATH, 'a') as f:
            f.write(json.dumps({
                'text': text, 'label': label,
                'url': url, 'source': source
            }) + '\n')
        self._existing_urls.add(url)
        return True

    # ── 1. MalwareBazaar — Real Malware Samples ───────────────────────────────
    def collect_malwarebazaar(self, limit: int = 500) -> int:
        """
        MalwareBazaar API se real malware samples collect karo.
        Free API — no key needed.
        Tags: ransomware, trojan, backdoor, infostealer, etc.
        """
        logger.info("MalwareBazaar se real malware data collect kar raha hoon...")
        added = 0

        # Tag-based queries — har tag ek threat label map karta hai
        tag_label_map = {
            'ransomware':   'CRITICAL',
            'infostealer':  'CRITICAL',
            'backdoor':     'CRITICAL',
            'trojan':       'CRITICAL',
            'botnet':       'CRITICAL',
            'rootkit':      'CRITICAL',
            'apt':          'CRITICAL',
            'keylogger':    'HIGH',
            'downloader':   'HIGH',
            'dropper':      'HIGH',
            'rat':          'HIGH',
            'spyware':      'HIGH',
            'banker':       'HIGH',
            'cryptominer':  'MEDIUM',
            'adware':       'MEDIUM',
            'pup':          'LOW',
        }

        try:
            for tag, label in tag_label_map.items():
                r = self.session.post(
                    'https://mb-api.abuse.ch/api/v1/',
                    data={'query': 'get_taginfo', 'tag': tag, 'limit': 50},
                    timeout=15
                )
                if r.status_code != 200:
                    continue

                data = r.json()
                if data.get('query_status') != 'ok':
                    continue

                for sample in data.get('data', []):
                    sha256    = sample.get('sha256_hash', '')
                    file_type = sample.get('file_type', '')
                    file_name = sample.get('file_name', '') or ''
                    tags      = sample.get('tags', []) or []
                    signature = sample.get('signature', '') or ''
                    reporter  = sample.get('reporter', '') or ''

                    url_key = f"mb_{sha256[:16]}"

                    # Rich text description banao
                    text = (
                        f"Malware sample: {signature or tag}. "
                        f"Type: {file_type}. "
                        f"Tags: {', '.join(tags[:8])}. "
                        f"File: {file_name[:50]}. "
                        f"SHA256: {sha256[:32]}. "
                        f"Behavior: {tag} malware family detected by threat intelligence."
                    )

                    if self._save_sample(text, label, url_key, 'malwarebazaar'):
                        added += 1

                time.sleep(0.5)  # rate limit

            logger.info(f"  MalwareBazaar: +{added} real malware samples")
        except Exception as e:
            logger.warning(f"MalwareBazaar failed: {e}")

        return added

    # ── 2. CISA KEV — Known Exploited Vulnerabilities ────────────────────────
    def collect_cisa_kev(self) -> int:
        """
        CISA Known Exploited Vulnerabilities catalog.
        Yeh real-world mein actively exploit ho rahe CVEs hain — CRITICAL label.
        Free, no API key.
        """
        logger.info("CISA KEV (Known Exploited Vulnerabilities) collect kar raha hoon...")
        added = 0

        try:
            r = self.session.get(
                'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                timeout=30
            )
            if r.status_code != 200:
                return 0

            vulns = r.json().get('vulnerabilities', [])
            for v in vulns:
                cve_id      = v.get('cveID', '')
                vendor      = v.get('vendorProject', '')
                product     = v.get('product', '')
                vuln_name   = v.get('vulnerabilityName', '')
                description = v.get('shortDescription', '')
                action      = v.get('requiredAction', '')
                due_date    = v.get('dueDate', '')

                url_key = f"cisa_kev_{cve_id}"

                text = (
                    f"{cve_id}: {vuln_name}. "
                    f"Vendor: {vendor}. Product: {product}. "
                    f"{description} "
                    f"Required action: {action}. "
                    f"Actively exploited in the wild. CISA mandated patch by {due_date}."
                )

                # CISA KEV = actively exploited = CRITICAL
                if self._save_sample(text, 'CRITICAL', url_key, 'cisa_kev'):
                    added += 1

            logger.info(f"  CISA KEV: +{added} actively exploited CVEs")
        except Exception as e:
            logger.warning(f"CISA KEV failed: {e}")

        return added

    # ── 3. ExploitDB — Real Exploit Code Descriptions ────────────────────────
    def collect_exploitdb(self, limit: int = 300) -> int:
        """
        ExploitDB se real exploit descriptions collect karo.
        CSV format mein available — no API key needed.
        """
        logger.info("ExploitDB se real exploit data collect kar raha hoon...")
        added = 0

        try:
            # ExploitDB files.csv — exploit metadata
            r = self.session.get(
                'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
                timeout=30
            )
            if r.status_code != 200:
                return 0

            lines = r.text.splitlines()
            # CSV: id,file,description,date_published,author,type,platform,port
            for line in lines[1:limit+1]:  # skip header
                try:
                    parts = line.split(',', 7)
                    if len(parts) < 4:
                        continue
                    exploit_id  = parts[0].strip()
                    description = parts[2].strip().strip('"')
                    date        = parts[3].strip()
                    etype       = parts[5].strip() if len(parts) > 5 else ''
                    platform    = parts[6].strip() if len(parts) > 6 else ''

                    if len(description) < 20:
                        continue

                    url_key = f"edb_{exploit_id}"

                    # Severity based on exploit type
                    desc_lower = description.lower()
                    if any(k in desc_lower for k in ['remote code execution', 'rce', 'command injection', 'buffer overflow']):
                        label = 'CRITICAL'
                    elif any(k in desc_lower for k in ['privilege escalation', 'sql injection', 'authentication bypass']):
                        label = 'HIGH'
                    elif any(k in desc_lower for k in ['xss', 'csrf', 'information disclosure', 'path traversal']):
                        label = 'MEDIUM'
                    else:
                        label = 'LOW'

                    text = (
                        f"Exploit: {description}. "
                        f"Type: {etype}. Platform: {platform}. "
                        f"Published: {date}. ExploitDB ID: {exploit_id}."
                    )

                    if self._save_sample(text, label, url_key, 'exploitdb'):
                        added += 1

                except Exception:
                    continue

            logger.info(f"  ExploitDB: +{added} real exploits")
        except Exception as e:
            logger.warning(f"ExploitDB failed: {e}")

        return added

    # ── 4. AlienVault OTX — Threat Intelligence ──────────────────────────────
    def collect_alienvault_otx(self, limit: int = 200) -> int:
        """
        AlienVault OTX public pulses se threat intelligence collect karo.
        Free public API — no key needed for public pulses.
        """
        logger.info("AlienVault OTX se threat intelligence collect kar raha hoon...")
        added = 0

        try:
            r = self.session.get(
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                params={'limit': limit, 'page': 1},
                timeout=20
            )

            if r.status_code == 401:
                # No API key — use public endpoint
                r = self.session.get(
                    'https://otx.alienvault.com/api/v1/pulses/activity',
                    params={'limit': limit},
                    timeout=20
                )

            if r.status_code != 200:
                return 0

            pulses = r.json().get('results', [])
            for pulse in pulses:
                pulse_id    = pulse.get('id', '')
                name        = pulse.get('name', '')
                description = pulse.get('description', '') or ''
                tags        = pulse.get('tags', []) or []
                tlp         = pulse.get('tlp', 'white')
                malware     = pulse.get('malware_families', []) or []
                attack_ids  = pulse.get('attack_ids', []) or []

                url_key = f"otx_{pulse_id}"

                # Label from tags/malware
                all_tags = ' '.join(tags + [m.get('display_name', '') for m in malware]).lower()
                if any(k in all_tags for k in ['ransomware', 'apt', 'backdoor', 'infostealer', 'rootkit']):
                    label = 'CRITICAL'
                elif any(k in all_tags for k in ['trojan', 'rat', 'exploit', 'phishing', 'keylogger']):
                    label = 'HIGH'
                elif any(k in all_tags for k in ['malware', 'botnet', 'cryptominer', 'dropper']):
                    label = 'MEDIUM'
                else:
                    label = 'LOW'

                text = (
                    f"Threat: {name}. "
                    f"{description[:500]} "
                    f"Tags: {', '.join(tags[:10])}. "
                    f"Malware families: {', '.join(m.get('display_name','') for m in malware[:5])}. "
                    f"ATT&CK: {', '.join(a.get('id','') for a in attack_ids[:5])}."
                )

                if self._save_sample(text, label, url_key, 'alienvault_otx'):
                    added += 1

            logger.info(f"  AlienVault OTX: +{added} threat pulses")
        except Exception as e:
            logger.warning(f"AlienVault OTX failed: {e}")

        return added

    # ── 5. GitHub Malware Analysis Repos ─────────────────────────────────────
    def collect_github_malware_repos(self, token: str = None) -> int:
        """
        GitHub pe real malware analysis repos se data collect karo.
        Repos: theZoo, malware-samples, vx-underground writeups, etc.
        """
        logger.info("GitHub malware analysis repos se data collect kar raha hoon...")
        added = 0

        headers = {'Accept': 'application/vnd.github+json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        else:
            try:
                import config as _cfg
                if _cfg.GITHUB_TOKEN:
                    headers['Authorization'] = f'Bearer {_cfg.GITHUB_TOKEN}'
            except Exception:
                pass

        # Real malware analysis repos
        malware_repos = [
            # Malware samples + analysis
            ('ytisf/theZoo',                    'CRITICAL', 'malware samples repository live malware'),
            ('vxunderground/MalwareSourceCode',  'CRITICAL', 'malware source code analysis'),
            ('rshipp/awesome-malware-analysis',  'HIGH',     'malware analysis tools techniques'),
            ('mstfknn/malware-sample-library',   'CRITICAL', 'malware sample library'),
            # Threat intelligence
            ('hslatman/awesome-threat-intelligence', 'HIGH', 'threat intelligence feeds'),
            ('Neo23x0/signature-base',           'HIGH',     'YARA rules malware signatures'),
            ('InQuest/malware-iocs',             'CRITICAL', 'malware indicators of compromise'),
            # Exploit development
            ('offensive-security/exploitdb',     'HIGH',     'exploit database proof of concept'),
            ('rapid7/metasploit-framework',      'HIGH',     'penetration testing exploit modules'),
            # OSINT
            ('jivoi/awesome-osint',              'LOW',      'OSINT tools techniques investigation'),
        ]

        for repo_path, label, context in malware_repos:
            url_key = f"gh_mal_{repo_path.replace('/', '_')}"
            if url_key in self._existing_urls:
                continue

            try:
                # README fetch karo
                readme_url = f"https://raw.githubusercontent.com/{repo_path}/HEAD/README.md"
                r = self.session.get(readme_url, timeout=15)
                if r.status_code != 200:
                    continue

                # Clean markdown
                text = re.sub(r'```[\s\S]*?```', '', r.text)
                text = re.sub(r'[#*`>\[\]()]', '', text)
                text = re.sub(r'https?://\S+', '', text)
                text = ' '.join(text.split())[:2000]

                if len(text) >= 100:
                    full_text = f"{context}. {text}"[:2000]
                    if self._save_sample(full_text, label, url_key, 'github_malware'):
                        added += 1

                # Sections bhi collect karo
                sections = re.split(r'\n#{1,3} ', r.text)
                for i, section in enumerate(sections[1:15]):
                    sec_text = re.sub(r'```[\s\S]*?```', '', section)
                    sec_text = re.sub(r'[#*`>\[\]()]', '', sec_text)
                    sec_text = re.sub(r'https?://\S+', '', sec_text)
                    sec_text = ' '.join(sec_text.split())[:1000]
                    if len(sec_text) >= 80:
                        sec_key = f"{url_key}_s{i}"
                        if self._save_sample(f"{context}. {sec_text}", label, sec_key, 'github_malware'):
                            added += 1

                time.sleep(0.5)

            except Exception as e:
                logger.debug(f"  {repo_path} failed: {e}")

        logger.info(f"  GitHub malware repos: +{added} samples")
        return added

    # ── 6. Abuse.ch URLhaus — Malicious URLs ─────────────────────────────────
    def collect_urlhaus(self, limit: int = 200) -> int:
        """
        URLhaus se malicious URL patterns collect karo.
        Real phishing/malware distribution URLs.
        """
        logger.info("URLhaus se malicious URL data collect kar raha hoon...")
        added = 0

        try:
            r = self.session.post(
                'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                data={'limit': limit},
                timeout=15
            )
            if r.status_code != 200:
                return 0

            urls_data = r.json().get('urls', [])
            for item in urls_data:
                url_id   = item.get('id', '')
                url      = item.get('url', '')
                url_status = item.get('url_status', '')
                threat   = item.get('threat', '')
                tags     = item.get('tags', []) or []
                host     = item.get('host', '')

                url_key = f"urlhaus_{url_id}"

                # Label from threat type
                threat_lower = threat.lower()
                if 'malware' in threat_lower or 'botnet' in threat_lower:
                    label = 'CRITICAL'
                elif 'phishing' in threat_lower:
                    label = 'HIGH'
                else:
                    label = 'MEDIUM'

                text = (
                    f"Malicious URL detected: {threat}. "
                    f"Host: {host}. Status: {url_status}. "
                    f"Tags: {', '.join(tags[:5])}. "
                    f"URL pattern indicates {threat} distribution infrastructure."
                )

                if self._save_sample(text, label, url_key, 'urlhaus'):
                    added += 1

            logger.info(f"  URLhaus: +{added} malicious URL patterns")
        except Exception as e:
            logger.warning(f"URLhaus failed: {e}")

        return added

    # ── Main Collection ───────────────────────────────────────────────────────
    def collect_all(self, github_token: str = None) -> dict:
        """
        Sab sources se real threat data collect karo.
        """
        stats = {}

        stats['malwarebazaar'] = self.collect_malwarebazaar(limit=500)
        stats['cisa_kev']      = self.collect_cisa_kev()
        stats['exploitdb']     = self.collect_exploitdb(limit=300)
        stats['urlhaus']       = self.collect_urlhaus(limit=200)
        stats['otx']           = self.collect_alienvault_otx(limit=200)
        stats['github_malware']= self.collect_github_malware_repos(token=github_token)

        stats['total'] = sum(stats.values())

        # Log sources
        with open(REAL_DATA_LOG, 'w') as f:
            json.dump({
                'collected_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'stats': stats,
            }, f, indent=2)

        # Final count
        if THREAT_PATH.exists():
            with open(THREAT_PATH) as f:
                total_samples = sum(1 for l in f if l.strip())
            stats['total_in_file'] = total_samples

        return stats
