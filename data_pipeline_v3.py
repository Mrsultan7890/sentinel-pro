"""
Data Pipeline v4.0 — Generative Training Data Builder (Balanced)
=================================================================
Seq2Seq training data banata hai — 3 tasks:
  cmd_gen    — context → exact kali command
  report_gen — findings → professional report paragraph
  chain_gen  — current tool + finding → next tool

v4 Changes:
- Balanced cmd_gen: har tool ~1000 samples (searchsploit cap 1000)
- Synthetic cmd_gen: missing tools ke liye direct samples
- Expanded chain_gen: 40+ transitions, 200 samples per transition
- Better report_gen: unknown/exploit types replaced with real templates
- all_repos_training.jsonl bhi load karta hai (naya source)

Author: @who_is_the_black_hat
"""

import json
import logging
import random
import re
import time
from collections import Counter
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

DATA_DIR   = Path('models/ml_engine/training_data')
OUTPUT     = DATA_DIR / 'generative_training.jsonl'

# ── Command Templates ─────────────────────────────────────────────────────────
# tool_name → list of command templates
# {target} placeholder — runtime mein replace hoga
CMD_TEMPLATES = {
    'nmap': [
        'nmap -sV -sC -T4 --open {target}',
        'nmap -sV -p 80,443,8080,8443 {target}',
        'nmap -sV -sC -p- --min-rate 5000 {target}',
        'nmap -sU -sV --top-ports 100 {target}',
        'nmap -sV -sC -T4 -oN nmap_{target}.txt {target}',
        'nmap -A -T4 {target}',
        'nmap -sV --script vuln {target}',
    ],
    'nikto': [
        'nikto -h https://{target} -maxtime 60 -nointeractive',
        'nikto -h http://{target} -Tuning 1,2,3,4,5',
        'nikto -h https://{target} -ssl -nointeractive',
        'nikto -h https://{target} -maxtime 120 -nointeractive',
    ],
    'nuclei': [
        'nuclei -u https://{target} -severity critical,high -silent',
        'nuclei -u https://{target} -t cves/ -silent',
        'nuclei -u https://{target} -t exposures/ -severity critical,high,medium -silent',
        'nuclei -u https://{target} -t misconfiguration/ -silent',
        'nuclei -u https://{target} -t vulnerabilities/ -silent',
        'nuclei -u https://{target} -t technologies/ -silent',
        'nuclei -u https://{target} -severity critical -silent',
    ],
    'sqlmap': [
        'sqlmap -u "https://{target}" --batch --level=2 --risk=2 --forms',
        'sqlmap -u "https://{target}/login" --batch --dbs --forms',
        'sqlmap -u "https://{target}" --batch --crawl=2 --forms',
        'sqlmap -u "https://{target}" --batch --level=3 --risk=2 --dbs',
        'sqlmap -u "https://{target}" --batch --dump --forms',
    ],
    'gobuster': [
        'gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -t 30 -q',
        'gobuster dir -u https://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20',
        'gobuster dns -d {target} -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -q',
        'gobuster dir -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -t 30',
        'gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/big.txt -t 20 -q',
        'gobuster vhost -u https://{target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    ],
    'ffuf': [
        'ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s',
        'ffuf -u https://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301 -s',
        'ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302 -s',
        'ffuf -u https://{target}/?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -s',
        'ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/big.txt -mc 200,301,302,403,500 -s',
    ],
    'amass': [
        'amass enum -passive -d {target} -timeout 5',
        'amass enum -active -d {target} -timeout 10',
        'amass enum -passive -d {target} -o amass_{target}.txt',
        'amass intel -d {target} -whois',
    ],
    'subfinder': [
        'subfinder -d {target} -silent',
        'subfinder -d {target} -o subfinder_{target}.txt',
        'subfinder -d {target} -all -silent',
        'subfinder -d {target} -recursive -silent',
    ],
    'whatweb': [
        'whatweb https://{target} --color=never',
        'whatweb -a 3 https://{target} --color=never',
        'whatweb -a 4 https://{target} --color=never',
        'whatweb https://{target} --log-json=whatweb_{target}.json',
    ],
    'wafw00f': [
        'wafw00f https://{target}',
        'wafw00f -a https://{target}',
        'wafw00f -v https://{target}',
    ],
    'sslscan': [
        'sslscan --no-colour {target}',
        'sslscan --no-colour --show-certificate {target}',
        'sslscan --no-colour --tlsall {target}',
        'sslscan --no-colour --show-ciphers {target}',
    ],
    'theHarvester': [
        'theHarvester -d {target} -b bing,google,yahoo -l 50',
        'theHarvester -d {target} -b all -l 100',
        'theHarvester -d {target} -b google -l 200',
        'theHarvester -d {target} -b bing -l 100 -f harvester_{target}',
    ],
    'searchsploit': [
        'searchsploit {target}',
        'searchsploit --www {target}',
        'searchsploit -t {target}',
        'searchsploit --id {target}',
    ],
    'commix': [
        'commix --url="https://{target}" --batch --level=1',
        'commix --url="https://{target}/?id=1" --batch',
        'commix --url="https://{target}" --batch --all-techniques',
    ],
    'wpscan': [
        'wpscan --url https://{target} --no-update --enumerate u,p',
        'wpscan --url https://{target} --no-update --enumerate vp',
        'wpscan --url https://{target} --no-update --enumerate ap,at,cb,dbe',
        'wpscan --url https://{target} --no-update --passwords /usr/share/wordlists/rockyou.txt',
    ],
    'enum4linux': [
        'enum4linux -a {target}',
        'enum4linux -U -S {target}',
        'enum4linux -u admin -p admin {target}',
        'enum4linux -G {target}',
    ],
    'hydra': [
        'hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} http-post-form',
        'hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh',
        'hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} ftp',
        'hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-get /',
        'hydra -C /usr/share/wordlists/metasploit/http_default_userpass.txt {target} http-get /',
    ],
    'masscan': [
        'masscan {target} -p1-65535 --rate=1000',
        'masscan {target} -p80,443,8080,8443 --rate=5000',
        'masscan {target} -p1-10000 --rate=2000',
        'masscan {target} --top-ports 1000 --rate=1000',
    ],
    'hashcat': [
        'hashcat -m 0 {target} /usr/share/wordlists/rockyou.txt',
        'hashcat -m 1000 {target} /usr/share/wordlists/rockyou.txt',
        'hashcat -m 1800 {target} /usr/share/wordlists/rockyou.txt --force',
        'hashcat -m 0 {target} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule',
    ],
    'john': [
        'john {target} --wordlist=/usr/share/wordlists/rockyou.txt',
        'john {target} --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt',
        'john {target} --show',
        'john {target} --wordlist=/usr/share/wordlists/rockyou.txt --rules',
    ],
}

# ── Report Templates ──────────────────────────────────────────────────────────
# (label, threat_type) → report paragraph templates
REPORT_TEMPLATES = {
    ('CRITICAL', 'web_vuln'): [
        "CRITICAL vulnerability confirmed on {target}. Immediate remediation required. SQL injection detected on login endpoint — attacker can extract full database. Recommend: disable affected endpoint, apply parameterized queries, rotate all database credentials.",
        "Critical web vulnerability identified: Remote Code Execution possible via {target}. Attack surface is fully exposed. Immediate action: isolate server, apply emergency patch, notify security team and management.",
        "CRITICAL: Server-Side Template Injection confirmed on {target}. Attacker can execute arbitrary OS commands. Immediate patch required. Disable template rendering from user input, sanitize all inputs.",
        "Critical LFI/RFI vulnerability on {target} allows reading sensitive files including /etc/passwd and application configs. Patch immediately, implement input validation and path traversal protection.",
    ],
    ('CRITICAL', 'breach'): [
        "Active credential breach detected for {target}. Plaintext passwords found in stealer logs. Immediate action: force password reset for all affected accounts, enable MFA, revoke all active sessions.",
        "CRITICAL: {target} credentials exposed in multiple breach databases. Infostealer logs confirm active compromise. Rotate all secrets immediately, audit access logs for unauthorized activity.",
        "Credential dump confirmed for {target}. Database with {count} user records leaked. Force password reset, notify affected users, engage legal team for breach notification compliance.",
    ],
    ('CRITICAL', 'malware'): [
        "Malware indicators detected on {target}. C2 communication patterns identified. Immediate isolation required. Initiate incident response procedure, preserve forensic evidence before remediation.",
        "Active malware infection confirmed. {target} is communicating with known C2 infrastructure. Isolate system immediately, collect memory dump, engage IR team.",
        "Ransomware indicators found on {target}. File encryption activity detected. Immediately isolate from network, do not pay ransom, restore from clean backup, engage IR team.",
    ],
    ('CRITICAL', 'apt'): [
        "APT indicators present on {target}. Lateral movement detected across network segments. Escalate to SOC immediately. Preserve all logs and forensic artifacts for investigation.",
        "Advanced Persistent Threat activity confirmed. {target} shows signs of long-term compromise. Engage threat hunting team, review all privileged account activity for past 90 days.",
        "Nation-state level attack detected on {target}. Cobalt Strike beacon identified. Full incident response required. Preserve evidence, notify CISO, engage external IR firm.",
    ],
    ('CRITICAL', 'exploit'): [
        "Critical exploit confirmed on {target}. CVE with CVSS 9.8+ actively exploited. Emergency patch required within 24 hours. Isolate affected systems, apply vendor patch or implement WAF rule as temporary mitigation.",
        "Zero-day exploit detected targeting {target}. No patch available. Implement compensating controls: WAF rules, network segmentation, enhanced monitoring. Escalate to vendor immediately.",
    ],
    ('CRITICAL', 'misconfig'): [
        "Critical misconfiguration on {target}: DNS zone transfer allowed, exposing full DNS infrastructure. Disable AXFR on all nameservers immediately. Audit all exposed DNS records.",
        "CRITICAL: Subdomain takeover confirmed on {target}. Attacker can serve malicious content under your domain. Remove dangling DNS records immediately, implement subdomain monitoring.",
    ],
    ('HIGH', 'web_vuln'): [
        "High severity web vulnerability found on {target}. XSS and CORS misconfiguration allow session hijacking. Schedule urgent patch within 24 hours. Implement Content Security Policy headers.",
        "High risk: {target} exposes sensitive endpoints without authentication. Directory traversal and information disclosure confirmed. Apply access controls and security headers immediately.",
        "High severity: JWT none algorithm accepted on {target}. Authentication bypass possible. Enforce algorithm validation, rotate all tokens, implement proper JWT verification.",
        "CORS misconfiguration on {target} allows cross-origin requests with credentials. Restrict allowed origins to trusted domains only. Audit all CORS policies.",
    ],
    ('HIGH', 'recon'): [
        "Extensive reconnaissance activity detected against {target}. {count} subdomains enumerated, {ports} open ports identified. Harden attack surface: close unnecessary ports, implement rate limiting.",
        "Active recon confirmed on {target}. Attacker has mapped full infrastructure. Review firewall rules, implement geo-blocking, enable IDS/IPS alerting.",
        "Recon findings: {target} exposes {count} subdomains, technology stack fingerprinted. Implement security headers to reduce information disclosure, monitor for follow-up attacks.",
    ],
    ('HIGH', 'breach'): [
        "Credential exposure confirmed for {target}. Found in {count} breach databases. Force immediate password reset, audit all recent logins for suspicious activity.",
        "High risk breach: {target} credentials available on dark web markets. Enable MFA immediately, review and revoke suspicious OAuth tokens.",
        "GitHub secrets exposed for {target}. API keys and tokens found in public repositories. Rotate all exposed credentials immediately, implement secret scanning in CI/CD pipeline.",
    ],
    ('HIGH', 'misconfig'): [
        "Dangerous misconfiguration on {target}: S3 bucket publicly accessible, exposing sensitive files. Restrict bucket policy immediately, audit all cloud storage permissions.",
        "Security misconfiguration: {target} exposes admin panel without authentication. Restrict access to trusted IPs, implement strong authentication.",
        "High risk: {target} running outdated software with known vulnerabilities. {count} CVEs identified. Schedule emergency patching, implement WAF rules as temporary mitigation.",
    ],
    ('HIGH', 'phishing'): [
        "Phishing infrastructure detected targeting {target} users. Spoofed domain registered {count} days ago. Implement DMARC/DKIM/SPF, report to registrar, notify users.",
        "Spearphishing campaign targeting {target} employees detected. Malicious attachments with macro payloads identified. Block sender domains, run endpoint scan, user awareness training.",
    ],
    ('HIGH', 'exploit'): [
        "High severity exploit available for services running on {target}. {count} exploits found in ExploitDB. Patch affected services within 48 hours, implement network segmentation.",
        "Searchsploit found {count} exploits for technology stack on {target}. Prioritize patching of internet-facing components. Implement WAF rules for immediate protection.",
    ],
    ('MEDIUM', 'recon'): [
        "Reconnaissance findings for {target}: {count} subdomains discovered, technology stack identified. Monitor for escalation. Recommend: implement subdomain monitoring, review exposed services.",
        "Medium risk recon: {target} exposes version information and technology fingerprints. Implement security headers to reduce information disclosure.",
        "Subdomain enumeration complete for {target}: {count} subdomains found. Review each for unnecessary exposure. Implement wildcard DNS monitoring.",
    ],
    ('MEDIUM', 'web_vuln'): [
        "Medium severity findings on {target}: Missing security headers (CSP, HSTS, X-Frame-Options). Implement recommended headers to reduce attack surface.",
        "Vulnerability assessment of {target}: Outdated software versions detected. Schedule patching cycle, prioritize internet-facing components.",
        "Clickjacking vulnerability on {target}: X-Frame-Options header missing. Implement frame-ancestors CSP directive. Low exploitation complexity.",
        "Cookie security issues on {target}: HttpOnly and Secure flags missing on session cookies. Update cookie configuration to prevent XSS-based session theft.",
    ],
    ('MEDIUM', 'misconfig'): [
        "Misconfiguration detected on {target}: Default credentials in use on admin interface. Change all default passwords, implement account lockout policy.",
        "Security gap: {target} allows HTTP (unencrypted) connections. Enforce HTTPS redirect, implement HSTS with long max-age.",
        "SSL/TLS misconfiguration on {target}: TLS 1.0/1.1 enabled, weak cipher suites present. Disable legacy protocols, enforce TLS 1.2+ with strong ciphers.",
    ],
    ('MEDIUM', 'breach'): [
        "Credential exposure for {target}: Found in {count} older breach databases. Passwords likely changed but recommend forced reset. Enable MFA as additional protection.",
        "Email addresses for {target} domain found in breach data. No plaintext passwords but usernames exposed. Monitor for credential stuffing attacks, implement rate limiting on login.",
    ],
    ('MEDIUM', 'phishing'): [
        "Phishing indicators for {target}: Suspicious email patterns detected. Implement email filtering, user awareness training recommended.",
        "Social engineering risk for {target}: Employee information exposed via OSINT. Limit public exposure of employee details, implement security awareness program.",
    ],
    ('LOW', 'recon'): [
        "Low-level probe detected against {target}. Standard reconnaissance activity. Log and monitor. No immediate action required.",
        "Informational: {target} exposes non-sensitive version information. Consider implementing security headers to reduce fingerprinting.",
        "Passive recon complete for {target}. No sensitive information exposed. Security posture appears adequate for current threat level.",
    ],
    ('LOW', 'misconfig'): [
        "Minor misconfiguration on {target}: Non-critical security headers missing. Implement as part of next scheduled maintenance window.",
        "Low risk finding: {target} exposes server version in HTTP headers. Suppress version information to reduce fingerprinting surface.",
    ],
    ('LOW', 'unknown'): [
        "Scan completed for {target}. No critical vulnerabilities identified. Continue standard monitoring and scheduled patching.",
        "Assessment of {target}: Security posture is acceptable. Recommend periodic re-assessment and keeping software up to date.",
        "Clean scan result for {target}. SSL grade A, security headers configured, no known vulnerabilities detected. Maintain current security posture.",
    ],
}

# ── Chain Templates ───────────────────────────────────────────────────────────
# (current_tool, finding_type) → next_tool
CHAIN_LOGIC = {
    # nmap findings
    ('nmap',         'open_web_port'):      ['nikto', 'nuclei', 'gobuster', 'whatweb', 'wafw00f'],
    ('nmap',         'open_db_port'):       ['sqlmap', 'nuclei', 'searchsploit'],
    ('nmap',         'open_smb_port'):      ['enum4linux', 'searchsploit', 'hydra'],
    ('nmap',         'open_ssh_port'):      ['hydra', 'searchsploit'],
    ('nmap',         'open_ftp_port'):      ['hydra', 'searchsploit', 'nikto'],
    ('nmap',         'service_detected'):   ['searchsploit', 'nuclei', 'whatweb'],
    ('nmap',         'os_detected'):        ['searchsploit', 'nuclei'],
    # nikto findings
    ('nikto',        'vuln_found'):         ['sqlmap', 'nuclei', 'commix'],
    ('nikto',        'cms_detected'):       ['wpscan', 'nuclei'],
    ('nikto',        'xss_found'):          ['nuclei', 'sqlmap'],
    ('nikto',        'dir_found'):          ['gobuster', 'ffuf'],
    ('nikto',        'info_disclosure'):    ['nuclei', 'gobuster'],
    # gobuster/ffuf findings
    ('gobuster',     'dir_found'):          ['nikto', 'nuclei', 'ffuf'],
    ('gobuster',     'admin_found'):        ['nikto', 'nuclei', 'hydra'],
    ('gobuster',     'backup_found'):       ['nuclei', 'nikto'],
    ('ffuf',         'param_found'):        ['sqlmap', 'nuclei', 'commix'],
    ('ffuf',         'endpoint_found'):     ['nikto', 'nuclei'],
    # nuclei findings
    ('nuclei',       'cve_found'):          ['searchsploit', 'sqlmap'],
    ('nuclei',       'misconfig_found'):    ['nikto', 'gobuster'],
    ('nuclei',       'exposure_found'):     ['gobuster', 'ffuf'],
    # whatweb/wafw00f findings
    ('whatweb',      'tech_found'):         ['searchsploit', 'nuclei', 'nikto'],
    ('whatweb',      'cms_found'):          ['wpscan', 'nuclei'],
    ('whatweb',      'version_found'):      ['searchsploit', 'nuclei'],
    ('wafw00f',      'no_waf'):             ['sqlmap', 'commix', 'nuclei', 'nikto'],
    ('wafw00f',      'waf_found'):          ['nuclei', 'ffuf'],
    # subdomain tools
    ('amass',        'subdomain_found'):    ['nmap', 'nuclei', 'gobuster', 'whatweb'],
    ('subfinder',    'subdomain_found'):    ['nmap', 'nuclei', 'gobuster'],
    ('subfinder',    'many_subdomains'):    ['nmap', 'nuclei', 'amass'],
    # theHarvester findings
    ('theHarvester', 'email_found'):        ['breach', 'nuclei'],
    ('theHarvester', 'domain_found'):       ['nmap', 'nuclei', 'gobuster'],
    ('theHarvester', 'host_found'):         ['nmap', 'nuclei'],
    # sqlmap findings
    ('sqlmap',       'sqli_found'):         ['nuclei', 'commix'],
    ('sqlmap',       'db_found'):           ['nuclei', 'searchsploit'],
    # sslscan findings
    ('sslscan',      'weak_ssl'):           ['nuclei', 'nikto'],
    ('sslscan',      'expired_cert'):       ['nuclei'],
    ('sslscan',      'weak_cipher'):        ['nuclei', 'nikto'],
    # hydra/hashcat findings
    ('hydra',        'cred_found'):         ['nuclei', 'searchsploit'],
    ('hashcat',      'hash_cracked'):       ['nuclei', 'searchsploit'],
    # wpscan findings
    ('wpscan',       'plugin_vuln'):        ['searchsploit', 'nuclei'],
    ('wpscan',       'user_found'):         ['hydra', 'nuclei'],
    # enum4linux findings
    ('enum4linux',   'share_found'):        ['searchsploit', 'hydra'],
    ('enum4linux',   'user_found'):         ['hydra', 'searchsploit'],
    # masscan findings
    ('masscan',      'port_found'):         ['nmap', 'nuclei'],
    ('masscan',      'many_ports'):         ['nmap', 'nikto', 'nuclei'],
    # searchsploit findings
    ('searchsploit', 'exploit_found'):      ['nuclei', 'commix'],
    # commix findings
    ('commix',       'cmdi_found'):         ['nuclei', 'searchsploit'],
}


class GenerativeDataBuilder:
    """
    Existing data ko 3 task types mein convert karta hai:
    1. cmd_gen    — context → exact command
    2. report_gen — findings → report paragraph
    3. chain_gen  — current state → next tool
    """

    def __init__(self):
        self.stats = Counter()

    # ── Task 1: Command Generation ────────────────────────────────────────────

    def build_cmd_gen_samples(self, source_samples: list) -> list:
        """
        cmd_gen samples banao — balanced per tool.
        1. Source data se (combined + payloads + all_repos)
        2. Synthetic samples — missing tools ke liye direct generation
        """
        results = []
        placeholder = 'TARGET_DOMAIN'
        tool_counts = Counter()

        # Per-tool target count — balanced
        TARGET_PER_TOOL = 1000
        # searchsploit cap — imbalance fix
        TOOL_CAPS = {t: TARGET_PER_TOOL for t in CMD_TEMPLATES}
        TOOL_CAPS['searchsploit'] = 800
        TOOL_CAPS['nmap']         = 1200
        TOOL_CAPS['nuclei']       = 1200

        # 1. Source data se
        random.shuffle(source_samples)
        for s in source_samples:
            # next_tool (old format) ya tool (new_repos format) dono handle karo
            tool = s.get('next_tool', '') or s.get('tool', '')
            tool = tool.strip() if tool else ''
            if not tool or tool not in CMD_TEMPLATES:
                continue
            if tool_counts[tool] >= TOOL_CAPS.get(tool, TARGET_PER_TOOL):
                continue

            # new_repos mein 'input'/'output' fields hain, old format mein 'text'
            text  = s.get('text', '') or s.get('input', '')
            text  = text.strip()
            label = s.get('label', 'MEDIUM')
            ttype = s.get('threat_type', 'unknown')
            ahint = s.get('action_hint', 'monitor')
            if len(text) < 20:
                continue

            # output field (new_repos cmd) ya output_cmd (old) ya template
            if s.get('output') and s.get('task') == 'cmd_gen':
                cmd = s['output']
            elif s.get('output_cmd'):
                cmd = s['output_cmd']
            else:
                cmd = random.choice(CMD_TEMPLATES[tool]).replace('{target}', placeholder)

            results.append({
                'input':       f"[SCAN_CONTEXT] {text[:400].strip()} [THREAT] {label} [TYPE] {ttype}",
                'output':      cmd,
                'task':        'cmd_gen',
                'label':       label,
                'threat_type': ttype,
                'action_hint': ahint,
                'tool':        tool,
            })
            tool_counts[tool] += 1
            self.stats['cmd_gen'] += 1

        # 2. Synthetic samples — missing/low tools ke liye
        SYNTHETIC_CONTEXTS = {
            'gobuster': [
                ("web application found on port 80 443 directory enumeration needed", "HIGH", "web_vuln", "investigate"),
                ("nikto scan found interesting paths need deeper directory brute force", "HIGH", "web_vuln", "investigate"),
                ("target has web server running need to find hidden directories admin panels", "HIGH", "web_vuln", "investigate"),
                ("recon complete web ports open gobuster directory scan required", "MEDIUM", "recon", "investigate"),
                ("admin panel suspected need directory brute force to confirm location", "HIGH", "web_vuln", "patch_now"),
            ],
            'ffuf': [
                ("parameter fuzzing needed on web application endpoints", "HIGH", "web_vuln", "investigate"),
                ("web app has dynamic parameters need fuzzing for hidden params", "HIGH", "web_vuln", "investigate"),
                ("gobuster found endpoints need parameter discovery with ffuf", "HIGH", "web_vuln", "investigate"),
                ("api endpoint discovered need to fuzz parameters for vulnerabilities", "CRITICAL", "web_vuln", "patch_now"),
                ("directory found need file fuzzing to discover backup config files", "HIGH", "web_vuln", "investigate"),
            ],
            'subfinder': [
                ("domain recon needed subdomain enumeration first step", "MEDIUM", "recon", "investigate"),
                ("target domain identified need passive subdomain enumeration", "MEDIUM", "recon", "investigate"),
                ("initial recon phase subdomain discovery required", "LOW", "recon", "monitor"),
                ("attack surface mapping subdomain enumeration with subfinder", "MEDIUM", "recon", "investigate"),
                ("passive recon subfinder to find all subdomains without active scanning", "LOW", "recon", "monitor"),
            ],
            'amass': [
                ("comprehensive subdomain enumeration needed active and passive", "MEDIUM", "recon", "investigate"),
                ("subfinder found subdomains need deeper enumeration with amass", "MEDIUM", "recon", "investigate"),
                ("attack surface mapping amass for thorough subdomain discovery", "HIGH", "recon", "investigate"),
                ("domain intelligence gathering amass intel whois information", "MEDIUM", "recon", "investigate"),
            ],
            'whatweb': [
                ("web server detected need technology fingerprinting", "MEDIUM", "recon", "investigate"),
                ("nmap found web ports need to identify technology stack", "MEDIUM", "recon", "investigate"),
                ("target web application technology identification required", "LOW", "recon", "monitor"),
                ("cms detection needed before vulnerability scanning", "MEDIUM", "recon", "investigate"),
            ],
            'wafw00f': [
                ("web application firewall detection before active scanning", "MEDIUM", "recon", "investigate"),
                ("need to check if WAF present before sqlmap nuclei scan", "MEDIUM", "recon", "investigate"),
                ("waf detection required to adjust scanning strategy", "LOW", "recon", "monitor"),
                ("target may have WAF need to detect before exploitation attempts", "HIGH", "web_vuln", "investigate"),
            ],
            'sslscan': [
                ("ssl tls configuration check needed on web server", "MEDIUM", "misconfig", "patch_now"),
                ("https service found need ssl vulnerability assessment", "MEDIUM", "misconfig", "patch_now"),
                ("tls version and cipher suite audit required", "MEDIUM", "misconfig", "investigate"),
                ("certificate and ssl configuration review for compliance", "LOW", "misconfig", "monitor"),
                ("weak ssl detected need full sslscan assessment", "HIGH", "misconfig", "patch_now"),
            ],
            'theHarvester': [
                ("email harvesting needed for target domain osint", "MEDIUM", "recon", "investigate"),
                ("domain osint email address collection theHarvester", "MEDIUM", "recon", "investigate"),
                ("employee email discovery for phishing assessment", "HIGH", "phishing", "investigate"),
                ("passive recon email and subdomain harvesting", "LOW", "recon", "monitor"),
            ],
            'hydra': [
                ("login form found need brute force testing", "HIGH", "breach", "block_ip"),
                ("ssh service open weak password check required", "HIGH", "breach", "block_ip"),
                ("ftp service detected default credential check", "HIGH", "breach", "investigate"),
                ("admin panel found need credential brute force", "CRITICAL", "breach", "block_ip"),
                ("authentication endpoint discovered hydra brute force", "HIGH", "breach", "block_ip"),
            ],
            'wpscan': [
                ("wordpress cms detected need vulnerability scan", "HIGH", "web_vuln", "patch_now"),
                ("whatweb identified wordpress installation", "HIGH", "web_vuln", "patch_now"),
                ("cms fingerprinted as wordpress wpscan required", "HIGH", "web_vuln", "investigate"),
                ("wordpress site found enumerate plugins themes users", "HIGH", "web_vuln", "patch_now"),
            ],
            'commix': [
                ("command injection suspected in web application parameter", "CRITICAL", "web_vuln", "patch_now"),
                ("nikto found potential command injection vulnerability", "CRITICAL", "web_vuln", "patch_now"),
                ("ssti found possible command injection via template", "CRITICAL", "web_vuln", "patch_now"),
                ("user input passed to system command need commix test", "CRITICAL", "web_vuln", "patch_now"),
            ],
            'enum4linux': [
                ("smb port 445 139 open need enumeration", "HIGH", "recon", "investigate"),
                ("windows target smb shares user enumeration", "HIGH", "recon", "investigate"),
                ("nmap found smb service enum4linux for details", "HIGH", "recon", "investigate"),
                ("samba service detected need full enumeration", "HIGH", "recon", "investigate"),
            ],
            'masscan': [
                ("fast port scan needed on large ip range", "MEDIUM", "recon", "investigate"),
                ("network range scan masscan for quick port discovery", "MEDIUM", "recon", "investigate"),
                ("initial fast scan before detailed nmap scan", "LOW", "recon", "monitor"),
                ("large subnet port discovery masscan high speed", "MEDIUM", "recon", "investigate"),
            ],
            'hashcat': [
                ("password hash found need cracking", "HIGH", "breach", "investigate"),
                ("database dump contains hashed passwords hashcat", "CRITICAL", "breach", "escalate"),
                ("ntlm hash captured need offline cracking", "CRITICAL", "breach", "escalate"),
                ("md5 sha1 hash found need dictionary attack", "HIGH", "breach", "investigate"),
            ],
            'john': [
                ("password hash file found john the ripper crack", "HIGH", "breach", "investigate"),
                ("shadow file obtained need password cracking", "CRITICAL", "breach", "escalate"),
                ("zip rar password protected file john crack", "MEDIUM", "breach", "investigate"),
            ],
        }

        for tool, contexts in SYNTHETIC_CONTEXTS.items():
            if tool not in CMD_TEMPLATES:
                continue
            needed = max(0, TARGET_PER_TOOL - tool_counts[tool])
            if needed == 0:
                continue
            # Repeat contexts to fill needed count
            per_ctx = max(1, needed // len(contexts) + 1)
            added = 0
            for text, label, ttype, ahint in contexts * per_ctx:
                if added >= needed:
                    break
                cmd = random.choice(CMD_TEMPLATES[tool]).replace('{target}', placeholder)
                results.append({
                    'input':       f"[SCAN_CONTEXT] {text} [THREAT] {label} [TYPE] {ttype}",
                    'output':      cmd,
                    'task':        'cmd_gen',
                    'label':       label,
                    'threat_type': ttype,
                    'action_hint': ahint,
                    'tool':        tool,
                })
                added += 1
                self.stats['cmd_gen'] += 1

        logger.info(f"cmd_gen tool distribution: { {t: tool_counts[t] for t in sorted(tool_counts)} }")
        return results

    # ── Task 2: Report Generation ─────────────────────────────────────────────

    def build_report_gen_samples(self, source_samples: list) -> list:
        """
        threat_v4_labeled + combined data se report_gen samples banao.
        Input: findings summary
        Output: professional report paragraph
        """
        results = []
        placeholder = 'TARGET_DOMAIN'

        for s in source_samples:
            label = s.get('label', 'MEDIUM')
            ttype = s.get('threat_type', 'unknown')
            text  = s.get('text', '').strip()
            ahint = s.get('action_hint', 'monitor')

            if len(text) < 30:
                continue

            key = (label, ttype)
            # Fallback keys
            if key not in REPORT_TEMPLATES:
                fallback_keys = [k for k in REPORT_TEMPLATES if k[0] == label]
                if not fallback_keys:
                    fallback_keys = [('LOW', 'unknown')]
                key = random.choice(fallback_keys)

            template = random.choice(REPORT_TEMPLATES[key])
            report_text = (template
                .replace('{target}', placeholder)
                .replace('{count}', str(random.randint(3, 50)))
                .replace('{ports}', str(random.randint(2, 20))))

            input_text = (
                f"[FINDINGS] {text[:350].strip()} "
                f"[SEVERITY] {label} [TYPE] {ttype} [ACTION] {ahint}"
            )

            results.append({
                'input':       input_text,
                'output':      report_text,
                'task':        'report_gen',
                'label':       label,
                'threat_type': ttype,
                'action_hint': ahint,
            })
            self.stats['report_gen'] += 1

        return results

    # ── Task 3: Chain Generation ──────────────────────────────────────────────

    def build_chain_gen_samples(self, source_samples: list) -> list:
        """
        chain_gen samples banao — expanded transitions, 200 samples per transition.
        Input: current tool + finding
        Output: next tool name
        """
        results = []
        SAMPLES_PER_TRANSITION = 200

        # Finding type ke liye context variations
        FINDING_CONTEXTS = {
            'open_web_port':    ["port 80 443 8080 open web server running", "http https service detected", "web application found on open port", "web server responding on port 80"],
            'open_db_port':     ["mysql port 3306 open", "postgresql 5432 detected", "mssql 1433 running", "database service exposed"],
            'open_smb_port':    ["smb port 445 open", "samba service detected port 139 445", "windows file sharing exposed"],
            'open_ssh_port':    ["ssh port 22 open", "openssh service running", "ssh service detected"],
            'open_ftp_port':    ["ftp port 21 open", "ftp service running anonymous login", "file transfer service detected"],
            'service_detected': ["service version identified", "software version fingerprinted", "running service detected with version"],
            'os_detected':      ["operating system identified", "windows linux os fingerprinted", "os detection complete"],
            'vuln_found':       ["vulnerability found in scan", "security issue detected", "weakness identified in application"],
            'cms_detected':     ["wordpress joomla drupal cms found", "content management system detected", "cms fingerprinted"],
            'xss_found':        ["cross site scripting xss detected", "reflected xss found in parameter", "xss vulnerability confirmed"],
            'dir_found':        ["directory found accessible", "hidden path discovered", "admin directory found"],
            'info_disclosure':  ["sensitive information exposed", "version info leaked", "server info disclosed"],
            'admin_found':      ["admin panel found", "administration interface discovered", "login page found"],
            'backup_found':     ["backup file found", "config file exposed", "old backup accessible"],
            'param_found':      ["parameter discovered", "hidden parameter found", "input field identified"],
            'endpoint_found':   ["api endpoint found", "new endpoint discovered", "url path found"],
            'cve_found':        ["cve vulnerability detected", "known cve confirmed", "critical cve found"],
            'misconfig_found':  ["misconfiguration detected", "security config issue found", "insecure configuration"],
            'exposure_found':   ["sensitive data exposed", "file exposure detected", "information leak found"],
            'tech_found':       ["technology stack identified", "framework version detected", "software fingerprinted"],
            'cms_found':        ["cms identified wordpress drupal", "content management system found"],
            'version_found':    ["software version identified", "outdated version detected", "version fingerprinted"],
            'no_waf':           ["no web application firewall detected", "waf not present", "direct access possible no waf"],
            'waf_found':        ["waf detected cloudflare akamai", "web application firewall present", "waf blocking requests"],
            'subdomain_found':  ["subdomains discovered", "subdomain enumeration complete", "new subdomains found"],
            'many_subdomains':  ["large number of subdomains found", "100+ subdomains discovered", "extensive subdomain list"],
            'email_found':      ["email addresses harvested", "employee emails found", "email list collected"],
            'domain_found':     ["related domains found", "domain infrastructure mapped"],
            'host_found':       ["hosts discovered", "ip addresses found", "live hosts identified"],
            'sqli_found':       ["sql injection confirmed", "sqli vulnerability exploited", "database accessible via sqli"],
            'db_found':         ["database names extracted", "db schema found", "tables discovered"],
            'weak_ssl':         ["weak ssl tls configuration", "tls 1.0 enabled", "weak cipher suite detected"],
            'expired_cert':     ["ssl certificate expired", "invalid certificate", "cert validation failed"],
            'weak_cipher':      ["weak cipher suite", "rc4 des cipher enabled", "insecure cipher detected"],
            'cred_found':       ["credentials found", "username password discovered", "login successful"],
            'hash_cracked':     ["password hash cracked", "plaintext password recovered", "hash cracking successful"],
            'plugin_vuln':      ["vulnerable plugin found", "outdated wordpress plugin", "plugin cve detected"],
            'user_found':       ["usernames enumerated", "user list discovered", "accounts found"],
            'share_found':      ["smb shares accessible", "network share found", "file share exposed"],
            'port_found':       ["open ports discovered", "ports found by masscan"],
            'many_ports':       ["many open ports found", "large port range open", "extensive port exposure"],
            'exploit_found':    ["exploit available for service", "public exploit found", "exploitdb match found"],
            'cmdi_found':       ["command injection confirmed", "os command execution possible", "rce via command injection"],
        }

        for (current_tool, finding_type), next_tools in CHAIN_LOGIC.items():
            contexts = FINDING_CONTEXTS.get(finding_type, [f"{finding_type.replace('_', ' ')} detected"])
            for next_tool in next_tools:
                per_ctx = max(1, SAMPLES_PER_TRANSITION // len(contexts))
                added = 0
                for ctx in contexts * (per_ctx + 1):
                    if added >= SAMPLES_PER_TRANSITION:
                        break
                    results.append({
                        'input':       f"[CURRENT_TOOL] {current_tool} [FINDING] {ctx} [STATE] scan in progress",
                        'output':      next_tool,
                        'task':        'chain_gen',
                        'label':       'HIGH',
                        'threat_type': 'recon',
                        'action_hint': 'investigate',
                        'tool':        next_tool,
                    })
                    added += 1
                    self.stats['chain_gen'] += 1

        # Source data se bhi chain samples
        for s in source_samples:
            tool  = s.get('next_tool', '').strip()
            text  = s.get('text', '').strip()
            label = s.get('label', 'MEDIUM')
            ttype = s.get('threat_type', 'unknown')
            ahint = s.get('action_hint', 'monitor')
            if not tool or tool not in CMD_TEMPLATES or len(text) < 20:
                continue
            results.append({
                'input':       f"[CONTEXT] {text[:300].strip()} [SEVERITY] {label} [TYPE] {ttype}",
                'output':      tool,
                'task':        'chain_gen',
                'label':       label,
                'threat_type': ttype,
                'action_hint': ahint,
                'tool':        tool,
            })
            self.stats['chain_gen'] += 1

        return results

    # ── Autonomous Decisions → All Tasks ─────────────────────────────────────

    def build_from_decisions(self, decisions: list) -> list:
        """
        autonomous_decisions.jsonl se real decision samples banao.
        Yeh real scan data hai — sabse valuable.
        """
        results = []

        for d in decisions:
            scan_type = d.get('scan_type', '')
            target    = d.get('target', 'TARGET_DOMAIN')
            actions   = d.get('actions', [])

            if not actions:
                continue

            for action in actions:
                act      = action.get('action', '')
                reason   = action.get('reason', '')
                priority = action.get('priority', 'MEDIUM')

                if not act or not reason:
                    continue

                label_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH',
                             'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
                label = label_map.get(priority, 'MEDIUM')

                # cmd_gen sample
                if act in CMD_TEMPLATES:
                    cmd = random.choice(CMD_TEMPLATES[act]).replace('{target}', 'TARGET_DOMAIN')
                    results.append({
                        'input':       f"[SCAN_TYPE] {scan_type} [REASON] {reason} [PRIORITY] {priority}",
                        'output':      cmd,
                        'task':        'cmd_gen',
                        'label':       label,
                        'threat_type': 'recon',
                        'action_hint': 'investigate',
                        'tool':        act,
                    })
                    self.stats['cmd_gen'] += 1

                # chain_gen sample
                results.append({
                    'input':       f"[SCAN_TYPE] {scan_type} [FINDING] {reason[:200]} [PRIORITY] {priority}",
                    'output':      act,
                    'task':        'chain_gen',
                    'label':       label,
                    'threat_type': 'recon',
                    'action_hint': 'investigate',
                })
                self.stats['chain_gen'] += 1

        return results

    # ── Main Build ────────────────────────────────────────────────────────────

    def build(self, max_per_task: int = 20000) -> int:
        """
        Saare sources se data load karo, convert karo, save karo.
        Returns: total samples written
        """
        logger.info("=== Generative Data Pipeline v4.0 ===")
        all_samples = []

        # 1. combined_training.jsonl
        combined_path = DATA_DIR / 'combined_training.jsonl'
        combined = []
        if combined_path.exists():
            with open(combined_path) as f:
                for line in f:
                    try: combined.append(json.loads(line))
                    except: pass
            logger.info(f"combined_training: {len(combined)} samples")

        # 2. payloads_training.jsonl
        payloads_path = DATA_DIR / 'payloads_training.jsonl'
        payloads = []
        if payloads_path.exists():
            with open(payloads_path) as f:
                for line in f:
                    try: payloads.append(json.loads(line))
                    except: pass
            logger.info(f"payloads_training: {len(payloads)} samples")

        # 3. all_repos_training.jsonl
        all_repos_path = Path('/home/kali/data/sentinel_training/all_repos_training.jsonl')
        all_repos = []
        if all_repos_path.exists():
            with open(all_repos_path) as f:
                for line in f:
                    try: all_repos.append(json.loads(line))
                    except: pass
            logger.info(f"all_repos_training: {len(all_repos)} samples")

        # 3b. new_repos_training.jsonl (hacktricks, nuclei-templates, etc.)
        new_repos_path = Path('/home/kali/data/sentinel_training/new_repos_training.jsonl')
        new_repos = []
        if new_repos_path.exists():
            with open(new_repos_path) as f:
                for line in f:
                    try: new_repos.append(json.loads(line))
                    except: pass
            logger.info(f"new_repos_training: {len(new_repos)} samples")
        all_repos = all_repos + new_repos

        # 4. threat_v4_labeled.jsonl (report_gen ke liye, 50K cap)
        threat_path = DATA_DIR / 'threat_v4_labeled.jsonl'
        threat_v4 = []
        if threat_path.exists():
            with open(threat_path) as f:
                for i, line in enumerate(f):
                    if i >= 50000: break
                    try: threat_v4.append(json.loads(line))
                    except: pass
            logger.info(f"threat_v4_labeled: {len(threat_v4)} samples (capped 50K)")

        # 5. autonomous_decisions.jsonl
        decisions_path = DATA_DIR / 'autonomous_decisions.jsonl'
        decisions = []
        if decisions_path.exists():
            with open(decisions_path) as f:
                for line in f:
                    try: decisions.append(json.loads(line))
                    except: pass
            logger.info(f"autonomous_decisions: {len(decisions)} samples")

        # ── Build samples ──────────────────────────────────────────────────────

        # cmd_gen — all sources
        cmd_source = combined + payloads + all_repos
        random.shuffle(cmd_source)
        cmd_samples = self.build_cmd_gen_samples(cmd_source)
        logger.info(f"cmd_gen: {len(cmd_samples)} samples")

        # report_gen — unknown type filter karo
        report_source = [s for s in threat_v4 + combined
                         if s.get('threat_type', 'unknown') != 'unknown']
        random.shuffle(report_source)
        report_samples = self.build_report_gen_samples(report_source)
        logger.info(f"report_gen: {len(report_samples)} samples")

        # chain_gen — all sources
        chain_source = combined + payloads + all_repos
        chain_samples = self.build_chain_gen_samples(chain_source)
        logger.info(f"chain_gen: {len(chain_samples)} samples")

        # decisions
        decision_samples = self.build_from_decisions(decisions)
        logger.info(f"decision samples: {len(decision_samples)}")

        # ── Cap + shuffle ──────────────────────────────────────────────────────
        random.shuffle(cmd_samples)
        random.shuffle(report_samples)
        random.shuffle(chain_samples)

        all_samples = (
            cmd_samples[:max_per_task]
            + report_samples[:max_per_task]
            + chain_samples[:max_per_task]
            + decision_samples
        )
        random.shuffle(all_samples)

        # ── Save ───────────────────────────────────────────────────────────────
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(OUTPUT, 'w') as f:
            for s in all_samples:
                f.write(json.dumps(s, ensure_ascii=False) + '\n')
                written += 1

        logger.info(f"\n=== Done ===")
        logger.info(f"Total written : {written:,}")
        logger.info(f"cmd_gen       : {self.stats['cmd_gen']:,}")
        logger.info(f"report_gen    : {self.stats['report_gen']:,}")
        logger.info(f"chain_gen     : {self.stats['chain_gen']:,}")
        logger.info(f"Output        : {OUTPUT}")

        stats_path = DATA_DIR / 'pipeline_v4_stats.json'
        with open(stats_path, 'w') as f:
            json.dump({
                'total': written,
                'cmd_gen': self.stats['cmd_gen'],
                'report_gen': self.stats['report_gen'],
                'chain_gen': self.stats['chain_gen'],
                'output': str(OUTPUT),
                'built_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            }, f, indent=2)

        return written

if __name__ == '__main__':
    # Step 1: process_all_repos.py pehle run karo (agar nahi kiya)
    # python3 /home/kali/data/process_all_repos.py
    builder = GenerativeDataBuilder()
    total = builder.build(max_per_task=20000)
    print(f'\nGenerative training data ready: {total:,} samples')
    print(f'File: {OUTPUT}')
    print('\nAb Colab notebook mein upload karo aur train karo.')
