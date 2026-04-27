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
Payload Extractor — PayloadsAllTheThings → sentinel_proxy/payloads/
Extracts raw payloads from Intruder/*.txt files + README code blocks.
"""

import re
from pathlib import Path

SRC  = Path('/home/kali/data/PayloadsAllTheThings')
DEST = Path(__file__).parent

# Category mapping: folder name → output filename
CATEGORIES = {
    'SQL Injection':                  'sqli.txt',
    'XSS Injection':                  'xss.txt',
    'File Inclusion':                 'lfi.txt',
    'Directory Traversal':            'path_traversal.txt',
    'Server Side Request Forgery':    'ssrf.txt',
    'Server Side Template Injection': 'ssti.txt',
    'Command Injection':              'rce.txt',
    'XXE Injection':                  'xxe.txt',
    'Open Redirect':                  'open_redirect.txt',
    'LDAP Injection':                 'ldap.txt',
    'NoSQL Injection':                'nosql.txt',
    'GraphQL Injection':              'graphql.txt',
    'JSON Web Token':                 'jwt.txt',
    'CORS Misconfiguration':          'cors.txt',
    'CRLF Injection':                 'crlf.txt',
    'Insecure Deserialization':       'deserialization.txt',
    'Request Smuggling':              'smuggling.txt',
    'XPATH Injection':                'xpath.txt',
    'SAML Injection':                 'saml.txt',
    'Prototype Pollution':            'prototype_pollution.txt',
    'Upload Insecure Files':          'file_upload.txt',
    'OAuth Misconfiguration':         'oauth.txt',
    'Race Condition':                 'race_condition.txt',
    'Mass Assignment':                'mass_assignment.txt',
    'Web Cache Deception':            'cache_deception.txt',
    'HTTP Parameter Pollution':       'hpp.txt',
    'CSS Injection':                  'css_injection.txt',
    'CSV Injection':                  'csv_injection.txt',
    'LaTeX Injection':                'latex_injection.txt',
    'XSLT Injection':                 'xslt.txt',
    'Clickjacking':                   'clickjacking.txt',
    'CVE Exploits':                   'cve_exploits.txt',
}


def extract_from_intruder(folder: Path) -> list:
    """Extract payloads from Intruder/*.txt files."""
    payloads = []
    for intruder_dir in ['Intruder', 'Intruders']:
        d = folder / intruder_dir
        if d.exists():
            for f in d.glob('*.txt'):
                lines = f.read_text(errors='ignore').splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
    return payloads


def extract_from_readme(folder: Path) -> list:
    """Extract payloads from code blocks in README.md."""
    payloads = []
    readme = folder / 'README.md'
    if not readme.exists():
        return payloads
    content = readme.read_text(errors='ignore')
    # Extract lines from code blocks
    in_block = False
    for line in content.splitlines():
        if line.strip().startswith('```'):
            in_block = not in_block
            continue
        if in_block:
            line = line.strip()
            if line and len(line) > 2 and not line.startswith('#'):
                payloads.append(line)
    return payloads


def dedupe(payloads: list) -> list:
    seen = set()
    result = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


total_files = 0
total_payloads = 0

for folder_name, out_file in CATEGORIES.items():
    folder = SRC / folder_name
    if not folder.exists():
        continue

    payloads = extract_from_intruder(folder) + extract_from_readme(folder)
    payloads = dedupe(payloads)

    if payloads:
        out_path = DEST / out_file
        out_path.write_text('\n'.join(payloads) + '\n')
        print(f"  {out_file:<35} {len(payloads):>5} payloads")
        total_files += 1
        total_payloads += len(payloads)

print(f"\nDone: {total_files} files, {total_payloads} total payloads")
print(f"Saved to: {DEST}")
