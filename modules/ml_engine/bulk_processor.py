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
Bulk Data Processor
====================
Sab downloaded raw files ko clean training format mein convert karo.
Run: python3 modules/ml_engine/bulk_processor.py

Input  : models/ml_engine/training_data/bulk/
Output : models/ml_engine/training_data/threat_master.jsonl
"""

import json
import re
import csv
import io
from pathlib import Path
from collections import Counter

BULK_DIR  = Path('models/ml_engine/training_data/bulk')
PREV_GOOD = Path('models/ml_engine/training_data/threat_v4_clean.jsonl')
OUT       = Path('models/ml_engine/training_data/threat_master.jsonl')

LABELS = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}

seen    = set()
samples = []

def add(text: str, label: str, source: str):
    text = re.sub(r'[A-Za-z0-9+/]{100,}={0,2}', '<b64>', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) < 40 or label not in LABELS:
        return
    text = text[:3000]
    key  = text[:120].lower()
    if key in seen:
        return
    seen.add(key)
    samples.append({'text': text, 'label': label, 'source': source})

def score_to_label(score) -> str:
    try:
        s = float(score)
        if s >= 9.0:   return 'CRITICAL'
        elif s >= 7.0: return 'HIGH'
        elif s >= 4.0: return 'MEDIUM'
        else:          return 'LOW'
    except Exception:
        return None

def clean_md(text: str) -> str:
    text = re.sub(r'```[\s\S]*?```', '', text)
    text = re.sub(r'[#*`>|]', '', text)
    return text.strip()

# ── 1. Previous clean data (proven good) ─────────────────────────────────────
def load_prev():
    if not PREV_GOOD.exists():
        return
    n = 0
    with open(PREV_GOOD) as f:
        for line in f:
            try:
                s = json.loads(line.strip())
                add(s['text'], s['label'], s.get('source', 'prev'))
                n += 1
            except Exception:
                pass
    print(f'  prev clean data : {n:>8,}')

# ── 2. Fenrir dataset (344MB) ─────────────────────────────────────────────────
def process_fenrir():
    path = BULK_DIR / 'fenrir_cybersec.jsonl'
    if not path.exists():
        print('  fenrir          : NOT FOUND')
        return
    n = 0
    with open(path, errors='ignore') as f:
        for line in f:
            try:
                obj  = json.loads(line.strip())
                user = obj.get('user', '')
                asst = obj.get('assistant', '')
                if not user or not asst:
                    continue
                text = f'{user} {asst}'
                text = clean_md(text)
                # Label from content
                tl = text.lower()
                if any(k in tl for k in ['ransomware','zero-day','apt','c2','command and control',
                                          'exfiltrat','backdoor','rootkit','exploit kit','critical']):
                    label = 'CRITICAL'
                elif any(k in tl for k in ['sql injection','rce','remote code','privilege escalat',
                                            'authentication bypass','buffer overflow','high severity']):
                    label = 'HIGH'
                elif any(k in tl for k in ['misconfigur','xss','csrf','information disclosure',
                                            'medium severity','moderate']):
                    label = 'MEDIUM'
                elif any(k in tl for k in ['best practice','awareness','recommendation',
                                            'low severity','informational','patch management']):
                    label = 'LOW'
                else:
                    label = 'MEDIUM'  # default for security content
                add(text[:3000], label, 'fenrir')
                n += 1
            except Exception:
                pass
    print(f'  fenrir          : {n:>8,}')

# ── 3. Threat Intelligence HF (132MB) ────────────────────────────────────────
def process_threat_intel_hf():
    path = BULK_DIR / 'threat_intel_hf.jsonl'
    if not path.exists():
        print('  threat_intel_hf : NOT FOUND')
        return
    n = 0
    with open(path, errors='ignore') as f:
        for line in f:
            try:
                obj  = json.loads(line.strip())
                inp  = obj.get('input', '')
                out  = obj.get('output', '')
                meta = obj.get('metadata', {}) or {}
                if not out or len(out) < 40:
                    continue
                text = f'{inp} {out}'.strip()
                # Severity from metadata
                sev = str(meta.get('severity', '') or meta.get('threat_level', '')).upper()
                if sev in LABELS:
                    label = sev
                else:
                    tl = text.lower()
                    if any(k in tl for k in ['critical','ransomware','apt','zero-day','exfiltrat']):
                        label = 'CRITICAL'
                    elif any(k in tl for k in ['high','remote code','sql injection','privilege']):
                        label = 'HIGH'
                    elif any(k in tl for k in ['medium','moderate','misconfigur','xss']):
                        label = 'MEDIUM'
                    else:
                        label = 'HIGH'  # threat intel = mostly high
                add(text[:3000], label, 'threat_intel_hf')
                n += 1
            except Exception:
                pass
    print(f'  threat_intel_hf : {n:>8,}')

# ── 4. CTI mrmoor (2.7MB) ────────────────────────────────────────────────────
def process_cti_mrmoor():
    path = BULK_DIR / 'cti_mrmoor.jsonl'
    if not path.exists():
        print('  cti_mrmoor      : NOT FOUND')
        return
    n = 0
    with open(path, errors='ignore') as f:
        for line in f:
            try:
                obj  = json.loads(line.strip())
                text = obj.get('text', '')
                if not text or len(text) < 40:
                    continue
                tl = text.lower()
                if any(k in tl for k in ['malware','ransomware','apt','trojan','backdoor','c2']):
                    label = 'CRITICAL'
                elif any(k in tl for k in ['vulnerability','exploit','injection','overflow']):
                    label = 'HIGH'
                elif any(k in tl for k in ['phishing','suspicious','anomaly']):
                    label = 'MEDIUM'
                else:
                    label = 'MEDIUM'
                add(text[:3000], label, 'cti_mrmoor')
                n += 1
            except Exception:
                pass
    print(f'  cti_mrmoor      : {n:>8,}')

# ── 5. ExploitDB HF ───────────────────────────────────────────────────────────
def process_exploitdb_hf():
    path = BULK_DIR / 'exploitdb_hf.jsonl'
    if not path.exists():
        print('  exploitdb_hf    : NOT FOUND')
        return
    n = 0
    try:
        data = json.loads(path.read_text(errors='ignore'))
        items = data if isinstance(data, list) else []
    except Exception:
        items = []
        with open(path, errors='ignore') as f:
            for line in f:
                try: items.append(json.loads(line.strip()))
                except: pass

    for obj in items:
        title   = obj.get('title', '')
        desc    = obj.get('description', '') or obj.get('desc', '')
        etype   = str(obj.get('type', '') or obj.get('exploit_type', '')).lower()
        text    = f'{title} {desc}'.strip()
        if not text or len(text) < 20:
            continue
        if 'remote' in etype:   label = 'CRITICAL'
        elif 'local' in etype:  label = 'HIGH'
        elif 'webapps' in etype: label = 'HIGH'
        elif 'dos' in etype:    label = 'MEDIUM'
        else:                   label = 'HIGH'
        add(text[:2000], label, 'exploitdb_hf')
        n += 1
    print(f'  exploitdb_hf    : {n:>8,}')

# ── 6. Shellcode HF ───────────────────────────────────────────────────────────
def process_shellcode_hf():
    path = BULK_DIR / 'shellcode_hf.json'
    if not path.exists():
        print('  shellcode_hf    : NOT FOUND')
        return
    n = 0
    try:
        data  = json.loads(path.read_text(errors='ignore'))
        items = data if isinstance(data, list) else []
    except Exception:
        items = []

    for obj in items:
        vuln  = obj.get('vulnerability_type', '')
        desc  = obj.get('description', '') or obj.get('title', '')
        cve   = obj.get('cve', '')
        text  = f'{cve} {vuln} {desc}'.strip()
        if not text or len(text) < 20:
            continue
        vl = vuln.lower()
        if any(k in vl for k in ['buffer overflow','rce','remote','heap']):
            label = 'CRITICAL'
        elif any(k in vl for k in ['privilege','local','injection']):
            label = 'HIGH'
        else:
            label = 'HIGH'
        add(text[:2000], label, 'shellcode_hf')
        n += 1
    print(f'  shellcode_hf    : {n:>8,}')

# ── 7. Cyberattacks CSV ───────────────────────────────────────────────────────
def process_cyberattacks_csv():
    path = BULK_DIR / 'cyberattacks.csv'
    if not path.exists():
        print('  cyberattacks    : NOT FOUND')
        return
    n = 0
    try:
        with open(path, errors='ignore', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                org      = row.get('affected_organization', '')
                industry = row.get('affected_industry', '')
                attack   = row.get('attack_type', '') or row.get('slug', '')
                desc     = row.get('description', '') or row.get('event_description', '')
                text     = f'{attack} {org} {industry} {desc}'.strip()
                if not text or len(text) < 20:
                    continue
                tl = text.lower()
                if any(k in tl for k in ['ransomware','data breach','critical infrastructure']):
                    label = 'CRITICAL'
                elif any(k in tl for k in ['ddos','phishing','malware','intrusion']):
                    label = 'HIGH'
                else:
                    label = 'MEDIUM'
                add(text[:2000], label, 'cyberattacks_csv')
                n += 1
    except Exception as e:
        print(f'  cyberattacks CSV error: {e}')
    print(f'  cyberattacks    : {n:>8,}')

# ── 8. NVD bulk (if downloaded) ───────────────────────────────────────────────
def process_nvd_bulk():
    path = BULK_DIR / 'nvd_bulk.jsonl'
    if not path.exists():
        print('  nvd_bulk        : NOT FOUND (still downloading?)')
        return
    n = 0
    with open(path, errors='ignore') as f:
        for line in f:
            try:
                s = json.loads(line.strip())
                add(s['text'], s['label'], 'nvd_bulk')
                n += 1
            except Exception:
                pass
    print(f'  nvd_bulk        : {n:>8,}')

# ── Save + Stats ──────────────────────────────────────────────────────────────
def save_and_stats():
    with open(OUT, 'w') as f:
        for s in samples:
            f.write(json.dumps(s) + '\n')

    dist = Counter(s['label'] for s in samples)
    srcs = Counter(s['source'] for s in samples)
    size = OUT.stat().st_size / 1024 / 1024

    print(f'\n{"="*55}')
    print(f'THREAT MASTER DATASET')
    print(f'{"="*55}')
    print(f'Total samples : {len(samples):>10,}')
    print(f'File size     : {size:>9.1f} MB')
    print(f'\nLabel distribution:')
    for label in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        cnt = dist.get(label, 0)
        pct = cnt / len(samples) * 100 if samples else 0
        bar = '█' * (cnt // 5000)
        print(f'  {label:<10} {cnt:>8,}  {pct:5.1f}%  {bar}')
    print(f'\nSources:')
    for src, cnt in srcs.most_common():
        print(f'  {src:<30} {cnt:>8,}')
    print(f'\nSaved: {OUT}')
    print(f'{"="*55}')

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('Processing all bulk data...\n')
    load_prev()
    process_fenrir()
    process_threat_intel_hf()
    process_cti_mrmoor()
    process_exploitdb_hf()
    process_shellcode_hf()
    process_cyberattacks_csv()
    process_nvd_bulk()
    save_and_stats()
