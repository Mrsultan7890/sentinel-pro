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
Bulk Security Data Collector
Target: 600-700MB raw data → clean training samples
Sources: HuggingFace, NVD full feed, MITRE full, ExploitDB, GitHub CVE repos
"""

import json
import re
import time
import gzip
import zipfile
import io
import os
import threading
import requests
from pathlib import Path
from collections import Counter

# ── Config ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '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')
GH = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}

OUT_DIR  = Path('models/ml_engine/training_data/bulk')
OUT_DIR.mkdir(parents=True, exist_ok=True)

FINAL_OUT = Path('models/ml_engine/training_data/threat_v4_bulk.jsonl')

LABELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

_lock  = threading.Lock()
_stats = Counter()

def save(text: str, label: str, source: str):
    text = re.sub(r'[A-Za-z0-9+/]{100,}={0,2}', '<b64>', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) < 40 or label not in LABELS:
        return
    text = text[:3000]
    with _lock:
        with open(FINAL_OUT, 'a') as f:
            f.write(json.dumps({'text': text, 'label': label, 'source': source}) + '\n')
        _stats[source] += 1
        _stats['total'] += 1

def log(msg):
    print(msg, flush=True)

# ── 1. NVD Full Feed (2002–2024) ──────────────────────────────────────────────
def collect_nvd_full():
    log('\n[1/6] NVD Full Feed (2002-2024)...')
    total = 0
    SEV_MAP = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}

    for year in range(2002, 2026):
        url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz'
        try:
            r = requests.get(url, timeout=60, stream=True)
            if r.status_code != 200:
                continue
            raw = gzip.decompress(r.content)
            data = json.loads(raw)
            for item in data.get('CVE_Items', []):
                cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                descs  = item.get('cve', {}).get('description', {}).get('description_data', [])
                desc   = next((d['value'] for d in descs if d.get('lang') == 'en'), '')
                if not desc or len(desc) < 30:
                    continue
                # CVSS score se label
                impact = item.get('impact', {})
                score  = (impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore') or
                          impact.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore') or 0)
                if score >= 9.0:   label = 'CRITICAL'
                elif score >= 7.0: label = 'HIGH'
                elif score >= 4.0: label = 'MEDIUM'
                else:              label = 'LOW'
                save(f'{cve_id} {desc}', label, f'nvd_{year}')
                total += 1
            log(f'  NVD {year}: +{len(data.get("CVE_Items", []))} (total={total})')
        except Exception as e:
            log(f'  NVD {year} failed: {e}')
        time.sleep(0.3)
    log(f'  NVD DONE: {total} samples')

# ── 2. MITRE ATT&CK — All Domains ─────────────────────────────────────────────
def collect_mitre_full():
    log('\n[2/6] MITRE ATT&CK (Enterprise + ICS + Mobile)...')
    urls = [
        ('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', 'mitre_enterprise'),
        ('https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json', 'mitre_ics'),
        ('https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json', 'mitre_mobile'),
    ]
    total = 0
    for url, source in urls:
        try:
            r = requests.get(url, timeout=60)
            if r.status_code != 200:
                continue
            for obj in r.json().get('objects', []):
                desc  = obj.get('description', '')
                name  = obj.get('name', '')
                otype = obj.get('type', '')
                if not desc or len(desc) < 30:
                    continue
                if otype == 'attack-pattern':
                    phases = [k['phase_name'] for k in obj.get('kill_chain_phases', [])]
                    if any(p in phases for p in ['execution', 'exfiltration', 'impact', 'command-and-control']):
                        label = 'CRITICAL'
                    elif any(p in phases for p in ['privilege-escalation', 'defense-evasion', 'lateral-movement']):
                        label = 'HIGH'
                    elif any(p in phases for p in ['discovery', 'collection', 'credential-access']):
                        label = 'HIGH'
                    else:
                        label = 'MEDIUM'
                elif otype == 'malware':   label = 'CRITICAL'
                elif otype == 'tool':      label = 'HIGH'
                elif otype == 'campaign':  label = 'CRITICAL'
                elif otype == 'course-of-action': label = 'LOW'
                else:
                    continue
                clean = re.sub(r'\(Citation:[^)]+\)', '', desc)
                clean = re.sub(r'<[^>]+>', '', clean).strip()
                save(f'{name}. {clean}', label, source)
                total += 1
            log(f'  {source}: done')
        except Exception as e:
            log(f'  {source} failed: {e}')
    log(f'  MITRE DONE: {total} samples')

# ── 3. ExploitDB Full CSV ──────────────────────────────────────────────────────
def collect_exploitdb():
    log('\n[3/6] ExploitDB Full CSV...')
    url = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
    try:
        r = requests.get(url, timeout=60)
        if r.status_code != 200:
            log(f'  ExploitDB failed: {r.status_code}')
            return
        lines = r.text.splitlines()
        total = 0
        for line in lines[1:]:  # skip header
            parts = line.split(',')
            if len(parts) < 5:
                continue
            desc     = parts[2].strip().strip('"') if len(parts) > 2 else ''
            platform = parts[5].strip().strip('"') if len(parts) > 5 else ''
            etype    = parts[4].strip().strip('"') if len(parts) > 4 else ''
            if not desc or len(desc) < 10:
                continue
            # Type se label
            etype_l = etype.lower()
            if 'remote' in etype_l:   label = 'CRITICAL'
            elif 'local' in etype_l:  label = 'HIGH'
            elif 'webapps' in etype_l: label = 'HIGH'
            elif 'dos' in etype_l:    label = 'MEDIUM'
            else:                     label = 'MEDIUM'
            save(f'{desc} {platform} {etype}', label, 'exploitdb_full')
            total += 1
        log(f'  ExploitDB DONE: {total} samples')
    except Exception as e:
        log(f'  ExploitDB failed: {e}')

# ── 4. HuggingFace Datasets ────────────────────────────────────────────────────
def collect_huggingface():
    log('\n[4/6] HuggingFace Datasets...')

    # Dataset 1: CIRCL CVE (already have some, get more)
    hf_datasets = [
        # CVE / vulnerability datasets
        ('https://huggingface.co/datasets/gchhablani/bert-large-cased-finetuned-cybersecurity-ner/resolve/main/README.md', 'hf_cyber_ner', 'MEDIUM'),
        # Malware classification
        ('https://huggingface.co/datasets/MalwareBenchmark/malware-text-classification/resolve/main/README.md', 'hf_malware', 'CRITICAL'),
    ]

    # Direct JSONL datasets from HuggingFace
    hf_jsonl = [
        {
            'url': 'https://huggingface.co/datasets/AI4Sec/cve-description/resolve/main/data/train.jsonl',
            'source': 'hf_cve_desc',
            'text_key': 'description',
            'label_key': 'severity',
            'label_map': {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'},
        },
        {
            'url': 'https://huggingface.co/datasets/AI4Sec/cve-description/resolve/main/data/test.jsonl',
            'source': 'hf_cve_desc_test',
            'text_key': 'description',
            'label_key': 'severity',
            'label_map': {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'},
        },
    ]

    total = 0
    for ds in hf_jsonl:
        try:
            r = requests.get(ds['url'], timeout=30)
            if r.status_code != 200:
                log(f'  HF {ds["source"]}: {r.status_code}')
                continue
            for line in r.text.splitlines():
                try:
                    obj = json.loads(line)
                    text  = obj.get(ds['text_key'], '')
                    label_raw = str(obj.get(ds['label_key'], '')).upper()
                    label = ds['label_map'].get(label_raw)
                    if text and label:
                        save(text, label, ds['source'])
                        total += 1
                except Exception:
                    pass
            log(f'  HF {ds["source"]}: done')
        except Exception as e:
            log(f'  HF {ds["source"]} failed: {e}')

    # HuggingFace parquet files — cybersecurity datasets
    parquet_datasets = [
        'https://huggingface.co/datasets/mrm8488/bert-tiny-finetuned-sms-spam-detection/resolve/main/README.md',
    ]

    # Try datasets library approach
    try:
        from datasets import load_dataset
        log('  datasets library available — loading HF datasets...')

        # CTI (Cyber Threat Intelligence) dataset
        try:
            ds = load_dataset('AI4Sec/cve-description', split='train', trust_remote_code=True)
            for item in ds:
                text  = item.get('description', '') or item.get('text', '')
                sev   = str(item.get('severity', '')).upper()
                label = sev if sev in LABELS else None
                if text and label:
                    save(text, label, 'hf_ai4sec_cve')
                    total += 1
            log(f'  HF AI4Sec CVE: {total} samples')
        except Exception as e:
            log(f'  HF AI4Sec: {e}')

        # Cybersecurity threat intel
        try:
            ds2 = load_dataset('jackaduma/SecureNLP', split='train', trust_remote_code=True)
            for item in ds2:
                text = item.get('text', '') or item.get('sentence', '')
                label_raw = str(item.get('label', '')).upper()
                if text and len(text) > 30:
                    label = 'HIGH' if 'threat' in text.lower() else 'MEDIUM'
                    save(text, label, 'hf_securenlp')
                    total += 1
            log(f'  HF SecureNLP done')
        except Exception as e:
            log(f'  HF SecureNLP: {e}')

    except ImportError:
        log('  datasets library not installed — installing...')
        os.system('pip install datasets -q')
        log('  Retry after install — run script again')

    log(f'  HuggingFace DONE: {total} samples')

# ── 5. GitHub — Large CVE + Security Repos ────────────────────────────────────
def collect_github_bulk():
    log('\n[5/6] GitHub Bulk — CVE repos + Security writeups...')
    total = 0

    # CVEProject/cvelistV5 — official CVE JSON files
    log('  Fetching CVEProject/cvelistV5...')
    try:
        # Get recent CVEs from the official repo
        for year in ['2023', '2024', '2025']:
            r = requests.get(
                f'https://api.github.com/repos/CVEProject/cvelistV5/contents/cves/{year}',
                headers=GH, timeout=15)
            if r.status_code != 200:
                continue
            months = r.json()
            for month_dir in months[:12]:
                if month_dir.get('type') != 'dir':
                    continue
                r2 = requests.get(month_dir['url'], headers=GH, timeout=15)
                if r2.status_code != 200:
                    continue
                files = r2.json()
                for cve_file in files[:200]:  # 200 per month
                    if not cve_file.get('name', '').endswith('.json'):
                        continue
                    r3 = requests.get(cve_file['download_url'], timeout=10)
                    if r3.status_code != 200:
                        continue
                    try:
                        cve = r3.json()
                        # Extract description
                        descs = (cve.get('containers', {}).get('cna', {})
                                    .get('descriptions', []))
                        desc = next((d['value'] for d in descs
                                     if d.get('lang', '').startswith('en')), '')
                        if not desc or len(desc) < 30:
                            continue
                        # CVSS
                        metrics = (cve.get('containers', {}).get('cna', {})
                                      .get('metrics', []))
                        score = 0
                        for m in metrics:
                            for k in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                                if k in m:
                                    score = m[k].get('baseScore', 0)
                                    break
                        if score >= 9.0:   label = 'CRITICAL'
                        elif score >= 7.0: label = 'HIGH'
                        elif score >= 4.0: label = 'MEDIUM'
                        else:              label = 'LOW'
                        cve_id = cve_file['name'].replace('.json', '')
                        save(f'{cve_id} {desc}', label, f'cveproject_{year}')
                        total += 1
                    except Exception:
                        pass
                    time.sleep(0.05)
                time.sleep(0.2)
            log(f'  CVEProject {year}: done')
    except Exception as e:
        log(f'  CVEProject failed: {e}')

    # trickest/cve — PoC availability (HIGH/CRITICAL)
    log('  Fetching trickest/cve PoC data...')
    try:
        for year in ['2023', '2024']:
            r = requests.get(
                f'https://api.github.com/repos/trickest/cve/contents/{year}',
                headers=GH, timeout=15)
            if r.status_code != 200:
                continue
            for month in r.json()[:12]:
                if month.get('type') != 'dir':
                    continue
                r2 = requests.get(month['url'], headers=GH, timeout=15)
                if r2.status_code != 200:
                    continue
                for f in r2.json()[:100]:
                    if not f.get('name', '').endswith('.md'):
                        continue
                    r3 = requests.get(f['download_url'], timeout=10)
                    if r3.status_code != 200:
                        continue
                    text = r3.text[:2000]
                    text = re.sub(r'```[\s\S]*?```', '', text)
                    text = re.sub(r'[#*`>|]', '', text).strip()
                    if len(text) > 50:
                        save(text, 'CRITICAL', 'trickest_poc')
                        total += 1
                    time.sleep(0.05)
                time.sleep(0.2)
        log(f'  trickest/cve: done')
    except Exception as e:
        log(f'  trickest/cve failed: {e}')

    # GHSA authenticated — all pages
    log('  Fetching GHSA (authenticated)...')
    try:
        for sev, label in [('critical','CRITICAL'),('high','HIGH'),('moderate','MEDIUM'),('low','LOW')]:
            for page in range(1, 30):
                r = requests.get('https://api.github.com/advisories',
                    params={'severity': sev, 'per_page': 100, 'page': page},
                    headers=GH, timeout=15)
                if r.status_code != 200:
                    break
                advs = r.json()
                if not advs:
                    break
                for adv in advs:
                    text = f"{adv.get('summary','')}. {adv.get('description','') or ''}"
                    text = re.sub(r'```[\s\S]*?```', '', text)
                    text = re.sub(r'[#*`>]', '', text).strip()
                    if len(text) >= 30:
                        save(text[:2000], label, 'ghsa_bulk')
                        total += 1
                time.sleep(0.1)
        log(f'  GHSA bulk: done')
    except Exception as e:
        log(f'  GHSA failed: {e}')

    log(f'  GitHub DONE: {total} samples')

# ── 6. CISA + Additional Threat Intel ─────────────────────────────────────────
def collect_threat_intel():
    log('\n[6/6] Threat Intel — CISA KEV + CIRCL + OpenCVE...')
    total = 0

    # CISA KEV full
    try:
        r = requests.get(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            timeout=30)
        for v in r.json().get('vulnerabilities', []):
            text = f"{v.get('cveID','')} {v.get('vulnerabilityName','')} {v.get('shortDescription','')} {v.get('requiredAction','')}"
            save(text[:2000], 'CRITICAL', 'cisa_kev_full')
            total += 1
        log(f'  CISA KEV: {total}')
    except Exception as e:
        log(f'  CISA KEV failed: {e}')

    # CIRCL CVE Search API — bulk
    try:
        for year in range(2020, 2026):
            r = requests.get(
                f'https://cve.circl.lu/api/query?time_modifier=from&time_start={year}-01-01&time_end={year}-12-31&limit=2000',
                timeout=30)
            if r.status_code != 200:
                continue
            data = r.json()
            for item in data.get('results', []):
                cve_id = item.get('id', '')
                summary = item.get('summary', '')
                if not summary or len(summary) < 30:
                    continue
                cvss = item.get('cvss', 0) or 0
                if cvss >= 9.0:   label = 'CRITICAL'
                elif cvss >= 7.0: label = 'HIGH'
                elif cvss >= 4.0: label = 'MEDIUM'
                else:             label = 'LOW'
                save(f'{cve_id} {summary}', label, f'circl_{year}')
                total += 1
            log(f'  CIRCL {year}: {len(data.get("results",[]))}')
            time.sleep(1)
    except Exception as e:
        log(f'  CIRCL failed: {e}')

    # Sigma rules — full repo
    try:
        r = requests.get(
            'https://api.github.com/repos/SigmaHQ/sigma/git/trees/master',
            params={'recursive': 1}, headers=GH, timeout=30)
        rule_files = [f['path'] for f in r.json().get('tree', [])
                      if f['path'].endswith('.yml') and 'rules/' in f['path']]
        log(f'  Sigma rules found: {len(rule_files)}')
        for path in rule_files:
            rr = requests.get(
                f'https://api.github.com/repos/SigmaHQ/sigma/contents/{path}',
                headers={**GH, 'Accept': 'application/vnd.github.raw'}, timeout=10)
            if rr.status_code != 200:
                continue
            content = rr.text
            title   = re.search(r'title:\s*(.+)', content)
            desc    = re.search(r'description:\s*(.+)', content)
            level   = re.search(r'level:\s*(\w+)', content)
            tags    = re.findall(r'- attack\.\w+', content)
            if not title:
                continue
            t  = title.group(1).strip()
            d  = desc.group(1).strip() if desc else ''
            lv = level.group(1).lower() if level else 'medium'
            tg = ' '.join(tags)
            lmap = {'critical':'CRITICAL','high':'HIGH','medium':'MEDIUM','low':'LOW','informational':'LOW'}
            label = lmap.get(lv, 'MEDIUM')
            save(f'{t}. {d} {tg}', label, 'sigma_full')
            total += 1
            time.sleep(0.05)
        log(f'  Sigma: done')
    except Exception as e:
        log(f'  Sigma failed: {e}')

    log(f'  Threat Intel DONE: {total} samples')

# ── Final Stats ───────────────────────────────────────────────────────────────
def print_stats():
    if not FINAL_OUT.exists():
        log('No output file found')
        return

    samples = []
    with open(FINAL_OUT) as f:
        for line in f:
            try: samples.append(json.loads(line.strip()))
            except: pass

    dist = Counter(s['label'] for s in samples)
    srcs = Counter(s.get('source','?') for s in samples)
    size = FINAL_OUT.stat().st_size / 1024 / 1024

    log(f'\n{"="*55}')
    log(f'FINAL DATASET STATS')
    log(f'{"="*55}')
    log(f'Total samples : {len(samples):,}')
    log(f'File size     : {size:.1f} MB')
    log(f'Labels:')
    for label in ['CRITICAL','HIGH','MEDIUM','LOW']:
        cnt = dist.get(label, 0)
        log(f'  {label:<10} {cnt:>7,}  ({cnt/len(samples):.1%})')
    log(f'\nTop sources:')
    for src, cnt in srcs.most_common(20):
        log(f'  {src:<30} {cnt:>7,}')
    log(f'{"="*55}')

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--sources', nargs='+',
        choices=['nvd','mitre','exploitdb','huggingface','github','intel','all'],
        default=['all'])
    parser.add_argument('--resume', action='store_true',
        help='Resume — existing data keep karo, sirf missing sources collect karo')
    args = parser.parse_args()

    if not args.resume and FINAL_OUT.exists():
        FINAL_OUT.unlink()
        log('Previous data cleared — fresh start')

    run_all = 'all' in args.sources
    sources = args.sources

    if run_all or 'nvd'         in sources: collect_nvd_full()
    if run_all or 'mitre'       in sources: collect_mitre_full()
    if run_all or 'exploitdb'   in sources: collect_exploitdb()
    if run_all or 'huggingface' in sources: collect_huggingface()
    if run_all or 'github'      in sources: collect_github_bulk()
    if run_all or 'intel'       in sources: collect_threat_intel()

    print_stats()
