#!/usr/bin/env python3
"""
Data Pipeline v2 — 500MB Linux/Kali focused dataset
Sources: GitHub (shell scripts, CTF writeups, security tools) + NVD CVEs
Author: @who_is_the_black_hat
"""

import os
import json
import time
import requests
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger(__name__)

GITHUB_TOKEN = "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"
NVD_API_KEY  = "9a6cf2d9-b329-4894-9f38-a2d68a7f21cb"

OUT_DIR = Path("/home/kali/osints/models/ml_engine/training_data")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "linux_kali_dataset.jsonl"

GH_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# ── GitHub search queries ─────────────────────────────────────────────────────
GITHUB_QUERIES = [
    # Shell / Bash
    ("kali linux bash script security",        "shell_script"),
    ("nmap scan script bash",                  "recon"),
    ("sqlmap automation bash",                 "exploit"),
    ("metasploit automation ruby",             "exploit"),
    ("CTF writeup linux privilege escalation", "privesc"),
    ("CTF writeup walkthrough hack",           "ctf"),
    ("penetration testing cheatsheet",         "pentest"),
    ("linux privilege escalation script",      "privesc"),
    ("reverse shell bash python",              "exploit"),
    ("web vulnerability scanner python",       "vuln_scan"),
    ("subdomain enumeration bash",             "recon"),
    ("password cracking hashcat john",         "password"),
    ("network scanning automation",            "recon"),
    ("exploit development python",             "exploit"),
    ("osint automation python",                "osint"),
    ("burpsuite automation python",            "web_vuln"),
    ("xss payload list",                       "web_vuln"),
    ("sql injection payload",                  "web_vuln"),
    ("linux forensics bash script",            "forensics"),
    ("kali linux tool automation",             "tool_use"),
]

# ── NVD CVE fetch ─────────────────────────────────────────────────────────────

def fetch_nvd_cves(max_results=5000):
    log.info("NVD CVE fetch shuru...")
    items = []
    start = 0
    per_page = 2000
    headers = {"apiKey": NVD_API_KEY}

    while start < max_results:
        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"resultsPerPage": per_page, "startIndex": start},
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                log.warning(f"NVD error {r.status_code}")
                break
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                score = 0.0
                severity = "LOW"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    m = metrics.get(key, [])
                    if m:
                        cvss = m[0].get("cvssData", {})
                        score = cvss.get("baseScore", 0.0)
                        severity = cvss.get("baseSeverity", "LOW")
                        break
                if desc:
                    items.append({
                        "text": f"{cve_id}: {desc}",
                        "label": severity.upper(),
                        "type": "cve",
                        "score": score
                    })
            log.info(f"NVD: {len(items)} CVEs collected")
            start += per_page
            time.sleep(1)
        except Exception as e:
            log.error(f"NVD error: {e}")
            break
    return items

# ── GitHub repo content fetch ─────────────────────────────────────────────────

def search_github_repos(query, label, max_repos=10):
    items = []
    try:
        r = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": query, "sort": "stars", "per_page": max_repos},
            headers=GH_HEADERS, timeout=15
        )
        if r.status_code != 200:
            log.warning(f"GitHub search failed: {r.status_code} — {query}")
            return items
        repos = r.json().get("items", [])
        for repo in repos:
            full_name = repo["full_name"]
            readme = fetch_readme(full_name)
            if readme and len(readme) > 100:
                items.append({
                    "text": readme[:3000],
                    "label": "HIGH",
                    "type": label,
                    "source": f"github:{full_name}"
                })
            time.sleep(0.3)
    except Exception as e:
        log.error(f"GitHub repo search error: {e}")
    return items


def fetch_readme(full_name):
    try:
        r = requests.get(
            f"https://api.github.com/repos/{full_name}/readme",
            headers={**GH_HEADERS, "Accept": "application/vnd.github.v3.raw"},
            timeout=10
        )
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""


def search_github_code(query, label, max_results=30):
    items = []
    try:
        r = requests.get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": max_results},
            headers=GH_HEADERS, timeout=15
        )
        if r.status_code != 200:
            return items
        for item in r.json().get("items", []):
            raw_url = item.get("html_url", "").replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")
            try:
                rc = requests.get(raw_url, timeout=8)
                if rc.status_code == 200 and len(rc.text) > 50:
                    items.append({
                        "text": rc.text[:2000],
                        "label": "HIGH",
                        "type": label,
                        "source": raw_url
                    })
                time.sleep(0.2)
            except Exception:
                pass
    except Exception as e:
        log.error(f"GitHub code search error: {e}")
    return items


def fetch_github_gists(query, label):
    items = []
    try:
        r = requests.get(
            "https://api.github.com/gists/public",
            params={"per_page": 50},
            headers=GH_HEADERS, timeout=10
        )
        if r.status_code != 200:
            return items
        for gist in r.json():
            desc = gist.get("description", "")
            if any(kw in desc.lower() for kw in ["kali", "hack", "exploit", "pentest", "ctf", "nmap", "shell"]):
                for fname, fdata in gist.get("files", {}).items():
                    raw = fdata.get("raw_url", "")
                    if raw:
                        try:
                            rc = requests.get(raw, timeout=8)
                            if rc.status_code == 200:
                                items.append({
                                    "text": rc.text[:2000],
                                    "label": "HIGH",
                                    "type": label,
                                    "source": f"gist:{gist['id']}"
                                })
                        except Exception:
                            pass
        time.sleep(0.5)
    except Exception as e:
        log.error(f"Gist error: {e}")
    return items

# ── Main pipeline ─────────────────────────────────────────────────────────────

def run():
    all_data = []

    # 1. NVD CVEs
    cves = fetch_nvd_cves(max_results=10000)
    all_data.extend(cves)
    log.info(f"CVEs: {len(cves)}")

    # 2. GitHub repos
    for query, label in GITHUB_QUERIES:
        log.info(f"GitHub repos: {query}")
        items = search_github_repos(query, label, max_repos=15)
        all_data.extend(items)
        log.info(f"  +{len(items)} items (total: {len(all_data)})")
        time.sleep(1)

    # 3. GitHub code search — shell scripts
    code_queries = [
        ("nmap -sV -sC language:shell",          "recon"),
        ("sqlmap --batch language:python",        "exploit"),
        ("nikto -h language:shell",               "vuln_scan"),
        ("gobuster dir language:shell",           "recon"),
        ("hydra -l language:shell",               "password"),
        ("msfconsole -x language:ruby",           "exploit"),
        ("nuclei -u language:shell",              "vuln_scan"),
        ("subfinder -d language:shell",           "recon"),
        ("ffuf -w language:shell",                "recon"),
        ("hashcat -m language:shell",             "password"),
    ]
    for query, label in code_queries:
        log.info(f"GitHub code: {query}")
        items = search_github_code(query, label, max_results=20)
        all_data.extend(items)
        log.info(f"  +{len(items)} items (total: {len(all_data)})")
        time.sleep(2)

    # 4. Gists
    log.info("GitHub gists...")
    gists = fetch_github_gists("kali pentest", "tool_use")
    all_data.extend(gists)
    log.info(f"  +{len(gists)} gists (total: {len(all_data)})")

    # 5. Save
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for item in all_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    size_mb = OUT_FILE.stat().st_size / (1024 * 1024)
    log.info(f"\n✅ Done! {len(all_data)} samples → {OUT_FILE}")
    log.info(f"   Size: {size_mb:.1f} MB")

    # Stats
    from collections import Counter
    types = Counter(d["type"] for d in all_data)
    log.info("Type breakdown:")
    for t, c in types.most_common():
        log.info(f"  {t}: {c}")


if __name__ == "__main__":
    run()
