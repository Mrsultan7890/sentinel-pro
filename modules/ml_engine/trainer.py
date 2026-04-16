"""
ML Model Trainer — CRL se data collect karke models train karta hai.
Continuous learning: real OSINT scans se automatically training data badhta hai.

3 models train karta hai:
  1. ThreatClassifier    — text se threat level predict karo (LOW/MEDIUM/HIGH/CRITICAL)
  2. IdentityLinker      — do profiles same person hain ya nahi (0-1 probability)
  3. FakeProfileDetector — account genuine hai ya fake/bot (0-1 probability)

Continuous Learning Flow:
  Real scan hota hai
      ↓
  scan_result_to_training_data() automatically call hota hai
      ↓
  Labeled sample training pool mein save hota hai
      ↓
  Har 50 new samples ke baad model auto-retrain hota hai
      ↓
  Better accuracy next scan mein

Usage:
    from modules.ml_engine.trainer import ModelTrainer

    trainer = ModelTrainer()
    trainer.collect_data()   # CRL se data crawl karo
    trainer.train_all()      # teeno models train karo
    trainer.save_all()       # models/ml_engine/ mein save karo
    trainer.evaluate()       # accuracy report
"""

import json
import io
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine'
DATA_DIR   = MODELS_DIR / 'training_data'
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Continuous learning config
AUTO_RETRAIN_THRESHOLD = 50   # har 50 new real-scan samples ke baad auto-retrain
SCAN_DATA_FILE  = DATA_DIR / 'scan_feedback.jsonl'
COUNTER_FILE    = DATA_DIR / 'new_samples_counter.json'
PERF_LOG_FILE   = DATA_DIR / 'performance_log.jsonl'   # har retrain ke baad F1 score log

# Background retrain lock — ek waqt mein sirf ek retrain
_retrain_lock = threading.Lock()


# ── Training Queries ──────────────────────────────────────────────────────────
# CRL in queries se data crawl karega

# ── Trusted security sites — direct URL crawl (no DDG needed) ────────────────
# CRL ka deep_search in sites ke articles crawl karega
# Yeh approach DDG se zyada reliable hai — relevant content guaranteed

THREAT_SEED_URLS = {
    'CRITICAL': [
        'https://www.bleepingcomputer.com/news/security/',
        'https://www.bleepingcomputer.com/news/ransomware/',
        'https://krebsonsecurity.com/',
        'https://securelist.com/category/apt-reports/',
        'https://securelist.com/category/malware-descriptions/',
        'https://www.mandiant.com/resources/blog',
        'https://thedfirreport.com/',
        'https://any.run/malware-trends/',
        'https://www.welivesecurity.com/category/malware/',
        'https://www.welivesecurity.com/category/targeted-attacks/',
        'https://unit42.paloaltonetworks.com/',
        'https://www.crowdstrike.com/blog/category/threat-intel-research/',
        'https://decoded.avast.io/',
        'https://blog.malwarebytes.com/threat-intelligence/',
        'https://www.trendmicro.com/en_us/research.html',
    ],
    'HIGH': [
        'https://portswigger.net/research',
        'https://portswigger.net/daily-swig',
        'https://www.hackerone.com/vulnerability-and-security-testing-blog',
        'https://www.proofpoint.com/us/blog/threat-insight',
        'https://www.darkreading.com/threat-intelligence',
        'https://threatpost.com/',
        'https://www.group-ib.com/blog/',
        'https://www.rapid7.com/blog/tag/vulnerability/',
        'https://www.tenable.com/blog',
        'https://www.qualys.com/research/security-advisories/',
        'https://googleprojectzero.blogspot.com/',
        'https://www.zerodayinitiative.com/blog',
    ],
    'MEDIUM': [
        'https://owasp.org/www-project-top-ten/',
        'https://portswigger.net/web-security/all-topics',
        'https://portswigger.net/web-security/all-labs',
        'https://www.hackerone.com/blog',
        'https://rhinosecuritylabs.com/blog/',
        'https://www.sans.org/blog/',
        'https://attack.mitre.org/techniques/',
        'https://bishopfox.com/blog',
        'https://www.netspi.com/blog/technical/',
        'https://www.offensive-security.com/offsec/penetration-testing-techniques/',
        'https://pentestlab.blog/',
        'https://book.hacktricks.xyz/',
        'https://www.hackingarticles.in/',
    ],
    'LOW': [
        'https://www.sans.org/security-awareness-training/',
        'https://www.darkreading.com/cybersecurity-operations',
        'https://www.securityweek.com/',
        'https://www.csoonline.com/category/security/',
        'https://www.infosecurity-magazine.com/',
        'https://www.helpnetsecurity.com/',
        'https://cybersecuritynews.com/',
        'https://www.tripwire.com/state-of-security/',
        'https://www.schneier.com/',
        'https://nakedsecurity.sophos.com/',
    ],
}

# Query used for relevance ranking after crawl
THREAT_RANK_QUERIES = {
    'CRITICAL': 'ransomware malware exploit backdoor trojan APT breach credential infostealer',
    'HIGH':     'phishing vulnerability attack injection XSS SQLi DDoS fraud lateral movement',
    'MEDIUM':   'penetration testing bug bounty security audit misconfiguration vulnerability',
    'LOW':      'security awareness training guide best practice certification news',
}

# Keywords that MUST appear — filter irrelevant pages
THREAT_REQUIRED_KEYWORDS = {
    'CRITICAL': ['ransomware','malware','exploit','backdoor','trojan','botnet',
                 'zero-day','zero day','apt','breach','credential','infostealer',
                 'rootkit','exfiltrat','supply chain','mimikatz','fileless',
                 'cyberattack','threat actor','nation state','data leak'],
    'HIGH':     ['phishing','vulnerabilit','attack','hack','injection','xss','sqli',
                 'ddos','fraud','brute force','lateral movement','keylogger',
                 'remote access','social engineer','business email','cryptojack'],
    'MEDIUM':   ['pentest','penetration','security audit','bug bounty','scan',
                 'assessment','misconfigur','cors','jwt','subdomain takeover',
                 'information disclosure','security header','api security',
                 'vulnerability','security finding','owasp'],
    'LOW':      ['security awareness','security training','security guide',
                 'best practice','certification','security news','ctf',
                 'security career','zero trust','devsecops','threat model',
                 'gdpr','iso 27001','vpn','password manager','cybersecurity'],
}

FAKE_REQUIRED_KEYWORDS = {
    1: ['bot','fake','spam','automated account','coordinated','astroturf',
        'deepfake','sock puppet','disinformation','fake follower','fake review',
        'catfish','impersonat','scam','manipulation','bot detection','fake profile'],
    0: ['security researcher','software developer','journalist','professor',
        'security analyst','security engineer','professional','oscp',
        'cissp','bug bounty hunter','penetration tester','forensic',
        'threat researcher','malware analyst','verified'],
}

# Blocked domains — always skip these
BLOCKED_DOMAINS = {
    'support.google.com', 'accounts.google.com', 'play.google.com',
    'wikipedia.org', 'apple.com', 'amazon.com', 'youtube.com',
    'baidu.com', 'justdial.com', 'chromebook', 'chrome_webstore',
}


FAKE_PROFILE_QUERIES = {
    'fake': [
        'bot account detection social media analysis research',
        'fake follower detection machine learning study',
        'coordinated inauthentic behavior detection report',
        'social media spam bot behavior patterns analysis',
        # New
        'automated twitter bot account detection research',
        'instagram fake follower bot account characteristics',
        'facebook fake account network takedown report',
        'tiktok spam bot account behavior analysis',
        'telegram spam bot account flood attack',
        'social media astroturfing political manipulation bots',
        'deepfake profile picture AI generated face detection',
        'sock puppet account network disinformation campaign',
        'fake review bot amazon yelp detection research',
        'crypto pump dump scheme fake social media accounts',
        'romance scam fake profile catfishing detection',
        'impersonation account celebrity fake profile report',
    ],
    'real': [
        'security researcher personal blog portfolio',
        'software developer github open source contributions',
        'ethical hacker bug bounty hunter profile writeup',
        'OSINT investigator digital forensics professional',
        # New
        'cybersecurity professional linkedin verified profile',
        'malware analyst threat researcher published work',
        'penetration tester OSCP certified professional blog',
        'data scientist machine learning engineer portfolio',
        'journalist investigative reporter verified account',
        'academic professor university research publication',
        'startup founder entrepreneur verified social media',
        'government official verified public figure account',
        'doctor medical professional verified healthcare',
        'lawyer attorney verified legal professional profile',
        'activist human rights verified organization account',
        'artist musician verified creative professional',
    ],
}

# Synthetic samples — guaranteed labeled data
# Fake profile patterns (bots, spam accounts)
SYNTHETIC_FAKE = [
    "Follow me for daily crypto tips! 100x gains guaranteed! DM for signals. Bitcoin Ethereum NFT Web3 investment",
    "Make $500/day working from home! Click link in bio. Limited offer! Join now! Free money passive income",
    "I follow back! Follow4Follow F4F like4like comment4comment. Growing my account fast!",
    "Buy real Instagram followers cheap! 1000 followers $5. Boost your account today. DM us!",
    "OnlyFans link in bio! Hot content daily. Subscribe now. 18+ only. Free trial today!",
    "Retweet to win iPhone 15! Follow and RT. Winner announced Friday. 100% legit giveaway!",
    "I am professional trader. 95% win rate. Join my VIP group. Only $99/month. Proof in highlights.",
    "Account created 2 days ago. 0 posts. Following 5000 people. No profile picture. No bio.",
    "URGENT: Your account will be suspended! Click here to verify: bit.ly/verify-now",
    "Hello dear friend I am from Nigeria I need your help to transfer $5 million USD",
]

# Real profile patterns (genuine users)
SYNTHETIC_REAL = [
    "Security researcher at Google Project Zero. I find and report vulnerabilities. Views are my own. he/him",
    "PhD student in Computer Science at MIT. Researching adversarial machine learning. Open source contributor.",
    "Penetration tester and bug bounty hunter. OSCP certified. I write about web security and CTF challenges.",
    "Journalist covering cybersecurity and privacy. Previously at Wired, now freelance. DMs open for tips.",
    "Software engineer at Mozilla. Working on Firefox security. Rust enthusiast. Open source everything.",
    "Digital forensics investigator. 10 years in law enforcement. Now private sector. SANS instructor.",
    "Malware analyst at Mandiant. I reverse engineer threats for a living. Occasional conference speaker.",
    "CISO at a Fortune 500 company. 20 years in infosec. Board advisor. Author of two security books.",
    "CTF player and security student. Learning web exploitation and binary analysis. Writeups on my blog.",
    "Privacy advocate and researcher. Working on surveillance technology policy. EFF member.",
]


class ModelTrainer:
    """
    CRL se data collect karke ML models train karta hai.
    Models joblib format mein save hote hain models/ml_engine/ mein.
    """

    def __init__(self, use_semantic: bool = False):
        """
        use_semantic: True = sentence-transformers use karo (better accuracy, slower)
                      False = TF-IDF only (faster, good enough)
        """
        self.use_semantic = use_semantic
        self.threat_clf   = None
        self.identity_clf = None
        self.fake_clf     = None
        self._threat_data: list  = []
        self._fake_data:   list  = []
        self._identity_data: list = []

    # ── Data Collection ───────────────────────────────────────────────────────

    def collect_premium_sources(self) -> dict:
        """
        Free premium sources se high-quality labeled data collect karo:
        1. MITRE ATT&CK  — 835 techniques + 696 malware descriptions (CRITICAL/HIGH)
        2. NVD CVE        — NIST vulnerability database (CRITICAL/HIGH by CVSS score)
        3. Hugging Face   — fake profile detection dataset
        4. Duplicate cleanup — existing data se duplicates remove karo
        """
        import requests
        import warnings
        warnings.filterwarnings('ignore')

        threat_path = DATA_DIR / 'threat_raw.jsonl'
        fake_path   = DATA_DIR / 'fake_raw.jsonl'

        # Existing URLs/texts track karo
        existing_threat = set()
        if threat_path.exists():
            with open(threat_path) as f:
                for line in f:
                    try: existing_threat.add(json.loads(line).get('url',''))
                    except: pass

        stats = {'mitre': 0, 'nvd': 0, 'hf_fake': 0, 'duplicates_removed': 0}

        # ── 1. MITRE ATT&CK ──────────────────────────────────────────────────
        logger.info("MITRE ATT&CK se data collect kar raha hoon...")
        try:
            r = requests.get(
                'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
                timeout=30
            )
            if r.status_code == 200:
                objects = r.json().get('objects', [])
                with open(threat_path, 'a') as f:
                    for obj in objects:
                        obj_type = obj.get('type', '')
                        name     = obj.get('name', '')
                        desc     = obj.get('description', '')
                        url      = f"mitre_{obj.get('id','')}"

                        if not desc or url in existing_threat:
                            continue

                        # Label assign karo type se
                        if obj_type == 'attack-pattern':
                            phases = [k['phase_name'] for k in obj.get('kill_chain_phases', [])]
                            if any(p in phases for p in ['execution','exfiltration','impact','command-and-control']):
                                label = 'CRITICAL'
                            elif any(p in phases for p in ['privilege-escalation','defense-evasion','lateral-movement']):
                                label = 'HIGH'
                            else:
                                label = 'MEDIUM'
                        elif obj_type == 'malware':
                            label = 'CRITICAL'
                        elif obj_type == 'tool':
                            label = 'HIGH'
                        elif obj_type == 'campaign':
                            label = 'CRITICAL'
                        else:
                            continue

                        # Clean description — HTML tags remove karo
                        import re
                        clean = re.sub(r'\(Citation:[^)]+\)', '', desc)
                        clean = re.sub(r'<[^>]+>', '', clean).strip()
                        text  = f"{name}. {clean}"[:2000]

                        if len(text) >= 50:
                            f.write(json.dumps({
                                'text': text, 'label': label,
                                'url': url, 'source': 'mitre_attack'
                            }) + '\n')
                            existing_threat.add(url)
                            stats['mitre'] += 1

                logger.info(f"  MITRE ATT&CK: +{stats['mitre']} samples")
        except Exception as e:
            logger.warning(f"MITRE ATT&CK failed: {e}")

        # ── 2. NVD CVE ───────────────────────────────────────────────────────
        logger.info("NVD CVE database se data collect kar raha hoon...")
        try:
            import config as _cfg
            nvd_key = getattr(_cfg, 'NVD_API_KEY', '')
            headers = {'apiKey': nvd_key} if nvd_key else {}

            # CVSS severity levels se labeled data
            severity_label = {
                'CRITICAL': 'CRITICAL',
                'HIGH':     'HIGH',
                'MEDIUM':   'MEDIUM',
                'LOW':      'LOW',
            }
            with open(threat_path, 'a') as f:
                for severity, label in severity_label.items():
                    try:
                        r = requests.get(
                            'https://services.nvd.nist.gov/rest/json/cves/2.0',
                            params={'cvssV3Severity': severity, 'resultsPerPage': 100},
                            headers=headers, timeout=15
                        )
                        if r.status_code == 200:
                            cves = r.json().get('vulnerabilities', [])
                            for item in cves:
                                cve  = item.get('cve', {})
                                cid  = cve.get('id', '')
                                url  = f"nvd_{cid}"
                                if url in existing_threat:
                                    continue
                                descs = cve.get('descriptions', [])
                                desc  = next((d['value'] for d in descs if d.get('lang') == 'en'), '')
                                if len(desc) >= 30:
                                    score = item.get('cve', {}).get('metrics', {}).get(
                                        'cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', '')
                                    text = f"{cid} CVSS:{score} {desc}"[:2000]
                                    f.write(json.dumps({
                                        'text': text, 'label': label,
                                        'url': url, 'source': 'nvd_cve'
                                    }) + '\n')
                                    existing_threat.add(url)
                                    stats['nvd'] += 1
                        time.sleep(0.6)  # NVD rate limit
                    except Exception as e:
                        logger.debug(f"NVD {severity} failed: {e}")

            logger.info(f"  NVD CVE: +{stats['nvd']} samples")
        except Exception as e:
            logger.warning(f"NVD CVE failed: {e}")

        # ── 3. Hugging Face — PhishingEmail + CIRCL CVE + fake profile ────────────────
        logger.info("Hugging Face datasets se data collect kar raha hoon...")
        try:
            import pandas as pd
        except ImportError:
            logger.warning("pandas not installed — pip install pandas pyarrow")
            pd = None

        if pd:
            # 3a. PhishingEmailDetection — 120K emails, label 0-3
            # label: 0=safe, 1=safe, 2=phishing, 3=phishing
            try:
                logger.info("  PhishingEmailDetectionv2.0 (120K emails)...")
                r = requests.get(
                    'https://huggingface.co/datasets/cybersectony/PhishingEmailDetectionv2.0/resolve/main/data/train-00000-of-00001.parquet',
                    timeout=60
                )
                if r.status_code == 200:
                    df = pd.read_parquet(io.BytesIO(r.content))
                    existing_fake_texts = set()
                    if fake_path.exists():
                        with open(fake_path) as f:
                            for line in f:
                                try: existing_fake_texts.add(json.loads(line).get('text','')[:50])
                                except: pass
                    with open(fake_path, 'a') as f:
                        for _, row in df.iterrows():
                            text = str(row.get('content', ''))
                            raw_label = int(row.get('label', -1))
                            if raw_label < 0 or len(text) < 20:
                                continue
                            # 0,1 = legitimate, 2,3 = phishing/spam
                            label = 1 if raw_label >= 2 else 0
                            if text[:50] not in existing_fake_texts:
                                f.write(json.dumps({
                                    'text': text[:500], 'label': label,
                                    'url': 'hf_phishing_email', 'source': 'huggingface'
                                }) + '\n')
                                existing_fake_texts.add(text[:50])
                                stats['hf_fake'] += 1
                    logger.info(f"  PhishingEmail: +{stats['hf_fake']} samples")
            except Exception as e:
                logger.warning(f"PhishingEmail dataset failed: {e}")

            # 3b. CIRCL CVE — description + cvss score se labeled threat data
            try:
                logger.info("  CIRCL/vulnerability-scores (CVE descriptions)...")
                circl_added = 0
                # HuggingFace datasets-server API se rows fetch karo (no download needed)
                offset = 0
                batch_size = 100
                with open(threat_path, 'a') as f:
                    while circl_added < 2000:  # max 2000 CVE samples
                        r = requests.get(
                            'https://datasets-server.huggingface.co/rows',
                            params={
                                'dataset': 'CIRCL/vulnerability-scores',
                                'config': 'default', 'split': 'train',
                                'offset': offset, 'length': batch_size
                            }, timeout=15
                        )
                        if r.status_code != 200:
                            break
                        rows = r.json().get('rows', [])
                        if not rows:
                            break
                        for item in rows:
                            row = item.get('row', {})
                            cve_id = row.get('id', '')
                            desc   = row.get('description', '')
                            url    = f"circl_{cve_id}"
                            if url in existing_threat or len(desc) < 30:
                                continue
                            # CVSS score se label
                            score = (row.get('cvss_v3_1') or row.get('cvss_v3_0') or
                                     row.get('cvss_v4_0') or row.get('cvss_v2_0') or 0)
                            try: score = float(score)
                            except: score = 0
                            if score >= 9.0:   label = 'CRITICAL'
                            elif score >= 7.0: label = 'HIGH'
                            elif score >= 4.0: label = 'MEDIUM'
                            else:              label = 'LOW'
                            text = f"{cve_id} CVSS:{score} {desc}"[:2000]
                            f.write(json.dumps({
                                'text': text, 'label': label,
                                'url': url, 'source': 'circl_cve'
                            }) + '\n')
                            existing_threat.add(url)
                            circl_added += 1
                        offset += batch_size
                        time.sleep(0.3)
                stats['hf_fake'] = stats.get('hf_fake', 0)  # keep existing
                stats['circl_cve'] = circl_added
                logger.info(f"  CIRCL CVE: +{circl_added} samples")
            except Exception as e:
                logger.warning(f"CIRCL CVE failed: {e}")
                stats['circl_cve'] = 0
        else:
            stats['hf_fake'] = 0
            stats['circl_cve'] = 0

        # ── 4. Duplicate cleanup ──────────────────────────────────────────────
        logger.info("Duplicate cleanup kar raha hoon...")
        for path in [threat_path, fake_path]:
            if not path.exists():
                continue
            lines = path.read_text().splitlines()
            seen, unique = set(), []
            for line in lines:
                if not line.strip():
                    continue
                try:
                    key = json.loads(line).get('text', '')[:100]
                    if key not in seen:
                        seen.add(key)
                        unique.append(line)
                    else:
                        stats['duplicates_removed'] += 1
                except:
                    unique.append(line)
            path.write_text('\n'.join(unique) + '\n')

        logger.info(f"Duplicates removed: {stats['duplicates_removed']}")

        # Reload
        self._load_raw_data()
        self._inject_synthetic_samples()

        return {
            'mitre_attack':        stats['mitre'],
            'nvd_cve':             stats['nvd'],
            'huggingface_phishing': stats.get('hf_fake', 0),
            'circl_cve':           stats.get('circl_cve', 0),
            'duplicates_removed':  stats['duplicates_removed'],
            'total_threat':        len(self._threat_data),
            'total_fake':          len(self._fake_data),
        }

    def collect_data(
        self,
        max_pages_per_site: int = 8,
        rate_limit: float = 2.0,
        use_cache: bool = True,
    ) -> dict:
        """
        CRL deep_search se trusted security sites crawl karo.
        search_and_crawl NAHI — DDG generic/irrelevant results deta hai.
        deep_search directly security sites ke articles crawl karta hai.
        """
        try:
            from crl import deep_search, TieredCache
        except ImportError:
            raise ImportError("CRL not installed. Run: pip install crawl-relevance-layers")

        cache = TieredCache(
            memory_size=500, memory_ttl=86400,
            disk_path=str(DATA_DIR / '.crl_cache'), disk_ttl=604800,
        ) if use_cache else None

        logger.info("CRL deep_search se trusted security sites crawl kar raha hoon...")

        # ── Threat data ───────────────────────────────────────────────────────
        threat_raw_path = DATA_DIR / 'threat_raw.jsonl'
        existing_threat_urls = set()
        if threat_raw_path.exists():
            with open(threat_raw_path) as f:
                for line in f:
                    try: existing_threat_urls.add(json.loads(line).get('url', ''))
                    except Exception: pass
            logger.info(f"  Existing threat samples: {len(existing_threat_urls)}")

        new_threat = 0
        with open(threat_raw_path, 'a') as f:
            for label, seed_urls in THREAT_SEED_URLS.items():
                rank_query = THREAT_RANK_QUERIES[label]
                required   = THREAT_REQUIRED_KEYWORDS[label]
                logger.info(f"  [{label}] Crawling {len(seed_urls)} trusted sites...")
                try:
                    results = deep_search(
                        urls=seed_urls,
                        query=rank_query,
                        depth=1,
                        max_pages=max_pages_per_site * len(seed_urls),
                        max_pages_per_domain=max_pages_per_site,
                        follow_external=False,
                        top_k=max_pages_per_site * len(seed_urls),
                        mode='keyword',
                        rate_limit=rate_limit,
                        cache=cache,
                        min_text_length=150,
                    )
                    for r in results:
                        text = r.get('text', '').strip()
                        url  = r.get('url', '')
                        if url in existing_threat_urls: continue
                        if any(d in url.lower() for d in BLOCKED_DOMAINS): continue
                        if not any(kw in text.lower() for kw in required): continue
                        if len(text) >= 150:
                            f.write(json.dumps({
                                'text': text[:2000], 'label': label,
                                'url': url, 'score': r.get('relevance_score', 0),
                            }) + '\n')
                            existing_threat_urls.add(url)
                            new_threat += 1
                except Exception as e:
                    logger.warning(f"  [{label}] Crawl failed: {e}")
        logger.info(f"  Threat data: +{new_threat} new samples")

        # ── Fake profile data ─────────────────────────────────────────────────
        fake_raw_path = DATA_DIR / 'fake_raw.jsonl'
        existing_fake_urls = set()
        if fake_raw_path.exists():
            with open(fake_raw_path) as f:
                for line in f:
                    try: existing_fake_urls.add(json.loads(line).get('url', ''))
                    except Exception: pass
            logger.info(f"  Existing fake samples: {len(existing_fake_urls)}")

        FAKE_SEED_URLS = {
            1: [
                'https://www.technologyreview.com/topic/artificial-intelligence/',
                'https://www.wired.com/tag/bots/',
                'https://firstdraftnews.org/topic/disinformation/',
                'https://www.atlanticcouncil.org/programs/digital-forensic-research-lab/',
            ],
            0: [
                'https://portswigger.net/research',
                'https://www.hackerone.com/blog',
                'https://www.darkreading.com/vulnerabilities-threats',
                'https://www.sans.org/blog/',
            ],
        }
        FAKE_RANK_QUERIES = {
            1: 'fake bot account social media automated spam disinformation deepfake',
            0: 'security researcher professional verified expert analyst bug bounty',
        }

        new_fake = 0
        with open(fake_raw_path, 'a') as f:
            for label, seed_urls in FAKE_SEED_URLS.items():
                rank_query = FAKE_RANK_QUERIES[label]
                required   = FAKE_REQUIRED_KEYWORDS[label]
                logger.info(f"  [fake={label}] Crawling {len(seed_urls)} sites...")
                try:
                    results = deep_search(
                        urls=seed_urls,
                        query=rank_query,
                        depth=1,
                        max_pages=max_pages_per_site * len(seed_urls),
                        max_pages_per_domain=max_pages_per_site,
                        follow_external=False,
                        top_k=max_pages_per_site * len(seed_urls),
                        mode='keyword',
                        rate_limit=rate_limit,
                        cache=cache,
                        min_text_length=150,
                    )
                    for r in results:
                        text = r.get('text', '').strip()
                        url  = r.get('url', '')
                        if url in existing_fake_urls: continue
                        if any(d in url.lower() for d in BLOCKED_DOMAINS): continue
                        if not any(kw in text.lower() for kw in required): continue
                        if len(text) >= 150:
                            f.write(json.dumps({
                                'text': text[:2000], 'label': label, 'url': url,
                            }) + '\n')
                            existing_fake_urls.add(url)
                            new_fake += 1
                except Exception as e:
                    logger.warning(f"  [fake={label}] Crawl failed: {e}")
        logger.info(f"  Fake data: +{new_fake} new samples")

        # Load into memory + inject synthetic
        self._load_raw_data()
        self._inject_synthetic_samples()

        return {
            'threat': len(self._threat_data),
            'fake':   len(self._fake_data),
            'total':  len(self._threat_data) + len(self._fake_data),
        }
    def _inject_synthetic_samples(self):
        """Synthetic labeled samples inject karo — web crawl ke results supplement karo."""
        fake_path = DATA_DIR / 'fake_raw.jsonl'

        # Existing texts ka set — fake aur real dono se alag-alag track karo
        existing_texts = {d['text'][:50] for d in self._fake_data}
        new_fake = 0
        with open(fake_path, 'a') as f:
            for text in SYNTHETIC_FAKE:
                if text[:50] not in existing_texts:
                    f.write(json.dumps({'text': text, 'label': 1, 'url': 'synthetic'}) + '\n')
                    self._fake_data.append({'text': text, 'label': 1})
                    existing_texts.add(text[:50])
                    new_fake += 1
            for text in SYNTHETIC_REAL:
                if text[:50] not in existing_texts:
                    f.write(json.dumps({'text': text, 'label': 0, 'url': 'synthetic'}) + '\n')
                    self._fake_data.append({'text': text, 'label': 0})
                    existing_texts.add(text[:50])
                    new_fake += 1

        if new_fake > 0:
            logger.info(f"Synthetic samples injected: {new_fake} fake/real profile samples")

    def _load_raw_data(self):
        """Saved JSONL files se data load karo."""
        threat_path = DATA_DIR / 'threat_raw.jsonl'
        fake_path   = DATA_DIR / 'fake_raw.jsonl'

        if threat_path.exists():
            with open(threat_path) as f:
                self._threat_data = [json.loads(l) for l in f if l.strip()]
            logger.info(f"Threat data loaded: {len(self._threat_data)} samples")

        if fake_path.exists():
            with open(fake_path) as f:
                self._fake_data = [json.loads(l) for l in f if l.strip()]
            logger.info(f"Fake data loaded: {len(self._fake_data)} samples")

    def add_manual_sample(self, text: str, threat_label: str = None, fake_label: int = None):
        """
        Manually labeled sample add karo — real scan results se.

        Args:
            text:         Profile bio / post text
            threat_label: 'LOW' / 'MEDIUM' / 'HIGH' / 'CRITICAL'
            fake_label:   1 = fake, 0 = real
        """
        if threat_label:
            self._threat_data.append({'text': text, 'label': threat_label})
            # Append to file bhi
            with open(DATA_DIR / 'threat_raw.jsonl', 'a') as f:
                f.write(json.dumps({'text': text[:2000], 'label': threat_label, 'url': 'manual'}) + '\n')

        if fake_label is not None:
            self._fake_data.append({'text': text, 'label': fake_label})
            with open(DATA_DIR / 'fake_raw.jsonl', 'a') as f:
                f.write(json.dumps({'text': text[:2000], 'label': fake_label, 'url': 'manual'}) + '\n')

    # ── Training ──────────────────────────────────────────────────────────────

    def train_all(self) -> dict:
        """Teeno models train karo. Data pehle collect karo."""
        if not self._threat_data and not self._fake_data:
            self._load_raw_data()

        # Synthetic samples inject karo agar nahi hain
        self._inject_synthetic_samples()

        results = {}

        if len(self._threat_data) >= 10:
            results['threat']   = self._train_threat_classifier()
        else:
            logger.warning(f"Threat data insufficient ({len(self._threat_data)} samples, need 10+). Run collect_data() first.")
            results['threat'] = None

        if len(self._fake_data) >= 10:
            results['fake']     = self._train_fake_detector()
        else:
            logger.warning(f"Fake data insufficient ({len(self._fake_data)} samples, need 10+). Run collect_data() first.")
            results['fake'] = None

        results['identity'] = self._train_identity_linker()

        return results

    def _train_threat_classifier(self) -> dict:
        """
        ThreatClassifier train karo.
        Input: text → Output: LOW/MEDIUM/HIGH/CRITICAL
        Algorithm: TF-IDF + LogisticRegression (fast, explainable)
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import cross_val_score, StratifiedKFold
        from sklearn.preprocessing import LabelEncoder
        from collections import Counter

        logger.info("ThreatClassifier training shuru...")

        texts  = [d['text']  for d in self._threat_data]
        labels = [d['label'] for d in self._threat_data]

        # Class distribution check — imbalance warn karo
        dist = Counter(labels)
        logger.info(f"  Class distribution: {dict(dist)}")
        min_class = min(dist.values())
        if min_class < 10:
            logger.warning(f"  Low samples in some classes ({min_class}) — balanced weighting applied")

        # Label encode
        le = LabelEncoder()
        le.fit(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        y = le.transform(labels)

        # Pipeline: TF-IDF → LogisticRegression
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                sublinear_tf=True,
                stop_words='english',
            )),
            ('clf', LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                C=0.5,
                solver='lbfgs',
            )),
        ])

        # Cross-validation — stratified to handle imbalance
        if len(texts) >= 20:
            n_splits = min(5, min(dist.values()))  # cv folds can't exceed min class count
            n_splits = max(2, n_splits)
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            cv_scores = cross_val_score(pipeline, texts, y, cv=cv, scoring='f1_weighted')
            logger.info(f"  CV F1 score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f} (stratified {n_splits}-fold)")
        else:
            logger.info(f"  Training on {len(texts)} samples (too few for CV)")

        pipeline.fit(texts, y)
        self.threat_clf = (pipeline, le)

        logger.info(f"  ThreatClassifier trained on {len(texts)} samples")
        return {'samples': len(texts), 'classes': list(le.classes_)}

    def _train_fake_detector(self) -> dict:
        """
        FakeProfileDetector train karo.
        Input: text → Output: fake probability (0-1)
        Algorithm: TF-IDF + RandomForest
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import cross_val_score

        logger.info("FakeProfileDetector training shuru...")

        texts  = [d['text']  for d in self._fake_data]
        labels = [d['label'] for d in self._fake_data]
        y = np.array(labels, dtype=int)

        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=3000,
                ngram_range=(1, 2),
                sublinear_tf=True,
                stop_words='english',
            )),
            ('clf', RandomForestClassifier(
                n_estimators=100,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1,
            )),
        ])

        if len(texts) >= 20:
            cv_scores = cross_val_score(pipeline, texts, y, cv=5, scoring='f1')
            logger.info(f"  CV F1 score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

        pipeline.fit(texts, y)
        self.fake_clf = pipeline

        logger.info(f"  FakeProfileDetector trained on {len(texts)} samples")
        return {'samples': len(texts)}

    def _train_identity_linker(self) -> dict:
        """
        IdentityLinker — real scan data se username similarity thresholds calibrate karo.
        Agar labeled pairs hain toh supervised training, warna unsupervised threshold tuning.
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline

        logger.info("IdentityLinker training shuru...")

        # Identity pairs scan feedback se collect karo
        pairs_path = DATA_DIR / 'identity_pairs.jsonl'
        pairs = []
        if pairs_path.exists():
            with open(pairs_path) as f:
                for line in f:
                    try:
                        pairs.append(json.loads(line))
                    except Exception:
                        continue

        if len(pairs) >= 10:
            # Supervised: labeled pairs se train karo
            texts  = [f"{p['text_a']} [SEP] {p['text_b']}" for p in pairs]
            labels = [int(p['same_person']) for p in pairs]
            import numpy as _np
            y = _np.array(labels)
            pipeline = Pipeline([
                ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(2,4),
                                          max_features=1000, sublinear_tf=True)),
                ('clf',   LogisticRegression(max_iter=500, class_weight='balanced')),
            ])
            pipeline.fit(texts, y)
            self.identity_clf = pipeline
            logger.info(f"  IdentityLinker trained on {len(pairs)} labeled pairs")
            return {'status': 'supervised_trained', 'pairs': len(pairs)}
        else:
            # Unsupervised: EntityMatcher thresholds ko scan data se calibrate karo
            # Real scan se mile username pairs se similarity distribution nikalo
            username_pairs = []
            if SCAN_DATA_FILE.exists():
                with open(SCAN_DATA_FILE) as f:
                    for line in f:
                        try:
                            s = json.loads(line)
                            if s.get('type') == 'identity_pair':
                                username_pairs.append(s)
                        except Exception:
                            continue

            calibrated_threshold = 0.72  # default
            if len(username_pairs) >= 5:
                # Average similarity se threshold adjust karo
                sims = [p.get('similarity', 0.72) for p in username_pairs]
                import numpy as _np
                calibrated_threshold = round(float(_np.percentile(sims, 70)), 3)
                logger.info(f"  IdentityLinker threshold calibrated: {calibrated_threshold}")

            self.identity_clf = {'threshold': calibrated_threshold, 'type': 'threshold_based'}
            return {'status': 'threshold_calibrated', 'threshold': calibrated_threshold,
                    'note': f'Add labeled pairs to {pairs_path} for supervised training'}

    # ── Continuous Learning — Real Scan Data ────────────────────────────────

    @staticmethod
    def scan_result_to_training_data(scan_type: str, result: dict) -> int:
        """
        Real OSINT scan result se automatically training data extract karo.
        Har scan ke baad call hota hai — model continuously improve hota rehta hai.

        Args:
            scan_type: 'nlp' | 'fakecheck' | 'breach' | 'bugbounty' | 'person'
            result:    scan result dict

        Returns:
            Number of new samples added
        """
        added = 0

        try:
            if scan_type == 'nlp' and result.get('risk_level'):
                # NLP scan — text + risk_level = threat training sample
                texts = []
                if result.get('writing_style', {}).get('total_words', 0) > 10:
                    # Reconstruct text from key topics + professions
                    topics   = ' '.join(t['topic'] for t in result.get('key_topics', [])[:10])
                    profs    = ' '.join(p['profession'] for p in result.get('professions', [])[:3])
                    # contacts save NAHI karte — PII (emails, phones) ho sakti hai
                    text = f"{topics} {profs}".strip()
                    if len(text) >= 20:
                        texts.append(text)

                risk = result.get('risk_level', 'LOW')
                # ml_threat se override karo agar available
                if result.get('ml_threat', {}).get('label'):
                    risk = result['ml_threat']['label']

                for text in texts:
                    ModelTrainer._append_scan_sample('threat', text, risk)
                    added += 1

            elif scan_type == 'fakecheck' and result.get('overall_fake_score') is not None:
                # Fakecheck scan — score se label derive karo
                score = result.get('overall_fake_score', 0)
                fake_label = 1 if score >= 50 else 0

                # Content extract karo
                texts = []
                for ind in result.get('suspicious_indicators', []):
                    desc = ind.get('description', '')
                    if len(desc) >= 20:
                        texts.append(desc)

                # ML analysis se bhi
                ml = result.get('ml_analysis', {})
                for sample in ml.get('flagged_samples', []):
                    snippet = sample.get('snippet', '')
                    if len(snippet) >= 20:
                        texts.append(snippet)

                for text in texts[:5]:  # max 5 per scan
                    ModelTrainer._append_scan_sample('fake', text, fake_label)
                    added += 1

            elif scan_type == 'breach' and result.get('risk_level'):
                # Breach scan — target + risk level
                risk_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH',
                            'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
                risk = risk_map.get(result.get('risk_level', 'LOW'), 'LOW')
                summary = ' '.join(result.get('summary', []))
                if len(summary) >= 20:
                    ModelTrainer._append_scan_sample('threat', summary, risk)
                    added += 1

            elif scan_type == 'person' and result.get('risk_level'):
                risk = result.get('risk_level', 'LOW')
                flags = result.get('risk_flags', [])
                platform_count = len(result.get('social_profiles', []))
                if flags or platform_count > 0:
                    desc = f"Found on {platform_count} platforms. " + \
                           ' '.join(f.get('detail', '') for f in flags[:2])
                    if len(desc) >= 20:
                        ModelTrainer._append_scan_sample('threat', desc, risk)
                        added += 1

                # Identity pairs — same person ke alag usernames save karo (no PII)
                profiles = result.get('social_profiles', [])
                if len(profiles) >= 2:
                    for i in range(len(profiles)):
                        for j in range(i + 1, min(i + 3, len(profiles))):
                            pa = profiles[i].get('username', '')
                            pb = profiles[j].get('username', '')
                            if pa and pb and pa != pb:
                                ModelTrainer._append_scan_sample(
                                    'identity_pair',
                                    json.dumps({'text_a': pa, 'text_b': pb,
                                                'same_person': 1, 'source': 'person_osint'}),
                                    'same_person'
                                )

            elif scan_type == 'bugbounty' and result.get('target'):
                risk_map = {
                    'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH',
                    'MEDIUM': 'MEDIUM',     'LOW': 'LOW'
                }

                # 1. Vuln scan (SQLi/XSS/SSRF)
                vulns = result.get('vulns', {})
                if vulns and not vulns.get('error'):
                    risk = risk_map.get(vulns.get('risk_level', 'LOW'), 'LOW')
                    all_v = (vulns.get('sqli', []) + vulns.get('xss', []) +
                             vulns.get('ssrf', []) + vulns.get('blind_sqli', []))
                    for v in all_v[:3]:
                        desc = f"{v.get('type','')} vulnerability param={v.get('param','')} {v.get('evidence','')}"
                        if len(desc) >= 20:
                            ModelTrainer._append_scan_sample('threat', desc, risk)
                            added += 1

                # 2. SSTI findings
                ssti = result.get('ssti', {})
                if ssti and not ssti.get('error') and ssti.get('total', 0) > 0:
                    risk = risk_map.get(ssti.get('risk_level', 'HIGH'), 'HIGH')
                    for f in ssti.get('findings', [])[:2]:
                        desc = f"SSTI {f.get('engine','')} template injection param={f.get('param','')} payload={f.get('payload','')}"
                        ModelTrainer._append_scan_sample('threat', desc, risk)
                        added += 1

                # 3. DNS Zone Transfer
                zt = result.get('zone_transfer', {})
                if zt and zt.get('vulnerable'):
                    desc = f"DNS zone transfer AXFR allowed {len(zt['vulnerable'])} nameservers expose all DNS records"
                    ModelTrainer._append_scan_sample('threat', desc, 'CRITICAL')
                    added += 1

                # 4. HTTP Smuggling
                smug = result.get('smuggling', {})
                if smug and smug.get('findings'):
                    desc = f"HTTP request smuggling {smug['findings'][0].get('technique','')} confirmed desync attack possible"
                    ModelTrainer._append_scan_sample('threat', desc, 'CRITICAL')
                    added += 1

                # 5. Subdomain Takeover
                tkover = result.get('takeover', {})
                if tkover and tkover.get('vulnerable'):
                    desc = f"Subdomain takeover {len(tkover['vulnerable'])} subdomains vulnerable dangling DNS"
                    ModelTrainer._append_scan_sample('threat', desc, 'CRITICAL')
                    added += 1

                # 6. CORS misconfig
                cors = result.get('cors', {})
                if cors and cors.get('findings'):
                    risk = risk_map.get(cors.get('risk_level', 'HIGH'), 'HIGH')
                    desc = f"CORS misconfiguration {cors['findings'][0].get('issue','')} cross-origin request forgery"
                    ModelTrainer._append_scan_sample('threat', desc, risk)
                    added += 1

                # 7. JS secrets
                js = result.get('js', {})
                if js and js.get('secrets'):
                    for s in js['secrets'][:2]:
                        desc = f"Secret exposed {s.get('type','')} in JavaScript file hardcoded credential"
                        ModelTrainer._append_scan_sample('threat', desc, 'HIGH')
                        added += 1

                # 8. Headers grade — agar D ya F hai toh LOW threat sample
                hdrs = result.get('headers', {})
                if hdrs and hdrs.get('grade') in ('D', 'F'):
                    missing = ', '.join(hdrs.get('missing', [])[:4])
                    desc = f"Security headers missing grade {hdrs.get('grade','')} {missing} misconfiguration"
                    ModelTrainer._append_scan_sample('threat', desc, 'MEDIUM')
                    added += 1

                # 9. Agar kuch bhi nahi mila toh bhi ek LOW sample save karo
                if added == 0:
                    desc = f"Bug bounty scan {result.get('target','')} SSL grade {result.get('ssl',{}).get('grade','?')} no critical vulnerabilities"
                    ModelTrainer._append_scan_sample('threat', desc, 'LOW')
                    added += 1

            elif scan_type == 'recon' and result.get('target'):
                # Recon — risk flags se threat samples banao
                risk_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH',
                            'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
                # WHOIS risk flags
                for rf in result.get('whois', {}).get('risk_flags', [])[:2]:
                    desc = f"{rf.get('flag','')} {rf.get('detail','')}"
                    risk = risk_map.get(rf.get('severity', 'LOW'), 'LOW')
                    if len(desc) >= 20:
                        ModelTrainer._append_scan_sample('threat', desc, risk)
                        added += 1
                # Cloud assets
                ca = result.get('cloud_assets', {})
                if ca and ca.get('total', 0) > 0:
                    desc = f"Cloud storage exposed {ca.get('total',0)} assets public buckets found"
                    ModelTrainer._append_scan_sample('threat', desc,
                        risk_map.get(ca.get('risk_level', 'MEDIUM'), 'MEDIUM'))
                    added += 1
                # GitHub secrets
                ghd = result.get('github_dorks', {})
                if ghd and ghd.get('total_secrets', 0) > 0:
                    desc = f"GitHub secrets leaked {ghd.get('total_secrets',0)} credentials exposed in code"
                    ModelTrainer._append_scan_sample('threat', desc,
                        risk_map.get(ghd.get('risk_level', 'HIGH'), 'HIGH'))
                    added += 1

        except Exception as e:
            logger.debug(f"scan_result_to_training_data error: {e}")

        if added > 0:
            ModelTrainer._update_counter(added)
            logger.debug(f"Continuous learning: +{added} samples from {scan_type} scan")

        return added

    @staticmethod
    def _append_scan_sample(data_type: str, text: str, label) -> None:
        """Single sample ko scan_feedback.jsonl mein append karo."""
        try:
            SCAN_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(SCAN_DATA_FILE, 'a') as f:
                f.write(json.dumps({
                    'type':      data_type,   # 'threat' or 'fake'
                    'text':      text[:2000],
                    'label':     label,
                    'source':    'real_scan',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                }) + '\n')
        except Exception as e:
            logger.debug(f"_append_scan_sample error: {e}")

    @staticmethod
    def _update_counter(added: int) -> bool:
        """
        Counter update karo. Agar threshold reach ho jaye toh True return karo
        (caller ko pata chale ki retrain karna chahiye).
        """
        try:
            counter = {'new_samples': 0}
            if COUNTER_FILE.exists():
                with open(COUNTER_FILE) as f:
                    counter = json.load(f)
            counter['new_samples'] = counter.get('new_samples', 0) + added
            with open(COUNTER_FILE, 'w') as f:
                json.dump(counter, f)
            return counter['new_samples'] >= AUTO_RETRAIN_THRESHOLD
        except Exception:
            return False

    @staticmethod
    def should_retrain() -> bool:
        """Check karo ki auto-retrain karna chahiye ya nahi."""
        try:
            if not COUNTER_FILE.exists():
                return False
            with open(COUNTER_FILE) as f:
                counter = json.load(f)
            return counter.get('new_samples', 0) >= AUTO_RETRAIN_THRESHOLD
        except Exception:
            return False

    def merge_scan_data(self) -> int:
        """
        scan_feedback.jsonl se data ko main training files mein merge karo.
        Retrain se pehle call karo.
        Returns: number of samples merged
        """
        if not SCAN_DATA_FILE.exists():
            return 0

        merged = 0
        threat_path = DATA_DIR / 'threat_raw.jsonl'
        fake_path   = DATA_DIR / 'fake_raw.jsonl'

        threat_lines = []
        fake_lines   = []
        with open(SCAN_DATA_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                    entry  = json.dumps({'text': sample['text'], 'label': sample['label'], 'url': 'real_scan'}) + '\n'
                    if sample['type'] == 'threat':
                        threat_lines.append(entry)
                        merged += 1
                    elif sample['type'] == 'fake':
                        fake_lines.append(entry)
                        merged += 1
                except Exception:
                    continue

        if threat_lines:
            with open(threat_path, 'a') as tf:
                tf.writelines(threat_lines)
        if fake_lines:
            with open(fake_path, 'a') as ff:
                ff.writelines(fake_lines)

        # Feedback file clear karo (already merged)
        SCAN_DATA_FILE.unlink(missing_ok=True)

        # Counter reset karo
        with open(COUNTER_FILE, 'w') as f:
            json.dump({'new_samples': 0}, f)

        logger.info(f"Scan data merged: {merged} samples added to training pool")
        return merged

    def auto_retrain_if_needed(self) -> bool:
        """
        Agar enough new scan data hai toh automatically retrain karo aur save karo.
        Returns: True agar retrain hua
        """
        if not self.should_retrain():
            return False
        if not _retrain_lock.acquire(blocking=False):
            logger.debug("Auto-retrain already running in another thread — skipping")
            return False
        try:
            logger.info(f"Auto-retrain triggered ({AUTO_RETRAIN_THRESHOLD}+ new samples)")
            merged = self.merge_scan_data()
            if merged == 0:
                return False
            self._load_raw_data()
            self._inject_synthetic_samples()
            self.train_all()
            report = self.evaluate()
            self.save_all()
            self._log_performance(report, trigger='auto_retrain', merged=merged)
            logger.info("Auto-retrain complete — models updated with real scan data")
            return True
        finally:
            _retrain_lock.release()

    @staticmethod
    def auto_retrain_background() -> None:
        """Background thread mein auto-retrain chalao — main thread block nahi hoga."""
        if not ModelTrainer.should_retrain():
            return
        def _run():
            try:
                trainer = ModelTrainer()
                trainer.auto_retrain_if_needed()
            except Exception as e:
                logger.debug(f"Background retrain error: {e}")
        t = threading.Thread(target=_run, daemon=True, name='sentinel-retrain')
        t.start()
        logger.debug("Background retrain thread started")

    @staticmethod
    def _log_performance(report: dict, trigger: str = 'manual', merged: int = 0) -> None:
        """Har retrain ke baad F1 score performance_log.jsonl mein save karo."""
        try:
            entry = {
                'timestamp':  time.strftime('%Y-%m-%d %H:%M:%S'),
                'trigger':    trigger,
                'merged':     merged,
                'metrics':    report,
            }
            with open(PERF_LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            logger.info(f"Performance logged: {report}")
        except Exception as e:
            logger.debug(f"Performance log error: {e}")

    @staticmethod
    def performance_history() -> list:
        """Performance log padhke return karo — drift detection ke liye."""
        if not PERF_LOG_FILE.exists():
            return []
        history = []
        with open(PERF_LOG_FILE) as f:
            for line in f:
                try:
                    history.append(json.loads(line))
                except Exception:
                    continue
        return history

    @staticmethod
    def detect_drift() -> dict:
        """
        Model drift detect karo — agar last 3 retrains mein F1 score gir raha hai
        toh drift warning return karo.
        """
        history = ModelTrainer.performance_history()
        if len(history) < 3:
            return {'drift_detected': False, 'reason': 'insufficient_history'}

        recent = history[-3:]
        threat_f1s = []
        fake_f1s   = []
        for entry in recent:
            m = entry.get('metrics', {})
            if 'threat_classifier' in m:
                threat_f1s.append(m['threat_classifier'].get('f1_weighted', 0))
            if 'fake_detector' in m:
                fake_f1s.append(m['fake_detector'].get('f1', 0))

        drift_flags = []
        if len(threat_f1s) >= 3:
            if threat_f1s[-1] < threat_f1s[0] - 0.10:  # 10% drop
                drift_flags.append({
                    'model': 'threat_classifier',
                    'f1_drop': round(threat_f1s[0] - threat_f1s[-1], 4),
                    'history': threat_f1s,
                })
        if len(fake_f1s) >= 3:
            if fake_f1s[-1] < fake_f1s[0] - 0.10:
                drift_flags.append({
                    'model': 'fake_detector',
                    'f1_drop': round(fake_f1s[0] - fake_f1s[-1], 4),
                    'history': fake_f1s,
                })

        return {
            'drift_detected': len(drift_flags) > 0,
            'flags':          drift_flags,
            'checked_at':     time.strftime('%Y-%m-%d %H:%M:%S'),
        }

    @staticmethod
    def pending_samples() -> int:
        """Kitne new scan samples pending hain retrain ke liye."""
        try:
            if not COUNTER_FILE.exists():
                return 0
            with open(COUNTER_FILE) as f:
                return json.load(f).get('new_samples', 0)
        except Exception:
            return 0

    # ── Save / Load ───────────────────────────────────────────────────────────

    def save_all(self) -> dict:
        """Trained models ko models/ml_engine/ mein save karo."""
        try:
            import joblib
        except ImportError:
            raise ImportError("joblib not installed. Run: pip install joblib")

        saved = {}

        if self.threat_clf:
            path = MODELS_DIR / 'threat_classifier.joblib'
            joblib.dump(self.threat_clf, path)
            saved['threat_classifier'] = str(path)
            logger.info(f"  Saved: {path}")

        if self.fake_clf:
            path = MODELS_DIR / 'fake_detector.joblib'
            joblib.dump(self.fake_clf, path)
            saved['fake_detector'] = str(path)
            logger.info(f"  Saved: {path}")

        # Metadata save karo
        meta = {
            'model_name':     'Sentinel Threat Intelligence Model',
            'version':        '1.0',
            'author':         'who_is_the_black_hat',
            'github':         'https://github.com/Mrsultan7890/osints',
            'license':        'MIT',
            'trained_at':     time.strftime('%Y-%m-%d %H:%M:%S'),
            'models':         list(saved.keys()),
            'threat_samples': len(self._threat_data),
            'fake_samples':   len(self._fake_data),
            'algorithms': {
                'threat_classifier':  'TF-IDF (5000 features, bigrams) + LogisticRegression (balanced)',
                'fake_detector':      'TF-IDF (3000 features, bigrams) + RandomForest (100 trees, balanced)',
            },
            'training_sources': [
                'bleepingcomputer.com', 'krebsonsecurity.com', 'mandiant.com',
                'portswigger.net', 'thedfirreport.com', 'securelist.com',
                'welivesecurity.com', 'darkreading.com', 'sans.org',
            ],
            'description': (
                'Cybersecurity threat classification model trained on curated '
                'security content using CRL (crawl-relevance-layers) data pipeline. '
                'Classifies text into threat levels: LOW/MEDIUM/HIGH/CRITICAL.'
            ),
        }
        with open(MODELS_DIR / 'metadata.json', 'w') as f:
            json.dump(meta, f, indent=2)

        logger.info(f"Models saved to {MODELS_DIR}")
        return saved

    def load_all(self) -> dict:
        """Saved models load karo."""
        try:
            import joblib
        except ImportError:
            raise ImportError("joblib not installed. Run: pip install joblib")

        loaded = {}

        threat_path = MODELS_DIR / 'threat_classifier.joblib'
        if threat_path.exists():
            self.threat_clf = joblib.load(threat_path)
            loaded['threat_classifier'] = True
            logger.info("ThreatClassifier loaded")

        fake_path = MODELS_DIR / 'fake_detector.joblib'
        if fake_path.exists():
            self.fake_clf = joblib.load(fake_path)
            loaded['fake_detector'] = True
            logger.info("FakeProfileDetector loaded")

        return loaded

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict_threat(self, text: str) -> dict:
        """
        Text ka threat level predict karo.
        Returns: {'label': 'HIGH', 'confidence': 0.87, 'probabilities': {...}}
        """
        if not self.threat_clf:
            # Try loading saved model
            try:
                self.load_all()
            except Exception:
                pass
        if not self.threat_clf:
            return {'label': 'UNKNOWN', 'confidence': 0.0, 'error': 'Model not trained'}

        pipeline, le = self.threat_clf
        proba = pipeline.predict_proba([text])[0]
        pred_idx = proba.argmax()
        label = le.inverse_transform([pred_idx])[0]

        return {
            'label':         label,
            'confidence':    round(float(proba[pred_idx]), 4),
            'probabilities': {
                cls: round(float(p), 4)
                for cls, p in zip(le.classes_, proba)
            },
        }

    def predict_fake(self, text: str) -> dict:
        """
        Profile text ka fake probability predict karo.
        Returns: {'is_fake': True, 'fake_probability': 0.82}
        """
        if not self.fake_clf:
            try:
                self.load_all()
            except Exception:
                pass
        if not self.fake_clf:
            return {'is_fake': False, 'fake_probability': 0.0, 'error': 'Model not trained'}

        proba = self.fake_clf.predict_proba([text])[0]
        fake_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        return {
            'is_fake':         fake_prob >= 0.5,
            'fake_probability': round(fake_prob, 4),
            'confidence':       round(max(proba), 4),
        }

    # ── Evaluation ────────────────────────────────────────────────────────────

    def train_neural(self) -> dict:
        """
        SentinelThreatNet train karo — custom BiLSTM neural network.
        Yeh poora tera apna model hai.
        """
        if not self._threat_data:
            self._load_raw_data()
            self._inject_synthetic_samples()

        texts  = [d['text']  for d in self._threat_data]
        labels = [d['label'] for d in self._threat_data]

        if len(texts) < 20:
            return {
                'error': f'Need 20+ samples, got {len(texts)}. Run train collect first.',
                'status': 'insufficient_data'
            }

        logger.info(f"Training SentinelThreatNet on {len(texts)} samples...")

        from modules.ml_engine.sentinel_net import NeuralTrainer
        import torch

        # CPU/GPU ke hisaab se hyperparams adjust karo
        gpu_available = torch.cuda.is_available()
        epochs     = min(20, max(8, len(texts) // 10))   # CPU pe kam epochs
        batch_size = min(32, len(texts) // 4) if gpu_available else min(64, len(texts) // 4)
        patience   = 3  # CPU pe jaldi early stop

        trainer = NeuralTrainer(
            embed_dim  = 64  if not gpu_available else 128,   # CPU pe smaller model
            hidden_dim = 128 if not gpu_available else 256,
            num_layers = 1   if not gpu_available else 2,     # 1 layer = 4x faster
            dropout    = 0.3,
            max_len    = 128 if not gpu_available else 256,   # shorter sequences
            batch_size = batch_size,
            lr         = 2e-3,
            epochs     = epochs,
            patience   = patience,
        )

        history = trainer.train(texts, labels)
        saved   = trainer.save()

        logger.info(f"SentinelThreatNet training complete:")
        logger.info(f"  Best F1  : {history['best_val_f1']:.4f}")
        logger.info(f"  Best Acc : {history['best_val_acc']:.2%}")
        logger.info(f"  Epochs   : {history['epochs_run']}")
        logger.info(f"  Size     : {saved['size_mb']} MB")

        # Store trainer for predict
        self._neural_trainer = trainer

        return {
            'status':       'trained',
            'samples':      len(texts),
            'best_f1':      history['best_val_f1'],
            'best_acc':     history['best_val_acc'],
            'epochs_run':   history['epochs_run'],
            'model_size_mb': saved['size_mb'],
            'model_path':   saved['model'],
            'author':       'who_is_the_black_hat',
        }

    def predict_neural(self, text: str) -> dict:
        """SentinelThreatNet se predict karo"""
        from modules.ml_engine.sentinel_net import NeuralTrainer
        if not hasattr(self, '_neural_trainer'):
            self._neural_trainer = NeuralTrainer()
        return self._neural_trainer.predict(text)

    def evaluate(self) -> dict:
        """Models ki accuracy report generate karo."""
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import LabelEncoder

        report = {}

        if self.threat_clf and len(self._threat_data) >= 6:
            pipeline, le = self.threat_clf
            texts  = [d['text']  for d in self._threat_data]
            labels = [d['label'] for d in self._threat_data]
            y = le.transform(labels)
            cv = max(2, min(5, len(texts) // 3))
            scores = cross_val_score(pipeline, texts, y, cv=cv, scoring='f1_weighted')
            report['threat_classifier'] = {
                'f1_weighted': round(float(scores.mean()), 4),
                'std':         round(float(scores.std()), 4),
                'samples':     len(texts),
                'classes':     list(le.classes_),
            }
            logger.info(f"ThreatClassifier F1: {scores.mean():.3f} ± {scores.std():.3f}")

        if self.fake_clf and len(self._fake_data) >= 6:
            texts  = [d['text']  for d in self._fake_data]
            labels = [d['label'] for d in self._fake_data]
            y = np.array(labels, dtype=int)
            cv = max(2, min(5, len(texts) // 3))
            scores = cross_val_score(self.fake_clf, texts, y, cv=cv, scoring='f1')
            report['fake_detector'] = {
                'f1':      round(float(scores.mean()), 4),
                'std':     round(float(scores.std()), 4),
                'samples': len(texts),
            }
            logger.info(f"FakeDetector F1: {scores.mean():.3f} ± {scores.std():.3f}")

        return report

    def collect_github_data(self, token: str = None, max_repos: int = 50) -> dict:
        """
        GitHub se security training data collect karo.
        Sources:
          - Security advisories (GHSA) — labeled CRITICAL/HIGH/MEDIUM/LOW
          - CVE descriptions from GitHub Security Advisory Database
          - Awesome-lists: awesome-malware-analysis, awesome-osint, etc.
          - Real vulnerability writeups from security repos
        """
        import requests
        import re as _re

        threat_path = DATA_DIR / 'threat_raw.jsonl'
        existing_urls = set()
        if threat_path.exists():
            with open(threat_path) as f:
                for line in f:
                    try: existing_urls.add(json.loads(line).get('url', ''))
                    except: pass

        headers = {'Accept': 'application/vnd.github+json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        elif hasattr(__import__('config', fromlist=['']), 'GITHUB_TOKEN') and __import__('config', fromlist=['']).GITHUB_TOKEN:
            headers['Authorization'] = f"Bearer {__import__('config', fromlist=['']).GITHUB_TOKEN}"

        added = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}

        # ── 1. GitHub Security Advisories (GHSA) ─────────────────────────────
        logger.info("GitHub Security Advisories (GHSA) se data collect kar raha hoon...")
        severity_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MODERATE': 'MEDIUM', 'LOW': 'LOW'}
        try:
            for severity, label in severity_map.items():
                page = 1
                while page <= 5:  # max 5 pages per severity
                    r = requests.get(
                        'https://api.github.com/advisories',
                        params={'severity': severity.lower(), 'per_page': 100, 'page': page},
                        headers=headers, timeout=15
                    )
                    if r.status_code != 200:
                        break
                    advisories = r.json()
                    if not advisories:
                        break
                    with open(threat_path, 'a') as f:
                        for adv in advisories:
                            ghsa_id = adv.get('ghsa_id', '')
                            url = f"ghsa_{ghsa_id}"
                            if url in existing_urls:
                                continue
                            summary = adv.get('summary', '')
                            desc    = adv.get('description', '') or ''
                            text    = f"{summary}. {desc}"[:2000].strip()
                            if len(text) < 30:
                                continue
                            # Clean markdown
                            text = _re.sub(r'```[\s\S]*?```', '', text)
                            text = _re.sub(r'[#*`>]', '', text).strip()
                            if len(text) >= 30:
                                f.write(json.dumps({
                                    'text': text, 'label': label,
                                    'url': url, 'source': 'github_ghsa'
                                }) + '\n')
                                existing_urls.add(url)
                                added[label.lower()] += 1
                                added['total'] += 1
                    page += 1
                    time.sleep(0.5)
            logger.info(f"  GHSA: +{added['total']} advisories")
        except Exception as e:
            logger.warning(f"GHSA collection failed: {e}")

        # ── 2. GitHub Code Search — security writeups ─────────────────────────
        logger.info("GitHub code search se security writeups collect kar raha hoon...")
        search_queries = [
            ('vulnerability writeup exploit proof of concept', 'HIGH'),
            ('malware analysis reverse engineering sample', 'CRITICAL'),
            ('penetration testing report findings', 'MEDIUM'),
            ('CVE exploit PoC remote code execution', 'CRITICAL'),
            ('bug bounty writeup XSS SQLi SSRF', 'HIGH'),
            ('security audit report misconfiguration', 'MEDIUM'),
            ('osint investigation methodology', 'LOW'),
            ('phishing campaign analysis indicators', 'HIGH'),
        ]
        repo_count = 0
        try:
            for query, label in search_queries:
                if repo_count >= max_repos:
                    break
                r = requests.get(
                    'https://api.github.com/search/repositories',
                    params={'q': query + ' language:markdown', 'sort': 'stars',
                            'per_page': 10, 'page': 1},
                    headers=headers, timeout=15
                )
                if r.status_code != 200:
                    time.sleep(2)
                    continue
                repos = r.json().get('items', [])
                for repo in repos[:5]:
                    if repo_count >= max_repos:
                        break
                    repo_url = repo.get('html_url', '')
                    url_key  = f"gh_repo_{repo.get('id', '')}"
                    if url_key in existing_urls:
                        continue
                    # README fetch karo
                    readme_url = f"https://raw.githubusercontent.com/{repo['full_name']}/HEAD/README.md"
                    try:
                        rr = requests.get(readme_url, timeout=10)
                        if rr.status_code == 200 and len(rr.text) >= 100:
                            text = rr.text[:2000]
                            # Clean markdown
                            text = _re.sub(r'```[\s\S]*?```', '', text)
                            text = _re.sub(r'[#*`>\[\]()]', '', text)
                            text = _re.sub(r'https?://\S+', '', text).strip()
                            text = ' '.join(text.split())[:2000]
                            if len(text) >= 50:
                                with open(threat_path, 'a') as f:
                                    f.write(json.dumps({
                                        'text': text, 'label': label,
                                        'url': url_key, 'source': 'github_readme'
                                    }) + '\n')
                                existing_urls.add(url_key)
                                added[label.lower()] += 1
                                added['total'] += 1
                                repo_count += 1
                    except Exception:
                        pass
                    time.sleep(0.3)
                time.sleep(1)  # search rate limit
            logger.info(f"  GitHub repos: +{repo_count} READMEs")
        except Exception as e:
            logger.warning(f"GitHub search failed: {e}")

        # ── 3. Awesome Security Lists — curated content ───────────────────────
        logger.info("Awesome security lists se data collect kar raha hoon...")
        awesome_lists = [
            ('Hack-with-Github/Awesome-Hacking', 'HIGH'),
            ('rmusser01/Awesome-Threat-Intelligence', 'CRITICAL'),
            ('hslatman/awesome-threat-intelligence', 'CRITICAL'),
            ('enaqx/awesome-pentest', 'HIGH'),
            ('jivoi/awesome-osint', 'LOW'),
            ('0x4D31/awesome-oscp', 'MEDIUM'),
        ]
        try:
            for repo_path, label in awesome_lists:
                url_key = f"awesome_{repo_path.replace('/', '_')}"
                if url_key in existing_urls:
                    continue
                readme_url = f"https://raw.githubusercontent.com/{repo_path}/HEAD/README.md"
                try:
                    r = requests.get(readme_url, timeout=15)
                    if r.status_code == 200 and len(r.text) >= 200:
                        # Split into chunks — har section ek sample
                        sections = _re.split(r'\n#{1,3} ', r.text)
                        for section in sections[:20]:
                            text = _re.sub(r'```[\s\S]*?```', '', section)
                            text = _re.sub(r'[#*`>\[\]()]', '', text)
                            text = _re.sub(r'https?://\S+', '', text).strip()
                            text = ' '.join(text.split())[:1000]
                            if len(text) >= 50:
                                sec_key = f"{url_key}_{hash(text[:50]) % 10000}"
                                if sec_key not in existing_urls:
                                    with open(threat_path, 'a') as f:
                                        f.write(json.dumps({
                                            'text': text, 'label': label,
                                            'url': sec_key, 'source': 'github_awesome'
                                        }) + '\n')
                                    existing_urls.add(sec_key)
                                    added[label.lower()] += 1
                                    added['total'] += 1
                    time.sleep(0.5)
                except Exception:
                    pass
            logger.info(f"  Awesome lists: processed {len(awesome_lists)} repos")
        except Exception as e:
            logger.warning(f"Awesome lists failed: {e}")

        self._load_raw_data()
        self._inject_synthetic_samples()

        logger.info(f"GitHub data collection complete: +{added['total']} total samples")
        logger.info(f"  CRITICAL: {added['critical']} | HIGH: {added['high']} | MEDIUM: {added['medium']} | LOW: {added['low']}")
        return {
            'github_ghsa':    added['critical'] + added['high'],
            'github_repos':   repo_count,
            'total_added':    added['total'],
            'breakdown':      added,
            'total_threat':   len(self._threat_data),
        }

    @staticmethod
    def status() -> dict:
        """Saved models ka status check karo."""
        meta_path = MODELS_DIR / 'metadata.json'
        result = {}
        if meta_path.exists():
            with open(meta_path) as f:
                result = json.load(f)
        else:
            result = {
                'status':  'no_models_trained',
                'message': "Run: trainer.collect_data() then trainer.train_all() then trainer.save_all()",
            }
        # Drift status bhi add karo
        drift = ModelTrainer.detect_drift()
        result['drift'] = drift
        result['pending_samples'] = ModelTrainer.pending_samples()
        return result
