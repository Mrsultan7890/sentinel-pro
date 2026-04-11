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
import logging
import os
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
SCAN_DATA_FILE  = DATA_DIR / 'scan_feedback.jsonl'   # real scan se aaya data
COUNTER_FILE    = DATA_DIR / 'new_samples_counter.json'


# ── Training Queries ──────────────────────────────────────────────────────────
# CRL in queries se data crawl karega

# ── Trusted security sites — direct URL crawl (no DDG needed) ────────────────
# CRL ka deep_search in sites ke articles crawl karega
# Yeh approach DDG se zyada reliable hai — relevant content guaranteed

THREAT_SEED_URLS = {
    'CRITICAL': [
        'https://www.bleepingcomputer.com/news/security/',
        'https://krebsonsecurity.com/',
        'https://securelist.com/category/apt-reports/',
        'https://www.mandiant.com/resources/blog',
        'https://thedfirreport.com/',
        'https://any.run/malware-trends/',
        'https://www.welivesecurity.com/category/malware/',
    ],
    'HIGH': [
        'https://portswigger.net/research',
        'https://www.hackerone.com/vulnerability-and-security-testing-blog',
        'https://www.proofpoint.com/us/blog/threat-insight',
        'https://www.darkreading.com/threat-intelligence',
        'https://threatpost.com/',
        'https://www.group-ib.com/blog/',
    ],
    'MEDIUM': [
        'https://owasp.org/www-project-top-ten/',
        'https://portswigger.net/web-security',
        'https://www.hackerone.com/blog',
        'https://rhinosecuritylabs.com/blog/',
        'https://www.sans.org/blog/',
        'https://attack.mitre.org/techniques/',
    ],
    'LOW': [
        'https://www.sans.org/security-awareness-training/',
        'https://www.darkreading.com/cybersecurity-operations',
        'https://www.securityweek.com/',
        'https://www.csoonline.com/category/security/',
        'https://www.infosecurity-magazine.com/',
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

        # Synthetic fake samples add karo
        existing_fake = {d['text'][:50] for d in self._fake_data}
        new_fake = 0
        with open(fake_path, 'a') as f:
            for text in SYNTHETIC_FAKE:
                if text[:50] not in existing_fake:
                    f.write(json.dumps({'text': text, 'label': 1, 'url': 'synthetic'}) + '\n')
                    self._fake_data.append({'text': text, 'label': 1})
                    new_fake += 1

        # Synthetic real samples add karo
        for text in SYNTHETIC_REAL:
            if text[:50] not in existing_fake:
                with open(fake_path, 'a') as f:
                    f.write(json.dumps({'text': text, 'label': 0, 'url': 'synthetic'}) + '\n')
                self._fake_data.append({'text': text, 'label': 0})
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
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import LabelEncoder

        logger.info("ThreatClassifier training shuru...")

        texts  = [d['text']  for d in self._threat_data]
        labels = [d['label'] for d in self._threat_data]

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
                class_weight='balanced',  # imbalanced classes handle karo
                C=1.0,
                solver='lbfgs',
            )),
        ])

        # Cross-validation
        if len(texts) >= 20:
            cv_scores = cross_val_score(pipeline, texts, y, cv=5, scoring='f1_weighted')
            logger.info(f"  CV F1 score: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
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
        IdentityLinker — rule-based + learned thresholds.
        Abhi ke liye threshold calibration karta hai existing EntityMatcher pe.
        Full supervised training ke liye labeled profile pairs chahiye.
        """
        logger.info("IdentityLinker: threshold calibration (labeled pairs needed for full training)")
        # Placeholder — jab labeled same-person pairs milein tab full training
        return {'status': 'threshold_calibrated', 'note': 'Add labeled pairs via add_identity_pair()'}

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
                # Person OSINT — sirf behavioral patterns save karo, PII nahi
                # Real names, bios, display names SAVE NAHI hote
                risk = result.get('risk_level', 'LOW')
                # Sirf risk flags aur platform count se derived text
                flags = result.get('risk_flags', [])
                platform_count = len(result.get('social_profiles', []))
                if flags or platform_count > 0:
                    # Generic behavioral description — no PII
                    desc = f"Found on {platform_count} platforms. " + \
                           ' '.join(f.get('detail', '') for f in flags[:2])
                    if len(desc) >= 20:
                        ModelTrainer._append_scan_sample('threat', desc, risk)
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

        with open(SCAN_DATA_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                    if sample['type'] == 'threat':
                        with open(threat_path, 'a') as tf:
                            tf.write(json.dumps({
                                'text':  sample['text'],
                                'label': sample['label'],
                                'url':   'real_scan',
                            }) + '\n')
                        merged += 1
                    elif sample['type'] == 'fake':
                        with open(fake_path, 'a') as ff:
                            ff.write(json.dumps({
                                'text':  sample['text'],
                                'label': sample['label'],
                                'url':   'real_scan',
                            }) + '\n')
                        merged += 1
                except Exception:
                    continue

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
        Main loop mein call karo har scan ke baad.
        Returns: True agar retrain hua
        """
        if not self.should_retrain():
            return False

        logger.info(f"Auto-retrain triggered ({AUTO_RETRAIN_THRESHOLD}+ new samples)")
        merged = self.merge_scan_data()
        if merged == 0:
            return False

        self._load_raw_data()
        self._inject_synthetic_samples()
        self.train_all()
        self.save_all()
        logger.info("Auto-retrain complete — models updated with real scan data")
        return True

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
            'version':    '1.0',
            'trained_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'models':     list(saved.keys()),
            'threat_samples': len(self._threat_data),
            'fake_samples':   len(self._fake_data),
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

    def evaluate(self) -> dict:
        """Models ki accuracy report generate karo."""
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import LabelEncoder

        report = {}

        if self.threat_clf and len(self._threat_data) >= 10:
            pipeline, le = self.threat_clf
            texts  = [d['text']  for d in self._threat_data]
            labels = [d['label'] for d in self._threat_data]
            y = le.transform(labels)
            scores = cross_val_score(pipeline, texts, y, cv=min(5, len(texts)//3), scoring='f1_weighted')
            report['threat_classifier'] = {
                'f1_weighted': round(float(scores.mean()), 4),
                'std':         round(float(scores.std()), 4),
                'samples':     len(texts),
                'classes':     list(le.classes_),
            }
            logger.info(f"ThreatClassifier F1: {scores.mean():.3f} ± {scores.std():.3f}")

        if self.fake_clf and len(self._fake_data) >= 10:
            texts  = [d['text']  for d in self._fake_data]
            labels = [d['label'] for d in self._fake_data]
            y = np.array(labels, dtype=int)
            scores = cross_val_score(self.fake_clf, texts, y, cv=min(5, len(texts)//3), scoring='f1')
            report['fake_detector'] = {
                'f1':      round(float(scores.mean()), 4),
                'std':     round(float(scores.std()), 4),
                'samples': len(texts),
            }
            logger.info(f"FakeDetector F1: {scores.mean():.3f} ± {scores.std():.3f}")

        return report

    @staticmethod
    def status() -> dict:
        """Saved models ka status check karo."""
        meta_path = MODELS_DIR / 'metadata.json'
        if meta_path.exists():
            with open(meta_path) as f:
                return json.load(f)
        return {
            'status':  'no_models_trained',
            'message': "Run: trainer.collect_data() then trainer.train_all() then trainer.save_all()",
        }
