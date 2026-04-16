#!/usr/bin/env python3
"""
Train SentinelNet v4.0 + ThreatClassifier on all available data
Usage: python3 train_model.py
Author: @who_is_the_black_hat
"""

import json
import logging
import sys
from pathlib import Path
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

sys.path.insert(0, '/home/kali/osints')

DATA_DIR   = Path('/home/kali/osints/models/ml_engine/training_data')
MODELS_DIR = Path('/home/kali/osints/models/ml_engine')

LABEL_MAP = {
    'CRITICAL': 'CRITICAL', 'critical': 'CRITICAL',
    'HIGH':     'HIGH',     'high':     'HIGH',
    'MEDIUM':   'MEDIUM',   'medium':   'MEDIUM', 'MODERATE': 'MEDIUM',
    'LOW':      'LOW',      'low':      'LOW',
}

# ── Load all data ─────────────────────────────────────────────────────────────

def load_all_data(max_samples=80000):
    """Sab JSONL files se data load karo, normalize karo"""
    samples = []
    seen    = set()

    # Priority order — best quality first
    files = [
        'threat_master_balanced.jsonl',  # 160K balanced
        'linux_kali_dataset.jsonl',       # 10K kali/linux focused
        'github_threat_data.jsonl',       # 4.6K github
        'threat_v4_clean.jsonl',          # 11.6K clean
        'code_threat_data.jsonl',         # 652 code
        'threat_raw.jsonl',               # raw
    ]

    for fname in files:
        fpath = DATA_DIR / fname
        if not fpath.exists():
            continue
        count = 0
        with open(fpath, encoding='utf-8', errors='replace') as f:
            for line in f:
                if len(samples) >= max_samples:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    text  = str(d.get('text') or d.get('content') or '').strip()
                    label = LABEL_MAP.get(str(d.get('label', '')).upper(), '')
                    if not text or not label or len(text) < 20:
                        continue
                    key = text[:80]
                    if key in seen:
                        continue
                    seen.add(key)
                    samples.append({'text': text[:1500], 'label': label})
                    count += 1
                except Exception:
                    continue
        log.info(f"  {fname}: +{count} samples")
        if len(samples) >= max_samples:
            break

    return samples


def balance_data(samples, max_per_class=15000):
    """Classes balance karo"""
    from collections import defaultdict
    import random
    buckets = defaultdict(list)
    for s in samples:
        buckets[s['label']].append(s)

    log.info("Class distribution before balance:")
    for label, items in sorted(buckets.items()):
        log.info(f"  {label}: {len(items)}")

    balanced = []
    for label, items in buckets.items():
        random.shuffle(items)
        balanced.extend(items[:max_per_class])

    random.shuffle(balanced)
    log.info(f"Total after balance: {len(balanced)}")
    return balanced


# ── Train ThreatClassifier (sklearn) ─────────────────────────────────────────

def train_sklearn(samples):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from sklearn.preprocessing import LabelEncoder
    import numpy as np
    import joblib

    log.info(f"\nTraining ThreatClassifier on {len(samples)} samples...")

    texts  = [s['text']  for s in samples]
    labels = [s['label'] for s in samples]

    le = LabelEncoder()
    le.fit(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    y = le.transform(labels)

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=8000,
            ngram_range=(1, 2),
            sublinear_tf=True,
            stop_words='english',
            min_df=2,
        )),
        ('clf', LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            C=1.0,
            solver='lbfgs',
            multi_class='multinomial',
        )),
    ])

    # Cross validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(pipeline, texts, y, cv=cv, scoring='f1_weighted', n_jobs=-1)
    log.info(f"ThreatClassifier CV F1: {scores.mean():.4f} ± {scores.std():.4f}")

    pipeline.fit(texts, y)

    # Save
    path = MODELS_DIR / 'threat_classifier.joblib'
    joblib.dump((pipeline, le), path)
    log.info(f"Saved: {path}")

    return scores.mean()


# ── Train SentinelNet (neural) ────────────────────────────────────────────────

def train_neural(samples):
    from modules.ml_engine.sentinel_net import NeuralTrainer
    import torch

    gpu = torch.cuda.is_available()
    log.info(f"\nTraining SentinelNet v4.0 on {len(samples)} samples (GPU: {gpu})...")

    trainer = NeuralTrainer(
        embed_dim   = 128,
        num_filters = 128,
        tf_layers   = 2,
        dropout     = 0.3,
        max_len     = 200,
        batch_size  = 128 if gpu else 64,
        lr          = 1e-3,
        epochs      = 30 if gpu else 15,
        patience    = 5,
    )

    history = trainer.train(samples)
    saved   = trainer.save()

    log.info(f"SentinelNet best F1  : {history['best_f1']:.4f}")
    log.info(f"SentinelNet epochs   : {history['epochs_run']}")
    log.info(f"Model saved          : {saved['model']}")

    return history['best_f1']


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("=== Sentinel Model Training ===\n")

    # 1. Load data
    log.info("Loading data...")
    samples = load_all_data(max_samples=80000)
    log.info(f"Total loaded: {len(samples)}")

    if len(samples) < 100:
        log.error("Bahut kam data hai. Pipeline pehle chalao.")
        sys.exit(1)

    # 2. Balance
    samples = balance_data(samples, max_per_class=15000)

    # 3. Train sklearn ThreatClassifier
    try:
        f1_sklearn = train_sklearn(samples)
        log.info(f"ThreatClassifier F1: {f1_sklearn:.4f}")
    except Exception as e:
        log.error(f"ThreatClassifier failed: {e}")

    # 4. Train SentinelNet neural
    try:
        f1_neural = train_neural(samples)
        log.info(f"SentinelNet F1: {f1_neural:.4f}")
    except Exception as e:
        log.error(f"SentinelNet failed: {e}")
        import traceback
        traceback.print_exc()

    log.info("\n=== Training Complete ===")
    log.info(f"Models saved to: {MODELS_DIR}")


if __name__ == '__main__':
    main()
