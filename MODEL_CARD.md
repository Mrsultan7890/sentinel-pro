# Sentinel Threat Intelligence Model

```
Author  : @who_is_the_black_hat
GitHub  : https://github.com/Mrsultan7890/osints
License : MIT
Version : 1.0
```

---

## Models

### 1. ThreatClassifier
- **Task:** Text classification → threat level prediction
- **Labels:** `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- **Algorithm:** TF-IDF (5000 features, 1-2 ngrams) + LogisticRegression (balanced)
- **Use case:** Classify OSINT text, breach summaries, NLP profiles by threat level

### 2. FakeProfileDetector
- **Task:** Binary classification → fake/real account detection
- **Labels:** `0` (real) / `1` (fake)
- **Algorithm:** TF-IDF (3000 features, 1-2 ngrams) + RandomForest (100 trees, balanced)
- **Use case:** Detect bot accounts, spam profiles, coordinated inauthentic behavior

---

## Training Data

Data collected using **CRL (crawl-relevance-layers)** — a custom async web crawling
library with BM25 + semantic relevance ranking.

### Trusted Sources (Threat Data)
| Label | Sources |
|-------|---------|
| CRITICAL | bleepingcomputer.com, krebsonsecurity.com, mandiant.com, thedfirreport.com |
| HIGH | portswigger.net, proofpoint.com, group-ib.com, darkreading.com |
| MEDIUM | owasp.org, hackerone.com, rhinosecuritylabs.com, sans.org |
| LOW | sans.org, securityweek.com, csoonline.com, infosecurity-magazine.com |

### Quality Filters
- Blocked domains: wikipedia.org, support.google.com, generic sites
- Keyword validation: each sample must contain label-relevant security keywords
- Min text length: 150 characters
- Duplicate URL detection: same URL never added twice

---

## Continuous Learning

Every real scan in Sentinel Pro automatically feeds labeled data back:

```
Real scan (nlp/fakecheck/breach/person)
    ↓
scan_result_to_training_data()  ← PII stripped
    ↓
scan_feedback.jsonl
    ↓
Every 50 new samples → auto-retrain
    ↓
Better accuracy on next scan
```

---

## Performance

| Model | F1 Score | Samples | Notes |
|-------|----------|---------|-------|
| ThreatClassifier | ~0.75+ | 50+ | Improves with more data |
| FakeDetector | ~0.78+ | 50+ | Synthetic samples included |

*Scores improve significantly with 200+ samples per class.*

---

## Files

```
models/ml_engine/
  threat_classifier.joblib   ← ThreatClassifier (TF-IDF + LR)
  fake_detector.joblib       ← FakeDetector (TF-IDF + RF)
  metadata.json              ← Training metadata + author info
  training_data/
    threat_raw.jsonl         ← Labeled threat training data
    fake_raw.jsonl           ← Labeled fake/real profile data
    scan_feedback.jsonl      ← Real scan feedback (auto-generated)
```

---

## Usage

```python
from modules.ml_engine.trainer import ModelTrainer

trainer = ModelTrainer()
trainer.load_all()

# Threat prediction
result = trainer.predict_threat("ransomware attack encrypted files bitcoin ransom")
print(result)
# {'label': 'CRITICAL', 'confidence': 0.89, 'probabilities': {...}}

# Fake profile detection
result = trainer.predict_fake("Follow me for crypto tips! 100x gains! DM for signals!")
print(result)
# {'is_fake': True, 'fake_probability': 0.82}
```

---

## Train Your Own

```bash
# In Sentinel Pro interactive mode:
sentinel-pro> train collect    # CRL se data crawl karo (~10-15 min)
sentinel-pro> train run        # Models train karo
sentinel-pro> train save       # Save karo
sentinel-pro> train eval       # Accuracy check karo
```

---

## Citation

If you use this model in your research or tools:

```
Sentinel Threat Intelligence Model (2026)
Author: @who_is_the_black_hat
Source: https://github.com/Mrsultan7890/osints
```

---

## License

MIT License — free to use, modify, and distribute with attribution.
