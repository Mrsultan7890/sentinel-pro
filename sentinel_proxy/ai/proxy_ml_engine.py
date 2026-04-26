"""
ProxyMLEngine — Sentinel Proxy ke liye unified ML analysis engine
=================================================================
Wires existing algorithms + adds NEW proxy-specific models:
  1. SentinelNet       — HTTP request threat classification
  2. IsolationForest   — HTTP anomaly detection (timing, size, status)
  3. DBSCAN            — Session-based attack request clustering
  4. LightGBM          — HTTP log pattern analysis
  5. TF-IDF Payload    — Payload fingerprinting against payloads/*.txt
  6. LSTM Chain        — Request sequence pattern detection (brute/recon/IDOR)
  7. Random Forest WAF — WAF bypass probability detection
  8. Autoencoder       — Response anomaly (data leakage, stack traces)
  9. Markov Chain      — Attack path prediction
  10. Online SGD       — User-flagged request immediate learning
"""

import hashlib
import json
import logging
import math
import os
import re
import sys
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

# Paths
_PROXY_DIR   = Path(__file__).resolve().parents[1]
_PAYLOAD_DIR = _PROXY_DIR / 'payloads'
_MODELS_DIR  = Path(__file__).resolve().parents[3] / 'models' / 'ml_engine'
_PROXY_MODELS_DIR = _PROXY_DIR / 'models'
_PROXY_MODELS_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

# Risk ordering
_RISK_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

def _max_risk(*risks):
    return max(risks, key=lambda r: _RISK_ORDER.get(r, 0))


# ── 1. TF-IDF Payload Fingerprinter ──────────────────────────────────────────

class PayloadFingerprinter:
    """
    Payloads/*.txt se TF-IDF corpus banao.
    Incoming request body/params ko compare karo — similarity + matched type return karo.
    """

    def __init__(self):
        self._vectorizer  = None
        self._matrix      = None
        self._labels      = []   # payload type per row
        self._payloads    = []   # raw payload text per row
        self._lock        = threading.Lock()
        self._loaded      = False

    def load(self):
        """Payload files load karo aur TF-IDF fit karo — lazy, ek baar."""
        with self._lock:
            if self._loaded:
                return
            self._build()
            self._loaded = True

    def _build(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        corpus, labels = [], []
        for txt_file in sorted(_PAYLOAD_DIR.glob('*.txt')):
            ptype = txt_file.stem
            try:
                lines = [l.strip() for l in txt_file.read_text(errors='ignore').splitlines()
                         if l.strip() and not l.startswith('#')]
            except Exception:
                continue
            for line in lines:
                corpus.append(line)
                labels.append(ptype)

        if not corpus:
            logger.warning('[PayloadFingerprinter] No payload files found')
            return

        self._vectorizer = TfidfVectorizer(
            analyzer='char_wb', ngram_range=(2, 4),
            max_features=8000, sublinear_tf=True,
        )
        self._matrix  = self._vectorizer.fit_transform(corpus)
        self._labels  = labels
        self._payloads = corpus
        logger.info(f'[PayloadFingerprinter] Loaded {len(corpus)} payloads from {len(set(labels))} types')

    def match(self, text: str) -> dict:
        """
        text ko payload corpus se compare karo.
        Returns: {type, similarity, matched_payload}
        """
        if not text or not text.strip():
            return {'type': None, 'similarity': 0.0, 'matched_payload': ''}

        if not self._loaded:
            self.load()
        if self._vectorizer is None:
            return {'type': None, 'similarity': 0.0, 'matched_payload': ''}

        try:
            from sklearn.metrics.pairwise import cosine_similarity
            vec = self._vectorizer.transform([text[:500]])
            sims = cosine_similarity(vec, self._matrix)[0]
            best_idx = int(np.argmax(sims))
            best_sim = float(sims[best_idx])
            if best_sim < 0.05:
                return {'type': None, 'similarity': round(best_sim, 4), 'matched_payload': ''}
            return {
                'type':            self._labels[best_idx],
                'similarity':      round(best_sim, 4),
                'matched_payload': self._payloads[best_idx][:100],
            }
        except Exception as e:
            logger.debug(f'[PayloadFingerprinter] match error: {e}')
            return {'type': None, 'similarity': 0.0, 'matched_payload': ''}


# ── 2. LSTM Request Chain Analyzer ───────────────────────────────────────────

class LSTMChainAnalyzer:
    """
    Session ke last N requests ka sequence analyze karo.
    Detects: brute_force, recon, idor_enum, normal
    State vector: [method_enc, path_hash_norm, status_norm, resp_len_norm, timing_norm]
    Lazy PyTorch LSTM — agar torch nahi hai toh heuristic fallback.
    """

    SEQ_LEN    = 10
    INPUT_DIM  = 5
    HIDDEN_DIM = 32
    MODEL_PATH = _PROXY_MODELS_DIR / 'lstm_chain.pt'

    # Session request history: session_id → deque of feature vectors
    _sessions: dict = defaultdict(lambda: deque(maxlen=LSTMChainAnalyzer.SEQ_LEN
                                                  if hasattr(LSTMChainAnalyzer, 'SEQ_LEN')
                                                  else 10))

    _METHOD_MAP = {'GET': 0.2, 'POST': 0.4, 'PUT': 0.6, 'DELETE': 0.8, 'PATCH': 0.5,
                   'OPTIONS': 0.1, 'HEAD': 0.15}

    def __init__(self):
        self._model  = None
        self._device = None
        self._lock   = threading.Lock()
        self._loaded = False

    def _load_model(self):
        """Lazy load LSTM model — agar saved hai toh load karo, warna skip."""
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                import torch
                import torch.nn as nn
                self._device = torch.device('cpu')

                class _LSTM(nn.Module):
                    def __init__(self):
                        super().__init__()
                        self.lstm = nn.LSTM(LSTMChainAnalyzer.INPUT_DIM,
                                            LSTMChainAnalyzer.HIDDEN_DIM,
                                            batch_first=True)
                        self.fc   = nn.Linear(LSTMChainAnalyzer.HIDDEN_DIM, 4)  # 4 patterns

                    def forward(self, x):
                        out, _ = self.lstm(x)
                        return self.fc(out[:, -1, :])

                if self.MODEL_PATH.exists():
                    m = _LSTM()
                    m.load_state_dict(torch.load(self.MODEL_PATH, map_location='cpu',
                                                  weights_only=True))
                    m.eval()
                    self._model = m
                    logger.info('[LSTMChain] Model loaded')
            except Exception as e:
                logger.debug(f'[LSTMChain] load skipped: {e}')
            self._loaded = True

    def _flow_to_vec(self, flow: dict) -> list:
        method     = self._METHOD_MAP.get(flow.get('method', 'GET'), 0.2)
        path       = flow.get('path', '/')
        path_hash  = (int(hashlib.md5(path.encode()).hexdigest(), 16) % 1000) / 1000.0
        status     = min(flow.get('status_code', 200), 599) / 599.0
        resp_len   = min(flow.get('resp_length', 0), 100000) / 100000.0
        timing     = min(flow.get('timing', 0.0), 10.0) / 10.0
        return [method, path_hash, status, resp_len, timing]

    def add_request(self, session_id: str, flow: dict):
        """Session mein request add karo."""
        vec = self._flow_to_vec(flow)
        LSTMChainAnalyzer._sessions[session_id].append(vec)

    def analyze_session(self, session_id: str) -> dict:
        """
        Session ka pattern detect karo.
        Returns: {pattern, confidence, request_count}
        """
        history = list(LSTMChainAnalyzer._sessions.get(session_id, []))
        if len(history) < 3:
            return {'pattern': 'normal', 'confidence': 0.5, 'request_count': len(history)}

        self._load_model()

        # LSTM inference agar model available hai
        if self._model is not None:
            try:
                import torch
                seq = history[-self.SEQ_LEN:]
                # Pad agar kam requests hain
                while len(seq) < self.SEQ_LEN:
                    seq.insert(0, [0.0] * self.INPUT_DIM)
                x = torch.tensor([seq], dtype=torch.float32)
                with torch.no_grad():
                    logits = self._model(x)[0]
                    probs  = torch.softmax(logits, dim=-1).tolist()
                patterns = ['normal', 'brute_force', 'recon', 'idor_enum']
                best_idx = int(np.argmax(probs))
                return {
                    'pattern':       patterns[best_idx],
                    'confidence':    round(probs[best_idx], 4),
                    'request_count': len(history),
                    'source':        'lstm',
                }
            except Exception as e:
                logger.debug(f'[LSTMChain] inference error: {e}')

        # Heuristic fallback
        return self._heuristic_pattern(history)

    def _heuristic_pattern(self, history: list) -> dict:
        """Rule-based pattern detection — LSTM fallback."""
        n = len(history)
        # Brute force: bahut saari requests, similar path hash, POST
        methods   = [v[0] for v in history]
        path_hashes = [v[1] for v in history]
        statuses  = [v[2] for v in history]

        post_ratio  = methods.count(0.4) / n  # POST = 0.4
        path_unique = len(set(round(p, 2) for p in path_hashes)) / n
        error_ratio = sum(1 for s in statuses if s > (400/599)) / n

        if post_ratio > 0.7 and path_unique < 0.3:
            return {'pattern': 'brute_force', 'confidence': 0.75, 'request_count': n, 'source': 'heuristic'}
        if path_unique > 0.8 and error_ratio > 0.3:
            return {'pattern': 'recon', 'confidence': 0.70, 'request_count': n, 'source': 'heuristic'}
        if path_unique > 0.6 and post_ratio < 0.3:
            return {'pattern': 'idor_enum', 'confidence': 0.60, 'request_count': n, 'source': 'heuristic'}
        return {'pattern': 'normal', 'confidence': 0.80, 'request_count': n, 'source': 'heuristic'}

    def train(self, sessions_data: list) -> dict:
        """
        sessions_data: [{session_id, flows: [...], label: brute_force/recon/idor_enum/normal}]
        LSTM train karo aur save karo.
        """
        try:
            import torch
            import torch.nn as nn
            from torch.utils.data import DataLoader, TensorDataset

            PATTERNS = ['normal', 'brute_force', 'recon', 'idor_enum']
            X, y = [], []
            for s in sessions_data:
                label = PATTERNS.index(s.get('label', 'normal'))
                vecs  = [self._flow_to_vec(f) for f in s.get('flows', [])]
                if len(vecs) < 3:
                    continue
                # Pad/truncate to SEQ_LEN
                while len(vecs) < self.SEQ_LEN:
                    vecs.insert(0, [0.0] * self.INPUT_DIM)
                X.append(vecs[-self.SEQ_LEN:])
                y.append(label)

            if len(X) < 10:
                return {'error': 'Need 10+ labeled sessions'}

            Xt = torch.tensor(X, dtype=torch.float32)
            yt = torch.tensor(y, dtype=torch.long)
            ds = TensorDataset(Xt, yt)
            dl = DataLoader(ds, batch_size=16, shuffle=True)

            class _LSTM(nn.Module):
                def __init__(self):
                    super().__init__()
                    self.lstm = nn.LSTM(LSTMChainAnalyzer.INPUT_DIM,
                                        LSTMChainAnalyzer.HIDDEN_DIM, batch_first=True)
                    self.fc   = nn.Linear(LSTMChainAnalyzer.HIDDEN_DIM, 4)
                def forward(self, x):
                    out, _ = self.lstm(x)
                    return self.fc(out[:, -1, :])

            model = _LSTM()
            opt   = torch.optim.Adam(model.parameters(), lr=1e-3)
            crit  = nn.CrossEntropyLoss()

            for epoch in range(20):
                for xb, yb in dl:
                    opt.zero_grad()
                    loss = crit(model(xb), yb)
                    loss.backward()
                    opt.step()

            torch.save(model.state_dict(), self.MODEL_PATH)
            self._model  = model
            self._loaded = True
            logger.info(f'[LSTMChain] Trained on {len(X)} sessions, saved')
            return {'status': 'trained', 'sessions': len(X)}
        except Exception as e:
            return {'error': str(e)}


# ── 3. Random Forest WAF Bypass Detector ─────────────────────────────────────

class WAFBypassDetector:
    """
    Request features se WAF bypass probability detect karo.
    Features: entropy, double_encoding, null_bytes, unicode_tricks,
              comment_injection, case_variation, whitespace_tricks, payload_length
    Trained on payloads/*.txt (malicious=1) + normal requests (benign=0).
    """

    MODEL_PATH = _PROXY_MODELS_DIR / 'waf_bypass_rf.joblib'

    def __init__(self):
        self._model  = None
        self._lock   = threading.Lock()
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                import joblib
                if self.MODEL_PATH.exists():
                    self._model = joblib.load(self.MODEL_PATH)
                    logger.info('[WAFBypass] Model loaded')
                else:
                    self._train_from_payloads()
            except Exception as e:
                logger.debug(f'[WAFBypass] load error: {e}')
            self._loaded = True

    def _extract_features(self, text: str) -> list:
        """8 WAF bypass features extract karo."""
        if not text:
            return [0.0] * 8

        t = text[:2000]
        # 1. Shannon entropy
        freq  = defaultdict(int)
        for c in t:
            freq[c] += 1
        entropy = -sum((v/len(t)) * math.log2(v/len(t)) for v in freq.values() if v > 0)

        # 2. Double encoding (%25xx, %2525)
        double_enc = int(bool(re.search(r'%25[0-9a-fA-F]{2}|%2525', t)))

        # 3. Null bytes
        null_bytes = int('\x00' in t or '%00' in t.lower() or '\\x00' in t.lower())

        # 4. Unicode tricks (\\u, %u, overlong UTF-8)
        unicode_tricks = int(bool(re.search(r'%u[0-9a-fA-F]{4}|\\u[0-9a-fA-F]{4}|\\xc0|\\xaf', t, re.I)))

        # 5. Comment injection (SQL/HTML/JS comments)
        comment_inj = int(bool(re.search(r'/\*.*?\*/|<!--.*?-->|//\s*\w|--\s*\w', t, re.DOTALL)))

        # 6. Case variation (SeLeCt, ScRiPt)
        case_var = int(bool(re.search(
            r'(?i)(s[Ee][Ll][Ee][Cc][Tt]|[Uu][Nn][Ii][Oo][Nn]|[Ss][Cc][Rr][Ii][Pp][Tt])', t)))

        # 7. Whitespace tricks (tab, newline, form-feed in SQL/HTML)
        ws_tricks = int(bool(re.search(r'[\t\r\n\x0b\x0c]', t)))

        # 8. Payload length (normalized)
        pay_len = min(len(t), 2000) / 2000.0

        return [entropy, double_enc, null_bytes, unicode_tricks,
                comment_inj, case_var, ws_tricks, pay_len]

    def _train_from_payloads(self):
        """Payload files se auto-train karo."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            import joblib

            X, y = [], []
            # Malicious samples — payload files
            for txt_file in _PAYLOAD_DIR.glob('*.txt'):
                try:
                    lines = [l.strip() for l in txt_file.read_text(errors='ignore').splitlines()
                             if l.strip() and not l.startswith('#')]
                except Exception:
                    continue
                for line in lines[:200]:  # max 200 per file
                    X.append(self._extract_features(line))
                    y.append(1)

            # Benign samples — normal looking strings
            benign = [
                'username=john&password=secret123',
                'search=hello+world&page=1',
                'id=42&action=view',
                'name=John+Doe&email=john@example.com',
                'q=python+tutorial&lang=en',
                'file=report.pdf&download=true',
                'token=abc123&user_id=5',
                'category=electronics&sort=price',
                'message=Hello+how+are+you',
                'date=2024-01-01&format=json',
            ] * 50  # repeat for balance

            for b in benign:
                X.append(self._extract_features(b))
                y.append(0)

            if len(X) < 20:
                return

            clf = RandomForestClassifier(
                n_estimators=100, class_weight='balanced',
                random_state=42, n_jobs=-1,
            )
            clf.fit(np.array(X), np.array(y))
            joblib.dump(clf, self.MODEL_PATH)
            self._model = clf
            logger.info(f'[WAFBypass] Auto-trained on {len(X)} samples')
        except Exception as e:
            logger.debug(f'[WAFBypass] train error: {e}')

    def predict(self, flow: dict) -> float:
        """WAF bypass probability return karo (0.0 - 1.0)."""
        if not self._loaded:
            self._load()

        text = ' '.join([
            flow.get('url', ''),
            flow.get('body', ''),
            json.dumps(flow.get('params', {})),
        ])

        if self._model is None:
            # Rule-based fallback
            feats = self._extract_features(text)
            score = (feats[0] / 8.0 * 0.3 +   # entropy
                     feats[1] * 0.2 +            # double encoding
                     feats[2] * 0.2 +            # null bytes
                     feats[3] * 0.15 +           # unicode
                     feats[4] * 0.15)            # comments
            return round(min(score, 1.0), 4)

        try:
            feats = self._extract_features(text)
            prob  = self._model.predict_proba([feats])[0][1]
            return round(float(prob), 4)
        except Exception:
            return 0.0


# ── 4. Autoencoder Response Anomaly Detector ─────────────────────────────────

class ResponseAutoencoder:
    """
    Normal response patterns seekho, anomalies flag karo.
    Detects: data leakage, stack traces, unusual response sizes.
    Input: [status_code, resp_length, content_type_enc, header_count,
            has_error_kw, has_sensitive_kw]
    """

    INPUT_DIM  = 6
    HIDDEN_DIM = 16
    MODEL_PATH = _PROXY_MODELS_DIR / 'resp_autoencoder.pt'

    # Error keywords jo response mein nahi hone chahiye
    _ERROR_KW = [
        'traceback', 'stack trace', 'exception', 'syntax error',
        'undefined variable', 'fatal error', 'warning:', 'notice:',
        'mysql_fetch', 'pg_query', 'ora-', 'sqlstate', 'jdbc',
        'at line', 'in /var/', 'in /home/', 'in /etc/',
    ]
    _SENSITIVE_KW = [
        'password', 'passwd', 'secret', 'api_key', 'apikey', 'token',
        'private_key', 'access_key', 'aws_', 'authorization',
        'credit_card', 'ssn', 'social_security', 'bank_account',
        'root:', 'shadow:', '/etc/passwd', 'id_rsa',
    ]
    _CONTENT_TYPES = {
        'text/html': 0.1, 'application/json': 0.2, 'text/plain': 0.3,
        'application/xml': 0.4, 'text/xml': 0.4, 'application/javascript': 0.5,
        'text/css': 0.6, 'image/': 0.7, 'application/octet-stream': 0.8,
    }

    def __init__(self):
        self._model       = None
        self._threshold   = 0.05   # reconstruction error threshold
        self._lock        = threading.Lock()
        self._loaded      = False
        self._train_buf   = []     # buffer for online training
        self._buf_lock    = threading.Lock()

    def _flow_to_vec(self, flow: dict) -> list:
        status   = min(flow.get('status_code', 200), 599) / 599.0
        resp_len = min(flow.get('resp_length', 0), 500000) / 500000.0

        ct = flow.get('content_type', '').lower()
        ct_enc = 0.1
        for k, v in self._CONTENT_TYPES.items():
            if k in ct:
                ct_enc = v
                break

        hdr_count = min(flow.get('header_count', 0), 50) / 50.0

        resp_body = (flow.get('resp_body', '') or '')[:3000].lower()
        has_error = int(any(kw in resp_body for kw in self._ERROR_KW))
        has_sens  = int(any(kw in resp_body for kw in self._SENSITIVE_KW))

        return [status, resp_len, ct_enc, hdr_count, float(has_error), float(has_sens)]

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                import torch
                import torch.nn as nn

                class _AE(nn.Module):
                    def __init__(self):
                        super().__init__()
                        self.enc = nn.Sequential(
                            nn.Linear(ResponseAutoencoder.INPUT_DIM, ResponseAutoencoder.HIDDEN_DIM),
                            nn.ReLU(),
                            nn.Linear(ResponseAutoencoder.HIDDEN_DIM, 8),
                        )
                        self.dec = nn.Sequential(
                            nn.Linear(8, ResponseAutoencoder.HIDDEN_DIM),
                            nn.ReLU(),
                            nn.Linear(ResponseAutoencoder.HIDDEN_DIM, ResponseAutoencoder.INPUT_DIM),
                        )
                    def forward(self, x):
                        return self.dec(self.enc(x))

                if self.MODEL_PATH.exists():
                    ck = torch.load(self.MODEL_PATH, map_location='cpu', weights_only=True)
                    m  = _AE()
                    m.load_state_dict(ck['state'])
                    m.eval()
                    self._model     = m
                    self._threshold = ck.get('threshold', 0.05)
                    logger.info('[ResponseAE] Model loaded')
            except Exception as e:
                logger.debug(f'[ResponseAE] load error: {e}')
            self._loaded = True

    def analyze(self, flow: dict) -> dict:
        """
        Response anomaly score calculate karo.
        Returns: {anomaly_score, is_anomaly, flags}
        """
        if not self._loaded:
            self._load()

        vec   = self._flow_to_vec(flow)
        flags = []

        # Rule-based flags (instant, no model needed)
        resp_body = (flow.get('resp_body', '') or '')[:3000].lower()
        for kw in self._ERROR_KW:
            if kw in resp_body:
                flags.append(f'error_keyword:{kw}')
                break
        for kw in self._SENSITIVE_KW:
            if kw in resp_body:
                flags.append(f'sensitive_data:{kw}')
                break

        status = flow.get('status_code', 200)
        if status in (500, 502, 503):
            flags.append(f'server_error:{status}')

        resp_len = flow.get('resp_length', 0)
        if resp_len > 200000:
            flags.append('large_response')

        # Autoencoder reconstruction error
        anomaly_score = 0.0
        if self._model is not None:
            try:
                import torch
                x    = torch.tensor([vec], dtype=torch.float32)
                with torch.no_grad():
                    recon = self._model(x)
                mse  = float(((x - recon) ** 2).mean().item())
                anomaly_score = round(min(mse / (self._threshold * 2), 1.0), 4)
                if mse > self._threshold:
                    flags.append(f'ae_anomaly:{mse:.4f}')
            except Exception as e:
                logger.debug(f'[ResponseAE] inference error: {e}')
        else:
            # Heuristic score
            anomaly_score = round(min(len(flags) * 0.25, 1.0), 4)

        # Buffer mein add karo for future training
        with self._buf_lock:
            self._train_buf.append(vec)
            if len(self._train_buf) >= 200:
                self._async_train()

        return {
            'anomaly_score': anomaly_score,
            'is_anomaly':    anomaly_score > 0.5 or len(flags) > 0,
            'flags':         flags,
        }

    def _async_train(self):
        """Background mein autoencoder retrain karo."""
        data = list(self._train_buf)
        self._train_buf.clear()

        def _run():
            try:
                import torch
                import torch.nn as nn

                class _AE(nn.Module):
                    def __init__(self):
                        super().__init__()
                        self.enc = nn.Sequential(
                            nn.Linear(ResponseAutoencoder.INPUT_DIM, ResponseAutoencoder.HIDDEN_DIM),
                            nn.ReLU(),
                            nn.Linear(ResponseAutoencoder.HIDDEN_DIM, 8),
                        )
                        self.dec = nn.Sequential(
                            nn.Linear(8, ResponseAutoencoder.HIDDEN_DIM),
                            nn.ReLU(),
                            nn.Linear(ResponseAutoencoder.HIDDEN_DIM, ResponseAutoencoder.INPUT_DIM),
                        )
                    def forward(self, x):
                        return self.dec(self.enc(x))

                X   = torch.tensor(data, dtype=torch.float32)
                m   = _AE()
                opt = torch.optim.Adam(m.parameters(), lr=1e-3)
                for _ in range(50):
                    opt.zero_grad()
                    loss = nn.MSELoss()(m(X), X)
                    loss.backward()
                    opt.step()

                # Threshold = 95th percentile of reconstruction errors
                with torch.no_grad():
                    errs = ((X - m(X)) ** 2).mean(dim=1).numpy()
                threshold = float(np.percentile(errs, 95))

                m.eval()
                torch.save({'state': m.state_dict(), 'threshold': threshold},
                           ResponseAutoencoder.MODEL_PATH)
                self._model     = m
                self._threshold = threshold
                logger.info(f'[ResponseAE] Retrained on {len(data)} samples, threshold={threshold:.4f}')
            except Exception as e:
                logger.debug(f'[ResponseAE] async train error: {e}')

        threading.Thread(target=_run, daemon=True, name='ae-train').start()


# ── 5. Markov Chain Attack Path Predictor ────────────────────────────────────

class MarkovAttackPredictor:
    """
    HTTP traffic se attack path predict karo.
    States: recon, auth_probe, sqli_attempt, xss_attempt, lfi_attempt,
            ssrf_attempt, rce_attempt, normal, brute_force, fuzzing
    Transition matrix real proxy traffic se update hoti hai.
    """

    STATES = [
        'normal', 'recon', 'auth_probe', 'sqli_attempt', 'xss_attempt',
        'lfi_attempt', 'ssrf_attempt', 'rce_attempt', 'brute_force', 'fuzzing',
    ]
    STATE2IDX = {s: i for i, s in enumerate(STATES)}
    MATRIX_PATH = _PROXY_MODELS_DIR / 'markov_transitions.json'

    # Patterns to classify a request into a state
    _STATE_PATTERNS = {
        'sqli_attempt':  [r"'.*?(OR|AND|UNION|SELECT)", r"(--|#|/\*)", r"(SLEEP|BENCHMARK)\s*\("],
        'xss_attempt':   [r"<script", r"javascript:", r"on\w+\s*="],
        'lfi_attempt':   [r"\.\./", r"(etc/passwd|php://|file://)"],
        'ssrf_attempt':  [r"(127\.0\.0\.1|localhost|169\.254)", r"(http|ftp|dict|gopher)://"],
        'rce_attempt':   [r"(;|\||&&|`)\s*(id|whoami|cat|ls)", r"(system|exec|shell_exec)\s*\("],
        'auth_probe':    [r"(login|signin|auth|password|passwd|credential)", r"(admin|root|administrator)"],
        'brute_force':   [],  # detected by session pattern
        'fuzzing':       [r"(fuzz|FUZZ|§)", r"(\.\./){3,}"],
        'recon':         [r"(robots\.txt|sitemap|\.git|\.env|wp-admin|phpmyadmin)"],
    }

    def __init__(self):
        # Transition matrix: state_i → state_j count
        n = len(self.STATES)
        self._matrix = np.ones((n, n))  # Laplace smoothing
        self._session_states: dict = defaultdict(list)  # session → state history
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.MATRIX_PATH.exists():
            try:
                data = json.loads(self.MATRIX_PATH.read_text())
                self._matrix = np.array(data)
                logger.info('[Markov] Transition matrix loaded')
            except Exception:
                pass

    def _save(self):
        try:
            self.MATRIX_PATH.write_text(json.dumps(self._matrix.tolist()))
        except Exception:
            pass

    def _classify_state(self, flow: dict) -> str:
        """Request ko ek state mein classify karo."""
        text = ' '.join([
            flow.get('url', ''),
            flow.get('body', ''),
            json.dumps(flow.get('params', {})),
        ]).lower()

        for state, patterns in self._STATE_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return state
        return 'normal'

    def update(self, session_id: str, flow: dict) -> str:
        """
        Flow se state classify karo, transition matrix update karo.
        Returns: current state
        """
        current_state = self._classify_state(flow)
        history = self._session_states[session_id]

        if history:
            prev_idx = self.STATE2IDX.get(history[-1], 0)
            curr_idx = self.STATE2IDX.get(current_state, 0)
            with self._lock:
                self._matrix[prev_idx][curr_idx] += 1

        history.append(current_state)
        if len(history) > 20:
            history.pop(0)

        # Async save
        if sum(self._matrix.flatten()) % 50 == 0:
            threading.Thread(target=self._save, daemon=True).start()

        return current_state

    def predict_next(self, session_id: str) -> dict:
        """
        Session ki current state se next likely attack step predict karo.
        Returns: {current_state, next_state, probability, attack_chain}
        """
        history = self._session_states.get(session_id, [])
        if not history:
            return {'current_state': 'normal', 'next_state': 'normal',
                    'probability': 0.5, 'attack_chain': []}

        current = history[-1]
        curr_idx = self.STATE2IDX.get(current, 0)

        with self._lock:
            row  = self._matrix[curr_idx].copy()

        # Normalize
        total = row.sum()
        probs = row / total if total > 0 else np.ones(len(self.STATES)) / len(self.STATES)

        next_idx  = int(np.argmax(probs))
        next_state = self.STATES[next_idx]

        return {
            'current_state': current,
            'next_state':    next_state,
            'probability':   round(float(probs[next_idx]), 4),
            'attack_chain':  history[-5:],
            'top_3_next':    [
                {'state': self.STATES[i], 'prob': round(float(probs[i]), 4)}
                for i in np.argsort(probs)[::-1][:3]
            ],
        }


# ── 6. Online SGD Classifier ──────────────────────────────────────────────────

class OnlineLearner:
    """
    User flags request → immediate model update via SGDClassifier.partial_fit().
    Labels: malicious=1, benign=0
    Features: same as WAFBypassDetector (8 features)
    """

    MODEL_PATH = _PROXY_MODELS_DIR / 'online_sgd.joblib'

    def __init__(self):
        self._model  = None
        self._lock   = threading.Lock()
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                import joblib
                from sklearn.linear_model import SGDClassifier
                if self.MODEL_PATH.exists():
                    self._model = joblib.load(self.MODEL_PATH)
                    logger.info('[OnlineSGD] Model loaded')
                else:
                    self._model = SGDClassifier(
                        loss='log_loss', class_weight='balanced',
                        random_state=42, max_iter=1,
                    )
            except Exception as e:
                logger.debug(f'[OnlineSGD] load error: {e}')
            self._loaded = True

    def _flow_to_features(self, flow: dict) -> list:
        """WAFBypassDetector ke same 8 features use karo."""
        text = ' '.join([
            flow.get('url', ''),
            flow.get('body', ''),
            json.dumps(flow.get('params', {})),
        ])
        if not text.strip():
            return [0.0] * 8

        freq    = defaultdict(int)
        for c in text:
            freq[c] += 1
        entropy = -sum((v/len(text)) * math.log2(v/len(text)) for v in freq.values() if v > 0) if text else 0

        return [
            entropy,
            int(bool(re.search(r'%25[0-9a-fA-F]{2}|%2525', text))),
            int('\x00' in text or '%00' in text.lower()),
            int(bool(re.search(r'%u[0-9a-fA-F]{4}|\\u[0-9a-fA-F]{4}', text, re.I))),
            int(bool(re.search(r'/\*.*?\*/|<!--.*?-->', text, re.DOTALL))),
            int(bool(re.search(r'(?i)(s[Ee][Ll][Ee][Cc][Tt]|[Uu][Nn][Ii][Oo][Nn])', text))),
            int(bool(re.search(r'[\t\r\n\x0b\x0c]', text))),
            min(len(text), 2000) / 2000.0,
        ]

    def flag(self, flow: dict, label: str) -> bool:
        """
        User ne request flag kiya — model immediately update karo.
        label: 'malicious' | 'benign'
        Returns: True agar update successful
        """
        if not self._loaded:
            self._load()

        try:
            from sklearn.linear_model import SGDClassifier
            import joblib

            y = 1 if label == 'malicious' else 0
            X = [self._flow_to_features(flow)]

            with self._lock:
                if not hasattr(self._model, 'partial_fit') or self._model is None:
                    self._model = SGDClassifier(
                        loss='log_loss', class_weight='balanced',
                        random_state=42, max_iter=1,
                    )
                self._model.partial_fit(X, [y], classes=[0, 1])
                joblib.dump(self._model, self.MODEL_PATH)

            logger.info(f'[OnlineSGD] Updated with label={label}')
            return True
        except Exception as e:
            logger.debug(f'[OnlineSGD] flag error: {e}')
            return False

    def predict(self, flow: dict) -> float:
        """Malicious probability return karo (0.0 - 1.0)."""
        if not self._loaded:
            self._load()
        if self._model is None:
            return 0.0
        try:
            X = [self._flow_to_features(flow)]
            if not hasattr(self._model, 'predict_proba'):
                return 0.0
            # SGD needs to be fitted first
            proba = self._model.predict_proba(X)[0]
            return round(float(proba[1]) if len(proba) > 1 else float(proba[0]), 4)
        except Exception:
            return 0.0


# ── 7. HTTP Isolation Forest (proxy-specific) ─────────────────────────────────

class HTTPAnomalyDetector:
    """
    HTTP-specific anomaly detection.
    Features: status_code, resp_length, timing, param_count, path_depth,
              has_auth_header, content_type_enc, method_enc
    """

    MODEL_PATH = _PROXY_MODELS_DIR / 'http_isoforest.joblib'

    _METHOD_ENC = {'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4,
                   'PATCH': 5, 'OPTIONS': 6, 'HEAD': 7}
    _CT_ENC     = {'text/html': 1, 'application/json': 2, 'text/plain': 3,
                   'application/xml': 4, 'application/javascript': 5}

    def __init__(self):
        self._model    = None
        self._buf      = []
        self._buf_lock = threading.Lock()
        self._lock     = threading.Lock()
        self._loaded   = False

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                import joblib
                if self.MODEL_PATH.exists():
                    self._model = joblib.load(self.MODEL_PATH)
                    logger.info('[HTTPAnomaly] IsolationForest loaded')
            except Exception as e:
                logger.debug(f'[HTTPAnomaly] load error: {e}')
            self._loaded = True

    def _flow_to_vec(self, flow: dict) -> list:
        status    = flow.get('status_code', 200)
        resp_len  = min(flow.get('resp_length', 0), 500000)
        timing    = min(flow.get('timing', 0.0), 30.0)
        params    = flow.get('params', {})
        param_cnt = len(params) if isinstance(params, dict) else 0
        path      = flow.get('path', '/')
        path_depth = path.count('/')
        has_auth  = int(bool(flow.get('headers', {}).get('authorization') or
                             flow.get('headers', {}).get('Authorization')))
        ct        = flow.get('content_type', '')
        ct_enc    = next((v for k, v in self._CT_ENC.items() if k in ct), 0)
        method    = self._METHOD_ENC.get(flow.get('method', 'GET'), 0)
        return [status, resp_len, timing, param_cnt, path_depth, has_auth, ct_enc, method]

    def score(self, flow: dict) -> dict:
        """
        Anomaly score return karo.
        Returns: {anomaly_score, is_anomaly}
        """
        if not self._loaded:
            self._load()

        vec = self._flow_to_vec(flow)

        # Buffer mein add karo
        with self._buf_lock:
            self._buf.append(vec)
            if len(self._buf) >= 100:
                self._async_fit(list(self._buf))
                self._buf.clear()

        if self._model is None:
            return {'anomaly_score': 0.0, 'is_anomaly': False}

        try:
            score = float(self._model.decision_function([vec])[0])
            # IsolationForest: negative = anomaly, positive = normal
            # Normalize to 0-1 (higher = more anomalous)
            norm_score = round(max(0.0, min(1.0, (-score + 0.5))), 4)
            return {
                'anomaly_score': norm_score,
                'is_anomaly':    norm_score > 0.6,
            }
        except Exception:
            return {'anomaly_score': 0.0, 'is_anomaly': False}

    def _async_fit(self, data: list):
        def _run():
            try:
                from sklearn.ensemble import IsolationForest
                import joblib
                X = np.array(data)
                m = IsolationForest(contamination=0.1, n_estimators=100, random_state=42)
                m.fit(X)
                joblib.dump(m, self.MODEL_PATH)
                self._model = m
                logger.info(f'[HTTPAnomaly] Fitted on {len(data)} samples')
            except Exception as e:
                logger.debug(f'[HTTPAnomaly] fit error: {e}')
        threading.Thread(target=_run, daemon=True, name='http-isoforest').start()


# ── 8. SentinelNet + LightGBM wrappers for proxy ─────────────────────────────

class _SentinelNetProxy:
    """SentinelNet ko proxy ke liye wrap karo — lazy load."""

    def __init__(self):
        self._trainer = None
        self._lock    = threading.Lock()
        self._loaded  = False

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                from modules.ml_engine.sentinel_net import NeuralTrainer
                nt = NeuralTrainer()
                if nt.load():
                    self._trainer = nt
                    logger.info('[SentinelNetProxy] Loaded')
            except Exception as e:
                logger.debug(f'[SentinelNetProxy] load error: {e}')
            self._loaded = True

    def predict(self, text: str) -> dict:
        if not self._loaded:
            self._load()
        if self._trainer is None:
            return {'label': 'UNKNOWN', 'confidence': 0.0, 'threat_type': 'unknown',
                    'action_hint': 'monitor'}
        try:
            return self._trainer.predict(text[:1000])
        except Exception:
            return {'label': 'UNKNOWN', 'confidence': 0.0, 'threat_type': 'unknown',
                    'action_hint': 'monitor'}


class _LightGBMProxy:
    """SentinelLightGBM ko proxy HTTP logs ke liye use karo."""

    def __init__(self):
        self._lgbm   = None
        self._lock   = threading.Lock()
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                from sentinel_brain.advanced_ml import SentinelLightGBM
                self._lgbm = SentinelLightGBM()
                logger.info('[LightGBMProxy] Loaded')
            except Exception as e:
                logger.debug(f'[LightGBMProxy] load error: {e}')
            self._loaded = True

    def predict(self, flow: dict) -> dict:
        if not self._loaded:
            self._load()
        if self._lgbm is None:
            return {'is_attack': False, 'probability': 0.0, 'severity': 'LOW'}
        try:
            log_entry = {
                'message':       f"{flow.get('method','')} {flow.get('url','')} {flow.get('body','')}",
                'status_code':   flow.get('status_code', 200),
                'response_time': flow.get('timing', 0.0),
            }
            return self._lgbm.predict_log(log_entry)
        except Exception:
            return {'is_attack': False, 'probability': 0.0, 'severity': 'LOW'}


class _DBSCANProxy:
    """Session requests ko cluster karo — same attack pattern dhundo."""

    def __init__(self):
        self._dbscan = None
        self._lock   = threading.Lock()
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            try:
                from sentinel_brain.advanced_ml import SentinelDBSCAN
                self._dbscan = SentinelDBSCAN()
                logger.info('[DBSCANProxy] Loaded')
            except Exception as e:
                logger.debug(f'[DBSCANProxy] load error: {e}')
            self._loaded = True

    def cluster_paths(self, paths: list) -> dict:
        if not self._loaded:
            self._load()
        if self._dbscan is None or len(paths) < 2:
            return {'clusters': [], 'noise': paths}
        try:
            return self._dbscan.cluster_usernames(paths)  # same char n-gram logic works for paths
        except Exception:
            return {'clusters': [], 'noise': paths}


# ── Main ProxyMLEngine ────────────────────────────────────────────────────────

class ProxyMLEngine:
    """
    Sentinel Proxy ke liye unified ML analysis engine.

    Usage:
        engine = ProxyMLEngine()
        result = engine.analyze_request(flow)
        engine.flag_request(flow, 'malicious')
        resp   = engine.analyze_response(flow)
        sess   = engine.get_session_analysis(session_id)
    """

    def __init__(self):
        # Existing algorithms
        self._sentinel   = _SentinelNetProxy()
        self._lgbm       = _LightGBMProxy()
        self._dbscan     = _DBSCANProxy()

        # New proxy-specific algorithms
        self._payload_fp = PayloadFingerprinter()
        self._lstm       = LSTMChainAnalyzer()
        self._waf        = WAFBypassDetector()
        self._autoenc    = ResponseAutoencoder()
        self._markov     = MarkovAttackPredictor()
        self._online     = OnlineLearner()
        self._http_iso   = HTTPAnomalyDetector()

        # Session path tracking for DBSCAN
        self._session_paths: dict = defaultdict(list)

        logger.info('[ProxyMLEngine] Initialized')

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_request(self, flow: dict) -> dict:
        """
        HTTP request ka full ML analysis karo.

        flow dict keys:
            url, method, path, body, params, headers,
            status_code, resp_length, resp_body, timing,
            content_type, header_count, session_id

        Returns:
            risk, vulns, anomaly_score, waf_bypass_prob, attack_chain,
            payload_match, session_pattern, confidence, sources
        """
        session_id = flow.get('session_id', 'default')
        sources    = []
        vulns      = []
        risk       = 'LOW'
        confidence = 0.0

        # Build analysis text
        text = self._build_text(flow)

        # ── 1. SentinelNet ────────────────────────────────────────────────────
        sn_result = self._sentinel.predict(text)
        sn_label  = sn_result.get('label', 'UNKNOWN')
        sn_conf   = sn_result.get('confidence', 0.0)
        if sn_label not in ('UNKNOWN', 'LOW'):
            vulns.append({
                'type':     sn_result.get('threat_type', 'unknown'),
                'severity': sn_label,
                'detail':   f"SentinelNet: {sn_result.get('action_hint', 'investigate')}",
                'source':   'sentinelnet',
            })
            risk       = _max_risk(risk, sn_label)
            confidence = max(confidence, sn_conf)
            sources.append('sentinelnet')

        # ── 2. IsolationForest (HTTP anomaly) ─────────────────────────────────
        iso_result = self._http_iso.score(flow)
        if iso_result.get('is_anomaly'):
            vulns.append({
                'type':     'http_anomaly',
                'severity': 'MEDIUM',
                'detail':   f"HTTP anomaly score: {iso_result['anomaly_score']:.3f}",
                'source':   'isolation_forest',
            })
            risk = _max_risk(risk, 'MEDIUM')
            sources.append('isolation_forest')

        # ── 3. LightGBM (log pattern) ─────────────────────────────────────────
        lgbm_result = self._lgbm.predict(flow)
        if lgbm_result.get('is_attack'):
            sev = lgbm_result.get('severity', 'MEDIUM')
            vulns.append({
                'type':     'attack_pattern',
                'severity': sev,
                'detail':   f"LightGBM attack probability: {lgbm_result.get('probability', 0):.3f}",
                'source':   'lightgbm',
            })
            risk = _max_risk(risk, sev)
            sources.append('lightgbm')

        # ── 4. TF-IDF Payload Fingerprinting ─────────────────────────────────
        payload_text = ' '.join([
            flow.get('body', ''),
            json.dumps(flow.get('params', {})),
            flow.get('url', ''),
        ])
        payload_match = self._payload_fp.match(payload_text)
        if payload_match.get('type') and payload_match.get('similarity', 0) > 0.15:
            sev = self._payload_type_to_severity(payload_match['type'])
            vulns.append({
                'type':     payload_match['type'],
                'severity': sev,
                'detail':   f"Payload match: {payload_match['type']} (sim={payload_match['similarity']:.3f})",
                'source':   'tfidf_payload',
            })
            risk = _max_risk(risk, sev)
            sources.append('tfidf_payload')

        # ── 5. WAF Bypass Detector ────────────────────────────────────────────
        waf_prob = self._waf.predict(flow)
        if waf_prob > 0.6:
            vulns.append({
                'type':     'waf_bypass',
                'severity': 'HIGH' if waf_prob > 0.8 else 'MEDIUM',
                'detail':   f"WAF bypass probability: {waf_prob:.3f}",
                'source':   'rf_waf',
            })
            risk = _max_risk(risk, 'HIGH' if waf_prob > 0.8 else 'MEDIUM')
            sources.append('rf_waf')

        # ── 6. Online SGD (user-flagged learning) ─────────────────────────────
        sgd_prob = self._online.predict(flow)
        if sgd_prob > 0.7:
            vulns.append({
                'type':     'user_flagged_pattern',
                'severity': 'HIGH',
                'detail':   f"Similar to user-flagged requests (prob={sgd_prob:.3f})",
                'source':   'online_sgd',
            })
            risk = _max_risk(risk, 'HIGH')
            sources.append('online_sgd')

        # ── 7. LSTM Session Pattern ───────────────────────────────────────────
        self._lstm.add_request(session_id, flow)
        lstm_result    = self._lstm.analyze_session(session_id)
        session_pattern = lstm_result.get('pattern', 'normal')
        if session_pattern in ('brute_force', 'recon', 'idor_enum'):
            sev = 'HIGH' if session_pattern == 'brute_force' else 'MEDIUM'
            vulns.append({
                'type':     session_pattern,
                'severity': sev,
                'detail':   f"Session pattern: {session_pattern} (conf={lstm_result.get('confidence', 0):.3f})",
                'source':   'lstm',
            })
            risk = _max_risk(risk, sev)
            sources.append('lstm')

        # ── 8. Markov Attack Path ─────────────────────────────────────────────
        self._markov.update(session_id, flow)
        markov_result = self._markov.predict_next(session_id)
        attack_chain  = markov_result.get('next_state', 'normal')

        # ── 9. DBSCAN path clustering ─────────────────────────────────────────
        path = flow.get('path', '/')
        self._session_paths[session_id].append(path)
        if len(self._session_paths[session_id]) >= 5:
            cluster_result = self._dbscan.cluster_paths(
                self._session_paths[session_id][-20:]
            )
            if len(cluster_result.get('clusters', [])) > 0:
                sources.append('dbscan')

        # ── Final confidence ──────────────────────────────────────────────────
        if not confidence and vulns:
            confidence = round(min(0.5 + len(vulns) * 0.1, 0.95), 4)

        return {
            'risk':             risk,
            'vulns':            vulns,
            'anomaly_score':    iso_result.get('anomaly_score', 0.0),
            'waf_bypass_prob':  waf_prob,
            'attack_chain':     attack_chain,
            'payload_match':    payload_match,
            'session_pattern':  session_pattern,
            'confidence':       round(confidence, 4),
            'sources':          list(set(sources)),
            'markov':           markov_result,
        }

    def analyze_response(self, flow: dict) -> dict:
        """
        HTTP response ka autoencoder anomaly analysis karo.
        Returns: {anomaly_score, is_anomaly, flags, risk}
        """
        result = self._autoenc.analyze(flow)
        risk   = 'LOW'
        if result.get('is_anomaly'):
            score = result.get('anomaly_score', 0)
            risk  = 'CRITICAL' if score > 0.8 else 'HIGH' if score > 0.6 else 'MEDIUM'
        result['risk'] = risk
        return result

    def flag_request(self, flow: dict, label: str):
        """
        User ne request flag kiya — online learning update karo.
        label: 'malicious' | 'benign'
        """
        self._online.flag(flow, label)
        logger.info(f'[ProxyMLEngine] Request flagged as {label}')

    def get_session_analysis(self, session_id: str) -> dict:
        """
        Session ka full analysis return karo.
        Returns: {pattern, confidence, request_count, markov, paths_clustered}
        """
        lstm_result   = self._lstm.analyze_session(session_id)
        markov_result = self._markov.predict_next(session_id)
        paths         = self._session_paths.get(session_id, [])

        cluster_result = {}
        if len(paths) >= 3:
            cluster_result = self._dbscan.cluster_paths(paths[-20:])

        return {
            'session_id':      session_id,
            'pattern':         lstm_result.get('pattern', 'normal'),
            'confidence':      lstm_result.get('confidence', 0.5),
            'request_count':   lstm_result.get('request_count', 0),
            'markov':          markov_result,
            'paths_clustered': cluster_result,
            'state_history':   self._markov._session_states.get(session_id, [])[-10:],
        }

    def train_lstm(self, sessions_data: list) -> dict:
        """LSTM model train karo labeled session data se."""
        return self._lstm.train(sessions_data)

    def get_status(self) -> dict:
        """Engine components ka status return karo."""
        return {
            'sentinelnet':    self._sentinel._trainer is not None,
            'lightgbm':       self._lgbm._lgbm is not None,
            'dbscan':         self._dbscan._dbscan is not None,
            'payload_fp':     self._payload_fp._loaded,
            'lstm':           self._lstm._model is not None,
            'waf_bypass':     self._waf._model is not None,
            'autoencoder':    self._autoenc._model is not None,
            'markov':         True,
            'online_sgd':     self._online._model is not None,
            'http_isoforest': self._http_iso._model is not None,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_text(self, flow: dict) -> str:
        """Flow se analysis text banao."""
        parts = [
            flow.get('url', ''),
            flow.get('method', ''),
            flow.get('body', '')[:500],
            json.dumps(flow.get('params', {}))[:300],
        ]
        return ' '.join(p for p in parts if p)[:1000]

    @staticmethod
    def _payload_type_to_severity(ptype: str) -> str:
        """Payload type se severity map karo."""
        critical = {'sqli', 'rce', 'xxe', 'ssti', 'cve_exploits', 'smuggling'}
        high     = {'xss', 'lfi', 'ssrf', 'path_traversal', 'ldap', 'xpath', 'xslt'}
        medium   = {'cors', 'crlf', 'open_redirect', 'prototype_pollution',
                    'nosql', 'graphql', 'jwt', 'oauth', 'saml'}
        if ptype in critical:
            return 'CRITICAL'
        if ptype in high:
            return 'HIGH'
        if ptype in medium:
            return 'MEDIUM'
        return 'LOW'


# ── Singleton ─────────────────────────────────────────────────────────────────

_engine_instance: ProxyMLEngine = None
_engine_lock = threading.Lock()


def get_engine() -> ProxyMLEngine:
    """Singleton ProxyMLEngine instance return karo."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = ProxyMLEngine()
    return _engine_instance
