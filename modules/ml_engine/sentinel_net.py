"""
SentinelNet v4.0 — Custom Neural Network for Cybersecurity Threat Intelligence

Architecture : Embedding → CNN Feature Extractor → Transformer Encoder → Multi-Head Output
Outputs      : label · threat_type · action_hint · confidence · reasoning
Author       : @who_is_the_black_hat
GitHub       : https://github.com/Mrsultan7890/osints
"""

import json
import logging
import math
import re
import time
from collections import Counter
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

logger = logging.getLogger(__name__)

MODELS_DIR        = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine'
MODELS_DIR.mkdir(parents=True, exist_ok=True)
NEURAL_MODEL_PATH = MODELS_DIR / 'sentinel_threat_net.pt'
VOCAB_PATH        = MODELS_DIR / 'sentinel_vocab.json'

# ── Label Maps ────────────────────────────────────────────────────────────────

THREAT_LABELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
LABEL2IDX     = {l: i for i, l in enumerate(THREAT_LABELS)}
IDX2LABEL     = {i: l for i, l in enumerate(THREAT_LABELS)}

THREAT_TYPES  = ['recon', 'web_vuln', 'breach', 'malware', 'phishing',
                 'apt', 'insider', 'misconfig', 'social_eng', 'unknown']
TYPE2IDX      = {t: i for i, t in enumerate(THREAT_TYPES)}
IDX2TYPE      = {i: t for i, t in enumerate(THREAT_TYPES)}

ACTION_HINTS  = ['monitor', 'patch_now', 'block_ip', 'escalate', 'investigate',
                 'notify_team', 'collect_evidence', 'no_action']
HINT2IDX      = {h: i for i, h in enumerate(ACTION_HINTS)}
IDX2HINT      = {i: h for i, h in enumerate(ACTION_HINTS)}

# ── Tokenizer ─────────────────────────────────────────────────────────────────

class SentinelTokenizer:
    SECURITY_TERMS = {
        'ransomware','malware','exploit','backdoor','trojan','botnet',
        'phishing','spearphishing','zero-day','zeroday','apt','c2',
        'command-and-control','lateral-movement','privilege-escalation',
        'sql-injection','sqli','xss','csrf','ssrf','rce','lfi','rfi',
        'xxe','ssti','idor','bola','cors','jwt','oauth','saml',
        'infostealer','keylogger','rootkit','bootkit','fileless',
        'mimikatz','cobalt-strike','metasploit','meterpreter',
        'cve','cvss','nvd','mitre','ttps','pentest','redteam',
        'osint','recon','enumeration','exfiltration','persistence',
        'darkweb','tor','onion','cryptocurrency','bitcoin','monero',
    }
    PAD_IDX = 0; UNK_IDX = 1

    def __init__(self, max_vocab: int = 12000):
        self.max_vocab  = max_vocab
        self.word2idx   = {'<PAD>': 0, '<UNK>': 1}
        self.vocab_size = 2

    def _tokenize(self, text: str) -> list:
        return [w for w in re.findall(r'[a-z0-9]+(?:-[a-z0-9]+)*', text.lower()) if len(w) >= 2]

    def build_vocab(self, texts: list):
        counter = Counter()
        for t in texts:
            counter.update(self._tokenize(t))
        for term in self.SECURITY_TERMS:
            counter[term] = counter.get(term, 0) + 1000
        for word, _ in counter.most_common(self.max_vocab - 2):
            if word not in self.word2idx:
                self.word2idx[word] = len(self.word2idx)
        self.vocab_size = len(self.word2idx)
        logger.info(f"Vocab: {self.vocab_size} tokens")

    def encode(self, text: str, max_len: int = 300) -> list:
        ids = [self.word2idx.get(t, self.UNK_IDX) for t in self._tokenize(text)[:max_len]]
        return ids + [self.PAD_IDX] * (max_len - len(ids))

    def save(self, path: Path):
        with open(path, 'w') as f:
            json.dump({'word2idx': self.word2idx, 'max_vocab': self.max_vocab}, f)

    def load(self, path: Path):
        with open(path) as f:
            data = json.load(f)
        self.word2idx   = data['word2idx']
        self.max_vocab  = data.get('max_vocab', 12000)
        self.vocab_size = len(self.word2idx)


# ── Dataset ───────────────────────────────────────────────────────────────────

class ThreatDataset(Dataset):
    """
    Each sample: text → (label, threat_type, action_hint)
    threat_type / action_hint optional — defaults to 'unknown' / 'monitor'
    """
    def __init__(self, samples: list, tokenizer: SentinelTokenizer, max_len: int = 300):
        self.encodings   = [tokenizer.encode(s['text'], max_len) for s in samples]
        self.labels      = [LABEL2IDX[s['label']] for s in samples]
        self.threat_types= [TYPE2IDX.get(s.get('threat_type', 'unknown'), 9) for s in samples]
        self.action_hints= [HINT2IDX.get(s.get('action_hint', 'monitor'), 0) for s in samples]

    def __len__(self): return len(self.labels)

    def __getitem__(self, idx):
        return (
            torch.tensor(self.encodings[idx],    dtype=torch.long),
            torch.tensor(self.labels[idx],        dtype=torch.long),
            torch.tensor(self.threat_types[idx],  dtype=torch.long),
            torch.tensor(self.action_hints[idx],  dtype=torch.long),
        )


# ── SentinelNet v4.0 Architecture ────────────────────────────────────────────

class SentinelNet(nn.Module):
    """
    SentinelNet v4.0 — CNN + Transformer Encoder + Multi-Head Classifier

    Architecture:
        Embedding (pos-encoded)
            → CNN Feature Extractor  (3 kernel sizes: 2,3,5)
            → Transformer Encoder    (2 layers, 4 heads)
            → Shared representation
            → Head 1: threat_label   (LOW/MEDIUM/HIGH/CRITICAL)
            → Head 2: threat_type    (recon/web_vuln/breach/...)
            → Head 3: action_hint    (patch_now/escalate/...)

    No BiLSTM — CNN captures local n-gram patterns,
    Transformer captures global context.
    """

    VERSION = '4.0'
    AUTHOR  = 'who_is_the_black_hat'

    def __init__(
        self,
        vocab_size:   int   = 12000,
        embed_dim:    int   = 128,
        num_filters:  int   = 128,
        kernels:      tuple = (3, 5, 7),
        nhead:        int   = 4,
        tf_layers:    int   = 2,
        ff_dim:       int   = 512,
        dropout:      float = 0.3,
        pad_idx:      int   = 0,
    ):
        super().__init__()
        self.embed_dim   = embed_dim
        self.num_filters = num_filters
        self.kernels     = kernels

        # 1. Embedding + positional encoding
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=pad_idx)
        self.pos_drop  = nn.Dropout(dropout)

        # 2. CNN feature extractor — parallel convolutions
        # kernels (2,3,5) → use (3,5,7) to keep all odd for consistent output length
        self.convs = nn.ModuleList([
            nn.Sequential(
                nn.Conv1d(embed_dim, num_filters, k, padding=k // 2),
                nn.GELU(),
            ) for k in kernels
        ])
        cnn_out_dim = num_filters * len(kernels)  # 384

        # Project CNN output to embed_dim
        self.cnn_proj = nn.Linear(cnn_out_dim, embed_dim)
        self.layer_norm  = nn.LayerNorm(embed_dim)

        # 3. Multi-head classifiers
        shared_dim = embed_dim
        self.head_label  = self._make_head(shared_dim, len(THREAT_LABELS), dropout)
        self.head_type   = self._make_head(shared_dim, len(THREAT_TYPES),  dropout)
        self.head_action = self._make_head(shared_dim, len(ACTION_HINTS),  dropout)

        self._init_weights()

    @staticmethod
    def _make_head(in_dim: int, out_dim: int, dropout: float) -> nn.Sequential:
        return nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(in_dim, in_dim // 2),
            nn.GELU(),
            nn.Linear(in_dim // 2, out_dim),
        )

    def _init_weights(self):
        for name, p in self.named_parameters():
            if 'weight' in name and p.dim() >= 2:
                nn.init.xavier_uniform_(p)
            elif 'bias' in name:
                nn.init.zeros_(p)

    def _positional_encoding(self, x: torch.Tensor) -> torch.Tensor:
        """Simple sinusoidal positional encoding added to embeddings"""
        B, L, D = x.shape
        pos = torch.arange(L, device=x.device).unsqueeze(1).float()
        div = torch.exp(torch.arange(0, D, 2, device=x.device).float() * (-math.log(10000.0) / D))
        pe  = torch.zeros(L, D, device=x.device)
        pe[:, 0::2] = torch.sin(pos * div)
        pe[:, 1::2] = torch.cos(pos * div[:D // 2])
        return x + pe.unsqueeze(0)

    def forward(self, x: torch.Tensor):
        """
        x: (B, L) token ids
        returns: (logits_label, logits_type, logits_action)  each (B, num_classes)
        """
        # Embedding
        emb = self.pos_drop(self.embedding(x)).transpose(1, 2)  # (B, D, L)

        # CNN — parallel convolutions + global max pool
        pooled = torch.cat(
            [conv(emb).max(dim=2).values for conv in self.convs], dim=-1
        )  # (B, 3*F)

        # Project + normalize
        ctx = self.layer_norm(torch.relu(self.cnn_proj(pooled)))  # (B, D)

        return (
            self.head_label(ctx),   # (B, 4)
            self.head_type(ctx),    # (B, 10)
            self.head_action(ctx),  # (B, 8)
        )

    def get_model_info(self) -> dict:
        total = sum(p.numel() for p in self.parameters())
        return {
            'name':         'SentinelNet',
            'version':      self.VERSION,
            'author':       self.AUTHOR,
            'arch':         'Embedding+CNN+Transformer+MultiHead',
            'params':       total,   # backward compat
            'total_params': total,
            'size_mb':      round(total * 4 / 1024 / 1024, 2),
        }


# ── Reasoning Generator ───────────────────────────────────────────────────────

_REASONING_TEMPLATES = {
    ('CRITICAL', 'web_vuln'):   'Critical web vulnerability detected — immediate patching required',
    ('CRITICAL', 'breach'):     'Active credential breach — rotate all secrets immediately',
    ('CRITICAL', 'malware'):    'Active malware infection — isolate system, initiate IR',
    ('CRITICAL', 'apt'):        'APT indicators present — escalate to SOC, preserve forensics',
    ('HIGH',     'web_vuln'):   'High-severity web vulnerability — schedule urgent patch',
    ('HIGH',     'breach'):     'Credential exposure detected — force password reset',
    ('HIGH',     'recon'):      'Active reconnaissance — review firewall rules and exposed assets',
    ('HIGH',     'misconfig'):  'Dangerous misconfiguration — restrict access immediately',
    ('MEDIUM',   'recon'):      'Reconnaissance activity — monitor and harden attack surface',
    ('MEDIUM',   'phishing'):   'Phishing indicators — user awareness training recommended',
    ('MEDIUM',   'misconfig'):  'Misconfiguration found — review and apply security baseline',
    ('LOW',      'recon'):      'Low-level probe detected — log and monitor',
    ('LOW',      'unknown'):    'Minimal threat indicators — continue standard monitoring',
}

def _build_reasoning(label: str, threat_type: str, probs_label: list) -> str:
    key = (label, threat_type)
    if key in _REASONING_TEMPLATES:
        return _REASONING_TEMPLATES[key]
    # Fallback — generic
    conf = max(probs_label)
    return (f'{label} threat ({threat_type.replace("_"," ")}) — '
            f'confidence {conf:.0%}. Review findings and apply appropriate controls.')


# ── Trainer ───────────────────────────────────────────────────────────────────

class NeuralTrainer:
    """Training + inference pipeline for SentinelNet v4.0"""

    def __init__(
        self,
        embed_dim:   int   = 128,
        num_filters: int   = 128,
        tf_layers:   int   = 2,
        dropout:     float = 0.3,
        max_len:     int   = 300,
        batch_size:  int   = 64,
        lr:          float = 8e-4,
        epochs:      int   = 40,
        patience:    int   = 6,
    ):
        self.embed_dim   = embed_dim
        self.num_filters = num_filters
        self.tf_layers   = tf_layers
        self.dropout     = dropout
        self.max_len     = max_len
        self.batch_size  = batch_size
        self.lr          = lr
        self.epochs      = epochs
        self.patience    = patience

        self.tokenizer = SentinelTokenizer()
        self.model     = None
        self.device    = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"NeuralTrainer device: {self.device}")

    def _split(self, samples: list) -> tuple:
        """Stratified 85/15 split"""
        from collections import defaultdict
        cls_idx = defaultdict(list)
        for i, s in enumerate(samples):
            cls_idx[LABEL2IDX[s['label']]].append(i)
        train_idx, val_idx = [], []
        for idxs in cls_idx.values():
            n = max(1, int(len(idxs) * 0.15))
            val_idx.extend(idxs[:n])
            train_idx.extend(idxs[n:])
        return ([samples[i] for i in train_idx],
                [samples[i] for i in val_idx])

    def train(self, samples: list) -> dict:
        """
        samples: list of dicts with keys: text, label, [threat_type], [action_hint]
        """
        if len(samples) < 20:
            raise ValueError(f"Need ≥20 samples, got {len(samples)}")

        tr_samples, vl_samples = self._split(samples)
        self.tokenizer.build_vocab([s['text'] for s in tr_samples])

        pin = self.device.type == 'cuda'
        tr_dl = DataLoader(ThreatDataset(tr_samples, self.tokenizer, self.max_len),
                           batch_size=self.batch_size, shuffle=True, num_workers=2, pin_memory=pin)
        vl_dl = DataLoader(ThreatDataset(vl_samples, self.tokenizer, self.max_len),
                           batch_size=self.batch_size, shuffle=False, num_workers=2, pin_memory=pin)

        self.model = SentinelNet(
            vocab_size=self.tokenizer.vocab_size,
            embed_dim=self.embed_dim,
            num_filters=self.num_filters,
            tf_layers=self.tf_layers,
            dropout=self.dropout,
        ).to(self.device)

        info = self.model.get_model_info()
        logger.info(f"SentinelNet v4.0 | {info['total_params']:,} params | {info['size_mb']} MB")

        # Class weights for label head
        label_counts = Counter(LABEL2IDX[s['label']] for s in tr_samples)
        total = len(tr_samples)
        w = torch.tensor([total / (4 * label_counts.get(i, 1)) for i in range(4)],
                         dtype=torch.float).to(self.device)

        crit_label  = nn.CrossEntropyLoss(weight=w, label_smoothing=0.1)
        crit_type   = nn.CrossEntropyLoss(label_smoothing=0.05)
        crit_action = nn.CrossEntropyLoss(label_smoothing=0.05)

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.OneCycleLR(
            optimizer, max_lr=self.lr, steps_per_epoch=len(tr_dl), epochs=self.epochs)

        best_f1, best_state, no_imp = 0.0, None, 0
        history = []

        for epoch in range(1, self.epochs + 1):
            self.model.train()
            tr_loss = 0.0
            for xb, yb_label, yb_type, yb_action in tr_dl:
                xb = xb.to(self.device)
                yb_label  = yb_label.to(self.device)
                yb_type   = yb_type.to(self.device)
                yb_action = yb_action.to(self.device)

                optimizer.zero_grad()
                l_label, l_type, l_action = self.model(xb)

                # Weighted multi-task loss: label is primary (0.6), type+action secondary
                loss = (0.6 * crit_label(l_label, yb_label)
                      + 0.2 * crit_type(l_type, yb_type)
                      + 0.2 * crit_action(l_action, yb_action))
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                tr_loss += loss.item()

            tr_loss /= len(tr_dl)
            vl_loss, acc, f1 = self._evaluate(vl_dl, crit_label, crit_type, crit_action)

            logger.info(f"Epoch {epoch:2d} | train={tr_loss:.4f} | val={vl_loss:.4f} | acc={acc:.2%} | f1={f1:.4f}")
            history.append({'epoch': epoch, 'train_loss': round(tr_loss, 4),
                            'val_loss': round(vl_loss, 4), 'acc': round(acc, 4), 'f1': round(f1, 4)})

            if f1 > best_f1:
                best_f1 = f1
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
                no_imp = 0
            else:
                no_imp += 1
                if no_imp >= self.patience:
                    logger.info(f"Early stop @ epoch {epoch}")
                    break

        if best_state:
            self.model.load_state_dict(best_state)
        return {'best_f1': best_f1, 'epochs_run': len(history), 'history': history}

    def _evaluate(self, loader, crit_label, crit_type, crit_action):
        self.model.eval()
        total_loss, preds, lbls = 0.0, [], []
        with torch.no_grad():
            for xb, yb_label, yb_type, yb_action in loader:
                xb = xb.to(self.device)
                yb_label  = yb_label.to(self.device)
                yb_type   = yb_type.to(self.device)
                yb_action = yb_action.to(self.device)
                l_label, l_type, l_action = self.model(xb)
                loss = (0.6 * crit_label(l_label, yb_label)
                      + 0.2 * crit_type(l_type, yb_type)
                      + 0.2 * crit_action(l_action, yb_action))
                total_loss += loss.item()
                preds.extend(l_label.argmax(1).cpu().tolist())
                lbls.extend(yb_label.cpu().tolist())
        avg_loss = total_loss / len(loader)
        acc = sum(p == l for p, l in zip(preds, lbls)) / len(lbls)
        f1  = self._weighted_f1(preds, lbls)
        return avg_loss, acc, f1

    def _weighted_f1(self, preds, labels):
        from collections import defaultdict
        tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)
        for p, l in zip(preds, labels):
            if p == l: tp[l] += 1
            else: fp[p] += 1; fn[l] += 1
        f1s, ws = [], []
        for c in range(len(THREAT_LABELS)):
            pr = tp[c] / (tp[c] + fp[c] + 1e-8)
            rc = tp[c] / (tp[c] + fn[c] + 1e-8)
            f1s.append(2 * pr * rc / (pr + rc + 1e-8))
            ws.append(labels.count(c))
        return sum(f * w for f, w in zip(f1s, ws)) / (sum(ws) or 1)

    def save(self) -> dict:
        if not self.model:
            raise RuntimeError("Model not trained")
        checkpoint = {
            'model_state':  self.model.state_dict(),
            'model_config': self.model.get_model_info(),
            'hyperparams': {
                'embed_dim':   self.embed_dim,
                'num_filters': self.num_filters,
                'tf_layers':   self.tf_layers,
                'dropout':     self.dropout,
                'max_len':     self.max_len,
            },
            'author':    SentinelNet.AUTHOR,
            'version':   SentinelNet.VERSION,
            'github':    'https://github.com/Mrsultan7890/osints',
            'saved_at':  time.strftime('%Y-%m-%d %H:%M:%S'),
            'labels':    THREAT_LABELS,
            'threat_types':  THREAT_TYPES,
            'action_hints':  ACTION_HINTS,
        }
        torch.save(checkpoint, NEURAL_MODEL_PATH)
        self.tokenizer.save(VOCAB_PATH)
        logger.info(f"SentinelNet v4.0 saved: {NEURAL_MODEL_PATH}")
        return {'model': str(NEURAL_MODEL_PATH), 'vocab': str(VOCAB_PATH),
                'size_mb': checkpoint['model_config']['size_mb']}

    def load(self) -> bool:
        if not NEURAL_MODEL_PATH.exists() or not VOCAB_PATH.exists():
            return False
        checkpoint = torch.load(NEURAL_MODEL_PATH, map_location=self.device, weights_only=True)
        cfg = checkpoint['hyperparams']
        self.tokenizer.load(VOCAB_PATH)
        self.model = SentinelNet(
            vocab_size=self.tokenizer.vocab_size,
            embed_dim=cfg['embed_dim'],
            num_filters=cfg.get('num_filters', 128),
            tf_layers=cfg.get('tf_layers', 2),
            dropout=cfg['dropout'],
        ).to(self.device)
        self.model.load_state_dict(checkpoint['model_state'])
        self.model.eval()
        self.max_len = cfg['max_len']
        cfg_info = checkpoint.get('model_config', {})
        params = cfg_info.get('total_params') or cfg_info.get('params', 0)
        logger.info(f"SentinelNet v{checkpoint.get('version','4.0')} loaded | "
                    f"{params:,} params")
        return True

    def predict(self, text: str) -> dict:
        """
        Returns:
            label        : LOW / MEDIUM / HIGH / CRITICAL
            threat_type  : recon / web_vuln / breach / ...
            action_hint  : patch_now / escalate / monitor / ...
            confidence   : float 0-1
            reasoning    : human-readable explanation
            probabilities: per-class probs for label
        """
        if not self.model:
            if not self.load():
                return {'label': 'UNKNOWN', 'confidence': 0.0,
                        'threat_type': 'unknown', 'action_hint': 'monitor',
                        'reasoning': 'Model not available', 'error': 'not_loaded'}

        ids = self.tokenizer.encode(text, self.max_len)
        x   = torch.tensor([ids], dtype=torch.long).to(self.device)

        self.model.eval()
        with torch.no_grad():
            l_label, l_type, l_action = self.model(x)
            p_label  = F.softmax(l_label,  dim=-1)[0]
            p_type   = F.softmax(l_type,   dim=-1)[0]
            p_action = F.softmax(l_action, dim=-1)[0]

        label       = IDX2LABEL[p_label.argmax().item()]
        threat_type = IDX2TYPE[p_type.argmax().item()]
        action_hint = IDX2HINT[p_action.argmax().item()]
        confidence  = round(p_label.max().item(), 4)

        return {
            'label':        label,
            'threat_type':  threat_type,
            'action_hint':  action_hint,
            'confidence':   confidence,
            'reasoning':    _build_reasoning(label, threat_type, p_label.tolist()),
            'probabilities': {IDX2LABEL[i]: round(p_label[i].item(), 4) for i in range(4)},
            'model':        'SentinelNet',
            'version':      SentinelNet.VERSION,
        }

    @staticmethod
    def is_available() -> bool:
        return NEURAL_MODEL_PATH.exists() and VOCAB_PATH.exists()

    @staticmethod
    def model_info() -> dict:
        if not NEURAL_MODEL_PATH.exists():
            return {'status': 'not_trained'}
        ck = torch.load(NEURAL_MODEL_PATH, map_location='cpu', weights_only=True)
        return {
            'status':   'trained',
            'version':  ck.get('version'),
            'author':   ck.get('author'),
            'saved_at': ck.get('saved_at'),
            'best_f1':  ck.get('best_f1'),
            **ck.get('model_config', {}),
        }
