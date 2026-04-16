"""
SentinelThreatNet — Google Colab Training Script
================================================
Yeh script Google Colab (T4 GPU) pe run karo:

STEPS:
1. Google Colab kholo: https://colab.research.google.com
2. Runtime > Change runtime type > T4 GPU
3. Naya cell banao, poora yeh script paste karo
4. Run karo — ~5-10 min mein complete hoga
5. Trained model download karo (sentinel_threat_net.pt + sentinel_vocab.json)
6. Apne machine pe replace karo:
   cp sentinel_threat_net.pt /home/kali/osints/models/ml_engine/
   cp sentinel_vocab.json    /home/kali/osints/models/ml_engine/
"""

# ── Cell 1: Install dependencies ─────────────────────────────────────────────
CELL_1 = """
!pip install -q torch requests
"""

# ── Cell 2: Download training data from your machine ─────────────────────────
# Option A: Upload threat_raw.jsonl manually to Colab
# Option B: Use the data URLs below (public security datasets)
CELL_2 = """
import requests, json, re, time
from pathlib import Path

Path('training_data').mkdir(exist_ok=True)
threat_path = Path('training_data/threat_raw.jsonl')

print('Downloading training data...')

added = 0

# 1. MITRE ATT&CK
try:
    r = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', timeout=30)
    objects = r.json().get('objects', [])
    with open(threat_path, 'a') as f:
        for obj in objects:
            obj_type = obj.get('type', '')
            desc = obj.get('description', '')
            name = obj.get('name', '')
            if not desc: continue
            if obj_type == 'attack-pattern':
                phases = [k['phase_name'] for k in obj.get('kill_chain_phases', [])]
                if any(p in phases for p in ['execution','exfiltration','impact','command-and-control']):
                    label = 'CRITICAL'
                elif any(p in phases for p in ['privilege-escalation','defense-evasion','lateral-movement']):
                    label = 'HIGH'
                else:
                    label = 'MEDIUM'
            elif obj_type == 'malware':   label = 'CRITICAL'
            elif obj_type == 'tool':      label = 'HIGH'
            elif obj_type == 'campaign':  label = 'CRITICAL'
            else: continue
            clean = re.sub(r'\\(Citation:[^)]+\\)', '', desc)
            clean = re.sub(r'<[^>]+>', '', clean).strip()
            text = f"{name}. {clean}"[:2000]
            if len(text) >= 50:
                f.write(json.dumps({'text': text, 'label': label, 'source': 'mitre'}) + '\\n')
                added += 1
    print(f'MITRE ATT&CK: +{added} samples')
except Exception as e:
    print(f'MITRE failed: {e}')

# 2. GitHub GHSA Advisories
ghsa_added = 0
try:
    severity_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'moderate': 'MEDIUM', 'low': 'LOW'}
    with open(threat_path, 'a') as f:
        for sev, label in severity_map.items():
            for page in range(1, 6):
                r = requests.get('https://api.github.com/advisories',
                    params={'severity': sev, 'per_page': 100, 'page': page}, timeout=15)
                if r.status_code != 200: break
                advisories = r.json()
                if not advisories: break
                for adv in advisories:
                    summary = adv.get('summary', '')
                    desc = adv.get('description', '') or ''
                    text = f"{summary}. {desc}"[:2000].strip()
                    text = re.sub(r'```[\\s\\S]*?```', '', text)
                    text = re.sub(r'[#*`>]', '', text).strip()
                    if len(text) >= 30:
                        f.write(json.dumps({'text': text, 'label': label, 'source': 'ghsa'}) + '\\n')
                        ghsa_added += 1
                time.sleep(0.3)
    print(f'GitHub GHSA: +{ghsa_added} samples')
except Exception as e:
    print(f'GHSA failed: {e}')

# 3. NVD CVE
nvd_added = 0
try:
    with open(threat_path, 'a') as f:
        for sev, label in [('CRITICAL','CRITICAL'),('HIGH','HIGH'),('MEDIUM','MEDIUM'),('LOW','LOW')]:
            r = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0',
                params={'cvssV3Severity': sev, 'resultsPerPage': 200}, timeout=20)
            if r.status_code == 200:
                for item in r.json().get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cid = cve.get('id', '')
                    descs = cve.get('descriptions', [])
                    desc = next((d['value'] for d in descs if d.get('lang') == 'en'), '')
                    if len(desc) >= 30:
                        f.write(json.dumps({'text': f"{cid} {desc}"[:2000], 'label': label, 'source': 'nvd'}) + '\\n')
                        nvd_added += 1
            time.sleep(0.6)
    print(f'NVD CVE: +{nvd_added} samples')
except Exception as e:
    print(f'NVD failed: {e}')

# Count
with open(threat_path) as f:
    total = sum(1 for l in f if l.strip())
print(f'\\nTotal samples: {total}')
"""

# ── Cell 3: Define SentinelThreatNet ─────────────────────────────────────────
CELL_3 = """
import json, re, math, time
from collections import Counter
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

THREAT_LABELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
LABEL2IDX = {l: i for i, l in enumerate(THREAT_LABELS)}
IDX2LABEL  = {i: l for i, l in enumerate(THREAT_LABELS)}

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f'Device: {DEVICE}')

# ── Tokenizer ──────────────────────────────────────────────────────────────
class SentinelTokenizer:
    SECURITY_TERMS = {
        'ransomware','malware','exploit','backdoor','trojan','botnet','phishing',
        'zero-day','apt','c2','sqli','xss','csrf','ssrf','rce','lfi','rfi','xxe',
        'ssti','idor','cors','jwt','oauth','infostealer','keylogger','rootkit',
        'mimikatz','cobalt-strike','cve','cvss','mitre','osint','exfiltration',
    }
    PAD_IDX = 0
    UNK_IDX = 1

    def __init__(self, max_vocab=10000):
        self.max_vocab = max_vocab
        self.word2idx = {'<PAD>': 0, '<UNK>': 1}
        self.vocab_size = 2

    def _tokenize(self, text):
        return [w for w in re.findall(r'[a-z0-9]+(?:-[a-z0-9]+)*', text.lower()) if len(w) >= 2]

    def build_vocab(self, texts):
        counter = Counter()
        for t in texts: counter.update(self._tokenize(t))
        for term in self.SECURITY_TERMS:
            counter[term] = counter.get(term, 0) + 1000
        for word, _ in counter.most_common(self.max_vocab - 2):
            if word not in self.word2idx:
                self.word2idx[word] = len(self.word2idx)
        self.vocab_size = len(self.word2idx)
        print(f'Vocab: {self.vocab_size} tokens')

    def encode(self, text, max_len=256):
        ids = [self.word2idx.get(t, self.UNK_IDX) for t in self._tokenize(text)[:max_len]]
        ids += [self.PAD_IDX] * (max_len - len(ids))
        return ids

    def save(self, path):
        with open(path, 'w') as f:
            json.dump({'word2idx': self.word2idx, 'max_vocab': self.max_vocab}, f)

    def load(self, path):
        with open(path) as f:
            d = json.load(f)
        self.word2idx = d['word2idx']
        self.vocab_size = len(self.word2idx)


# ── Dataset ────────────────────────────────────────────────────────────────
class ThreatDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=256):
        self.encodings = [tokenizer.encode(t, max_len) for t in texts]
        self.labels = labels

    def __len__(self): return len(self.labels)

    def __getitem__(self, idx):
        return (torch.tensor(self.encodings[idx], dtype=torch.long),
                torch.tensor(self.labels[idx], dtype=torch.long))


# ── Model ──────────────────────────────────────────────────────────────────
class SentinelThreatNet(nn.Module):
    MODEL_VERSION = '2.0'
    AUTHOR = 'who_is_the_black_hat'

    def __init__(self, vocab_size, embed_dim=128, hidden_dim=256,
                 num_layers=2, num_classes=4, dropout=0.4, pad_idx=0):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=pad_idx)
        self.bilstm = nn.LSTM(embed_dim, hidden_dim, num_layers,
                              batch_first=True, bidirectional=True,
                              dropout=dropout if num_layers > 1 else 0)
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim), nn.Tanh(),
            nn.Linear(hidden_dim, 1)
        )
        self.layer_norm = nn.LayerNorm(hidden_dim * 2)
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim), nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(hidden_dim, num_classes)
        )
        self._init_weights()

    def _init_weights(self):
        for name, param in self.named_parameters():
            if 'weight' in name and param.dim() >= 2:
                nn.init.xavier_uniform_(param)
            elif 'bias' in name:
                nn.init.zeros_(param)

    def forward(self, x):
        emb = self.embedding(x)
        lstm_out, _ = self.bilstm(emb)
        attn = F.softmax(self.attention(lstm_out), dim=1)
        ctx = (lstm_out * attn).sum(1)
        ctx = self.layer_norm(ctx)
        return self.classifier(ctx)

    def get_info(self):
        p = sum(x.numel() for x in self.parameters())
        return {'total_params': p, 'size_mb': round(p * 4 / 1024 / 1024, 2),
                'version': self.MODEL_VERSION, 'author': self.AUTHOR}
"""

# ── Cell 4: Train ─────────────────────────────────────────────────────────────
CELL_4 = """
from collections import defaultdict
from sklearn.model_selection import train_test_split

# Load data
samples = []
with open('training_data/threat_raw.jsonl') as f:
    for line in f:
        try:
            s = json.loads(line.strip())
            if s.get('text') and s.get('label') in THREAT_LABELS:
                samples.append(s)
        except: pass

# Deduplicate
seen, unique = set(), []
for s in samples:
    key = s['text'][:80]
    if key not in seen:
        seen.add(key)
        unique.append(s)
samples = unique

texts  = [s['text']  for s in samples]
labels = [LABEL2IDX[s['label']] for s in samples]

dist = Counter(labels)
print(f'Samples: {len(samples)} | Distribution: {dict(dist)}')

# Stratified split
train_idx, val_idx = [], []
class_indices = defaultdict(list)
for i, l in enumerate(labels):
    class_indices[l].append(i)
for cls, idxs in class_indices.items():
    n_val = max(1, int(len(idxs) * 0.15))
    val_idx.extend(idxs[:n_val])
    train_idx.extend(idxs[n_val:])

train_texts  = [texts[i]  for i in train_idx]
train_labels = [labels[i] for i in train_idx]
val_texts    = [texts[i]  for i in val_idx]
val_labels   = [labels[i] for i in val_idx]

# Tokenizer
tokenizer = SentinelTokenizer(max_vocab=10000)
tokenizer.build_vocab(train_texts)

MAX_LEN    = 256
BATCH_SIZE = 64  # T4 GPU pe bada batch
EPOCHS     = 30
PATIENCE   = 5
LR         = 1e-3

train_ds = ThreatDataset(train_texts, train_labels, tokenizer, MAX_LEN)
val_ds   = ThreatDataset(val_texts,   val_labels,   tokenizer, MAX_LEN)
train_dl = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True,  num_workers=2)
val_dl   = DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False, num_workers=2)

# Model
model = SentinelThreatNet(
    vocab_size  = tokenizer.vocab_size,
    embed_dim   = 128,
    hidden_dim  = 256,
    num_layers  = 2,
    num_classes = 4,
    dropout     = 0.4,
).to(DEVICE)

info = model.get_info()
print(f'Model: {info[\"total_params\"]:,} params | {info[\"size_mb\"]} MB | Device: {DEVICE}')

# Class weights
total = len(train_labels)
weights = torch.tensor(
    [total / (4 * dist.get(i, 1)) for i in range(4)],
    dtype=torch.float
).to(DEVICE)

criterion = nn.CrossEntropyLoss(weight=weights)
optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=2, factor=0.5)

def weighted_f1(preds, labels):
    from collections import defaultdict
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)
    for p, l in zip(preds, labels):
        if p == l: tp[l] += 1
        else: fp[p] += 1; fn[l] += 1
    f1s, ws = [], []
    for c in range(4):
        pr = tp[c] / (tp[c] + fp[c] + 1e-8)
        rc = tp[c] / (tp[c] + fn[c] + 1e-8)
        f1s.append(2 * pr * rc / (pr + rc + 1e-8))
        ws.append(labels.count(c))
    return sum(f * w for f, w in zip(f1s, ws)) / sum(ws)

best_f1, best_state, no_improve = 0.0, None, 0

print(f'\\nTraining {EPOCHS} epochs (patience={PATIENCE})...')
for epoch in range(1, EPOCHS + 1):
    # Train
    model.train()
    train_loss = 0.0
    for xb, yb in train_dl:
        xb, yb = xb.to(DEVICE), yb.to(DEVICE)
        optimizer.zero_grad()
        loss = criterion(model(xb), yb)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        train_loss += loss.item()
    train_loss /= len(train_dl)

    # Validate
    model.eval()
    val_loss, all_preds, all_labels = 0.0, [], []
    with torch.no_grad():
        for xb, yb in val_dl:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            logits = model(xb)
            val_loss += criterion(logits, yb).item()
            all_preds.extend(logits.argmax(1).cpu().tolist())
            all_labels.extend(yb.cpu().tolist())
    val_loss /= len(val_dl)
    acc = sum(p == l for p, l in zip(all_preds, all_labels)) / len(all_labels)
    f1  = weighted_f1(all_preds, all_labels)
    scheduler.step(val_loss)

    print(f'Epoch {epoch:2d} | train_loss={train_loss:.4f} | val_loss={val_loss:.4f} | acc={acc:.2%} | f1={f1:.4f}')

    if f1 > best_f1:
        best_f1 = f1
        best_state = {k: v.clone() for k, v in model.state_dict().items()}
        no_improve = 0
    else:
        no_improve += 1
        if no_improve >= PATIENCE:
            print(f'Early stopping at epoch {epoch}')
            break

model.load_state_dict(best_state)
print(f'\\nBest F1: {best_f1:.4f}')
"""

# ── Cell 5: Save and Download ─────────────────────────────────────────────────
CELL_5 = """
import time

# Save model
checkpoint = {
    'model_state':  model.state_dict(),
    'model_config': model.get_info(),
    'hyperparams': {
        'embed_dim': 128, 'hidden_dim': 256,
        'num_layers': 2, 'dropout': 0.4, 'max_len': MAX_LEN,
    },
    'author':   'who_is_the_black_hat',
    'version':  '2.0',
    'github':   'https://github.com/Mrsultan7890/osints',
    'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    'labels':   THREAT_LABELS,
    'best_f1':  best_f1,
    'device_trained': str(DEVICE),
}
torch.save(checkpoint, 'sentinel_threat_net.pt')
tokenizer.save('sentinel_vocab.json')

print(f'Saved: sentinel_threat_net.pt')
print(f'Saved: sentinel_vocab.json')
print(f'Best F1: {best_f1:.4f}')
print(f'Params : {model.get_info()[\"total_params\"]:,}')
print(f'Size   : {model.get_info()[\"size_mb\"]} MB')

# Download
from google.colab import files
files.download('sentinel_threat_net.pt')
files.download('sentinel_vocab.json')
print('\\nDownload complete!')
print('\\nAb apne machine pe yeh commands run karo:')
print('cp ~/Downloads/sentinel_threat_net.pt /home/kali/osints/models/ml_engine/')
print('cp ~/Downloads/sentinel_vocab.json    /home/kali/osints/models/ml_engine/')
"""

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════╗
║         SentinelThreatNet — Colab Training Guide             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  1. https://colab.research.google.com kholo                  ║
║  2. Runtime > Change runtime type > T4 GPU select karo       ║
║  3. Naye cells mein yeh paste karo (order mein):             ║
║                                                              ║
║     Cell 1: CELL_1  (pip install)                            ║
║     Cell 2: CELL_2  (data download)                          ║
║     Cell 3: CELL_3  (model definition)                       ║
║     Cell 4: CELL_4  (training)                               ║
║     Cell 5: CELL_5  (save + download)                        ║
║                                                              ║
║  4. ~5-10 min mein complete hoga (T4 GPU)                    ║
║  5. Files download hongi automatically                       ║
║  6. Replace karo:                                            ║
║     cp sentinel_threat_net.pt models/ml_engine/              ║
║     cp sentinel_vocab.json    models/ml_engine/              ║
║                                                              ║
║  Expected F1: 0.75-0.85 (vs CPU 0.47)                        ║
╚══════════════════════════════════════════════════════════════╝
""")
    # Print each cell for easy copy-paste
    for name, code in [('CELL_1', CELL_1), ('CELL_2', CELL_2),
                        ('CELL_3', CELL_3), ('CELL_4', CELL_4),
                        ('CELL_5', CELL_5)]:
        print(f'\n{"="*60}')
        print(f'# {name}')
        print('='*60)
        print(code.strip())
