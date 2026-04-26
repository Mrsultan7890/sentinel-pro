"""
SentinelLM v1.0 — Custom Transformer Language Model
=====================================================
Custom GPT-style model trained from scratch.
35.5M params · 6 layers · 8 heads · d_model=512
vocab=32K BPE · ctx_len=512

Usage:
    from modules.ml_engine.sentinel_lm import SentinelLM
    lm = SentinelLM()
    lm.load()
    out = lm.generate('scan example.com for open ports')
    cmd = lm.cmd_gen('find subdomains of example.com')

Author: @who_is_the_black_hat
"""

import json
import logging
import math
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parents[2] / 'models' / 'ml_engine'
MODEL_PATH = MODELS_DIR / 'sentinellm_v1.pt'
VOCAB_PATH = MODELS_DIR / 'sentinellm_vocab.json'

# ── Model Architecture ────────────────────────────────────────────────────────

class CausalSelfAttention(nn.Module):
    def __init__(self, d_model: int, n_heads: int, dropout: float):
        super().__init__()
        self.n_heads = n_heads
        self.d_head  = d_model // n_heads
        self.qkv     = nn.Linear(d_model, 3 * d_model, bias=False)
        self.out_proj = nn.Linear(d_model, d_model, bias=False)
        self.drop    = nn.Dropout(dropout)

    def forward(self, x, mask=None):
        B, T, C = x.shape
        qkv = self.qkv(x).reshape(B, T, 3, self.n_heads, self.d_head)
        qkv = qkv.permute(2, 0, 3, 1, 4)
        q, k, v = qkv[0], qkv[1], qkv[2]

        scale = math.sqrt(self.d_head)
        att   = (q @ k.transpose(-2, -1)) / scale
        if mask is not None:
            att = att.masked_fill(mask[:, :, :T, :T] == 0, float('-inf'))
        att = F.softmax(att, dim=-1)
        att = self.drop(att)
        out = (att @ v).transpose(1, 2).reshape(B, T, C)
        return self.out_proj(out)


class TransformerBlock(nn.Module):
    def __init__(self, d_model: int, n_heads: int, d_ff: int, dropout: float):
        super().__init__()
        self.ln1  = nn.LayerNorm(d_model)
        self.attn = CausalSelfAttention(d_model, n_heads, dropout)
        self.ln2  = nn.LayerNorm(d_model)
        self.ff   = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model),
            nn.Dropout(dropout),
        )

    def forward(self, x, mask=None):
        x = x + self.attn(self.ln1(x), mask)
        x = x + self.ff(self.ln2(x))
        return x


class SentinelTransformer(nn.Module):
    def __init__(self, vocab_size, n_layers, n_heads, d_model, d_ff, dropout, ctx_len):
        super().__init__()
        self.tok_emb  = nn.Embedding(vocab_size, d_model)
        self.pos_emb  = nn.Embedding(ctx_len, d_model)
        self.drop     = nn.Dropout(dropout)
        self.blocks   = nn.ModuleList([
            TransformerBlock(d_model, n_heads, d_ff, dropout)
            for _ in range(n_layers)
        ])
        self.ln_final = nn.LayerNorm(d_model)
        self.lm_head  = nn.Linear(d_model, vocab_size, bias=False)
        # Causal mask
        mask = torch.tril(torch.ones(ctx_len, ctx_len)).unsqueeze(0).unsqueeze(0)
        self.register_buffer('mask', mask)

    def forward(self, idx):
        B, T = idx.shape
        pos  = torch.arange(T, device=idx.device)
        x    = self.drop(self.tok_emb(idx) + self.pos_emb(pos))
        for block in self.blocks:
            x = block(x, self.mask)
        x    = self.ln_final(x)
        return self.lm_head(x)


# ── BPE Tokenizer ─────────────────────────────────────────────────────────────

class BPETokenizer:
    """Minimal BPE tokenizer compatible with sentinellm_vocab.json."""

    def __init__(self, vocab: dict, special_tokens: dict):
        self.vocab    = vocab                          # token → id
        self.inv      = {v: k for k, v in vocab.items()}  # id → token
        self.pad_id   = special_tokens.get('pad_id', 0)
        self.bos_id   = special_tokens.get('bos_id', 2)
        self.eos_id   = special_tokens.get('eos_id', 3)
        self.unk_id   = special_tokens.get('unk_id', 1)

    def encode(self, text: str, add_special: bool = True) -> list:
        """Char-level fallback tokenizer — works without tokenizers library."""
        ids = []
        if add_special:
            ids.append(self.bos_id)
        # Simple char-level encoding as fallback
        for ch in text:
            ids.append(self.vocab.get(ch, self.unk_id))
        if add_special:
            ids.append(self.eos_id)
        return ids

    def encode_fast(self, text: str, add_special: bool = True) -> list:
        """Use tokenizers library for proper BPE."""
        try:
            from tokenizers import Tokenizer
            tok = Tokenizer.from_file(str(VOCAB_PATH))
            enc = tok.encode(text)
            # post_processor already adds bos/eos via TemplateProcessing
            return enc.ids
        except Exception:
            return self.encode(text, add_special)

    def decode(self, ids: list) -> str:
        try:
            from tokenizers import Tokenizer
            tok = Tokenizer.from_file(str(VOCAB_PATH))
            clean = [i for i in ids if i not in (self.pad_id, self.bos_id, self.eos_id)]
            result = tok.decode(clean)
            # Clean up Ġ artifacts if any remain
            result = result.replace('Ġ', ' ').replace('Ċ', '\n').strip()
            return result
        except Exception:
            tokens = []
            for i in ids:
                if i in (self.bos_id, self.eos_id, self.pad_id):
                    continue
                t = self.inv.get(i, '')
                if t.startswith('Ġ'):
                    tokens.append(' ' + t[1:])
                elif t == 'Ċ':
                    tokens.append('\n')
                else:
                    tokens.append(t)
            return ''.join(tokens).strip()


# ── SentinelLM Inference Engine ───────────────────────────────────────────────

SYSTEM_PROMPT = (
    "### System: You are SentinelLM, an autonomous security AI on Kali Linux. "
    "Generate exact commands, plans, and reports for security tasks.\n"
)


class SentinelLM:
    """
    SentinelLM v1.0 inference engine.
    Custom 35.5M param Transformer — no external API needed.
    """

    def __init__(self):
        self._model     = None
        self._tokenizer = None
        self._config    = None
        self._loaded    = False
        self._device    = 'cpu'

    def load(self) -> bool:
        if self._loaded:
            return True
        if not MODEL_PATH.exists():
            logger.warning(f'[SentinelLM] Model not found: {MODEL_PATH}')
            return False
        if not VOCAB_PATH.exists():
            logger.warning(f'[SentinelLM] Vocab not found: {VOCAB_PATH}')
            return False
        try:
            ck = torch.load(str(MODEL_PATH), map_location='cpu', weights_only=False)
            cfg = ck['config']
            self._config = cfg

            model = SentinelTransformer(
                vocab_size = cfg['vocab_size'],
                n_layers   = cfg['n_layers'],
                n_heads    = cfg['n_heads'],
                d_model    = cfg['d_model'],
                d_ff       = cfg['d_ff'],
                dropout    = 0.0,   # inference — no dropout
                ctx_len    = cfg['ctx_len'],
            )
            model.load_state_dict(ck['model_state'])
            model.eval()
            self._model = model

            vocab_data = json.loads(VOCAB_PATH.read_text())
            vocab      = vocab_data.get('model', {}).get('vocab', vocab_data)
            special    = ck.get('special_tokens', {'pad_id':0,'bos_id':2,'eos_id':3,'unk_id':1})
            self._tokenizer = BPETokenizer(vocab, special)

            self._loaded = True
            logger.info(
                f'[SentinelLM] Loaded v{ck.get("version","1.0")} | '
                f'{cfg["n_layers"]}L {cfg["n_heads"]}H d{cfg["d_model"]} | '
                f'{ck.get("params",0)//1_000_000}M params | '
                f'val_loss={ck.get("best_val_loss",0):.3f}'
            )
            return True

        except Exception as e:
            logger.error(f'[SentinelLM] load error: {e}')
            return False

    def generate(
        self,
        prompt:         str,
        max_new_tokens: int   = 200,
        temperature:    float = 0.7,
        top_k:          int   = 50,
        top_p:          float = 0.9,
    ) -> str:
        """
        Generate text from prompt.

        Args:
            prompt:         Input text
            max_new_tokens: Max tokens to generate
            temperature:    Sampling temperature (0.1=deterministic, 1.0=creative)
            top_k:          Top-K sampling
            top_p:          Nucleus sampling threshold

        Returns:
            Generated text string
        """
        if not self._loaded:
            if not self.load():
                return ''
        try:
            full_prompt = SYSTEM_PROMPT + f'### Instruction: {prompt}\n### Response:'
            ids = self._tokenizer.encode_fast(full_prompt, add_special=True)
            ctx_len = self._config['ctx_len']

            # Truncate if too long
            if len(ids) > ctx_len - max_new_tokens:
                ids = ids[-(ctx_len - max_new_tokens):]

            idx = torch.tensor([ids], dtype=torch.long)
            generated = []

            with torch.no_grad():
                for _ in range(max_new_tokens):
                    # Crop to ctx_len
                    idx_cond = idx[:, -ctx_len:]
                    logits   = self._model(idx_cond)
                    logits   = logits[:, -1, :]  # last token

                    # Repetition penalty
                    if generated:
                        for prev_id in set(generated[-20:]):
                            logits[0, prev_id] /= 1.3

                    # Temperature
                    if temperature > 0:
                        logits = logits / temperature

                    # Top-K
                    if top_k > 0:
                        v, _ = torch.topk(logits, min(top_k, logits.size(-1)))
                        logits[logits < v[:, [-1]]] = float('-inf')

                    # Top-P (nucleus)
                    if top_p < 1.0:
                        sorted_logits, sorted_idx = torch.sort(logits, descending=True)
                        cum_probs = torch.cumsum(F.softmax(sorted_logits, dim=-1), dim=-1)
                        remove    = cum_probs - F.softmax(sorted_logits, dim=-1) > top_p
                        sorted_logits[remove] = float('-inf')
                        logits = torch.zeros_like(logits).scatter_(1, sorted_idx, sorted_logits)

                    probs   = F.softmax(logits, dim=-1)
                    next_id = torch.multinomial(probs, num_samples=1)

                    # Stop at EOS
                    if next_id.item() == self._tokenizer.eos_id:
                        break

                    generated.append(next_id.item())
                    idx = torch.cat([idx, next_id], dim=1)

                    # Stop at newline after Response: section
                    if len(generated) > 10:
                        decoded_so_far = self._tokenizer.decode(generated)
                        if decoded_so_far.count('\n') >= 3:
                            break

            return self._tokenizer.decode(generated).strip()

        except Exception as e:
            logger.error(f'[SentinelLM] generate error: {e}')
            return ''

    def cmd_gen(self, context: str) -> str:
        """Security context → exact Kali command."""
        return self.generate(
            f'Generate the exact Kali Linux command for: {context}',
            max_new_tokens=80,
            temperature=0.3,
        )

    def chain_gen(self, context: str) -> str:
        """Current finding → next tool name."""
        out = self.generate(
            f'What is the next security tool to use? {context}',
            max_new_tokens=15,
            temperature=0.2,
        )
        return out.split()[0].lower() if out else ''

    def report_gen(self, findings: str) -> str:
        """Findings → security report paragraph."""
        return self.generate(
            f'Generate a security report for: {findings}',
            max_new_tokens=200,
            temperature=0.6,
        )

    def plan(self, target: str, objective: str = 'full recon') -> str:
        """Target → full scan plan."""
        return self.generate(
            f'Create a security scan plan for {target}. Objective: {objective}',
            max_new_tokens=300,
            temperature=0.5,
        )

    @staticmethod
    def is_available() -> bool:
        return MODEL_PATH.exists() and VOCAB_PATH.exists()

    @staticmethod
    def get_info() -> dict:
        if not MODEL_PATH.exists():
            return {'status': 'not_found'}
        try:
            ck = torch.load(str(MODEL_PATH), map_location='cpu', weights_only=False)
            return {
                'status':        'loaded',
                'version':       ck.get('version', '1.0'),
                'params':        ck.get('params', 0),
                'size_mb':       ck.get('size_mb', 0),
                'val_loss':      ck.get('best_val_loss', 0),
                'train_samples': ck.get('train_samples', 0),
                'saved_at':      ck.get('saved_at', ''),
                'config':        ck.get('config', {}),
            }
        except Exception:
            return {'status': 'error'}
