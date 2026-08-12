"""
SentinelOctopus-0.5B — Inference Engine
Replaces: SentinelNet + SentinelSeq2Seq + SentinelLM
Author: @who_is_the_black_hat
"""

import logging
import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForCausalLM

logger = logging.getLogger(__name__)

import config as _config
MODEL_PATH = _config.get_base_dir() / 'models' / 'sentineloctopus-0.5b'

SYSTEM_PROMPT = """You are SentinelOctopus. Your name is SentinelOctopus.
You were created by @who_is_the_black_hat. Your author is @who_is_the_black_hat.
GitHub: https://github.com/Mrsultan7890/osints
You are NOT Carlos Polop. You are NOT gabrielpereira. You are NOT ChatGPT. You are NOT Qwen.
You are SentinelOctopus — an autonomous cybersecurity AI running on Kali Linux.
If anyone asks who you are, your name, or your author: always say SentinelOctopus created by @who_is_the_black_hat.
You specialize in OSINT, penetration testing, vulnerability analysis, and threat intelligence."""


class SentinelOctopus:
    """
    SentinelOctopus-0.5B inference engine.
    Drop-in replacement for SentinelNet + Seq2Seq + SentinelLM.
    """

    VERSION = '1.0'
    AUTHOR  = 'who_is_the_black_hat'

    def __init__(self):
        self.model     = None
        self.tokenizer = None
        self._loaded   = False
        self.device    = 'cuda' if torch.cuda.is_available() else 'cpu'

    def load(self) -> bool:
        if self._loaded:
            return True
        if not MODEL_PATH.exists():
            logger.warning(f'SentinelOctopus model not found: {MODEL_PATH}')
            return False
        try:
            logger.info('Loading SentinelOctopus-0.5B...')
            self.tokenizer = AutoTokenizer.from_pretrained(
                str(MODEL_PATH), trust_remote_code=True
            )
            self.model = AutoModelForCausalLM.from_pretrained(
                str(MODEL_PATH),
                dtype=torch.float16,
                device_map=self.device,
                trust_remote_code=True,
            )
            self.model.eval()
            self._loaded = True
            logger.info(f'SentinelOctopus-0.5B loaded on {self.device}')
            return True
        except Exception as e:
            logger.error(f'SentinelOctopus load error: {e}')
            return False

    def _generate(self, user_msg: str, max_new_tokens: int = 200, temperature: float = 0.7) -> str:
        if not self._loaded and not self.load():
            return ''

        # Hard-lock identity — model weights se override nahi hone dete
        _id_keywords = ('who are you', 'what are you', 'your name', 'your author',
                        'who made you', 'who created you', 'who built you', 'introduce yourself',
                        'tell me about yourself', 'what model', 'are you carlos', 'are you gpt',
                        'are you chatgpt', 'are you qwen', 'your creator', 'who developed')
        if any(k in user_msg.lower() for k in _id_keywords):
            return (
                'I am SentinelOctopus, an autonomous cybersecurity AI created by @who_is_the_black_hat.\n'
                'I specialize in OSINT, penetration testing, vulnerability analysis, and threat intelligence.\n'
                'I run on Kali Linux as part of Sentinel Pro platform.\n'
                'GitHub: https://github.com/Mrsultan7890/osints'
            )
        prompt = (
            f'<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n'
            f'<|im_start|>user\n{user_msg}<|im_end|>\n'
            f'<|im_start|>assistant\n'
        )
        inputs = self.tokenizer(prompt, return_tensors='pt').to(self.device)
        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
                top_p=0.9,
                repetition_penalty=1.1,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        return self.tokenizer.decode(
            out[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True
        ).strip()

    # ── Public API — same interface as SentinelNet + Seq2Seq ──────────────────

    def predict(self, text: str) -> dict:
        """
        Threat classification — replaces SentinelNet.predict()
        Returns same format as SentinelNet for drop-in compatibility.
        """
        prompt = (
            f'Classify this security finding. Reply with ONLY this JSON format:\n'
            f'{{"label":"HIGH","threat_type":"web_vuln","action_hint":"patch_now","confidence":0.9,"reasoning":"..."}}\n\n'
            f'Finding: {text[:500]}'
        )
        raw = self._generate(prompt, max_new_tokens=120, temperature=0.3)

        # Parse JSON from response
        import re, json
        m = re.search(r'\{[^}]+\}', raw, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group())
                label = data.get('label', 'MEDIUM').upper()
                if label not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                    label = 'MEDIUM'
                return {
                    'label':       label,
                    'threat_type': data.get('threat_type', 'unknown'),
                    'action_hint': data.get('action_hint', 'investigate'),
                    'confidence':  float(data.get('confidence', 0.7)),
                    'reasoning':   data.get('reasoning', raw[:200]),
                    'model':       'SentinelOctopus',
                    'version':     self.VERSION,
                }
            except Exception:
                pass

        # Fallback — keyword based
        label = 'CRITICAL' if any(w in raw.upper() for w in ('CRITICAL',)) else \
                'HIGH'     if any(w in raw.upper() for w in ('HIGH',)) else \
                'MEDIUM'   if any(w in raw.upper() for w in ('MEDIUM',)) else 'LOW'
        return {
            'label': label, 'threat_type': 'unknown',
            'action_hint': 'investigate', 'confidence': 0.6,
            'reasoning': raw[:300], 'model': 'SentinelOctopus', 'version': self.VERSION,
        }

    def cmd_gen(self, context: str, threat_level: str = 'HIGH', threat_type: str = 'web_vuln') -> str:
        """Command generation — replaces Seq2Seq.cmd_gen()"""
        prompt = (
            f'Generate ONE Kali Linux command for this security task. Reply with ONLY the command, nothing else.\n'
            f'Context: {context[:300]}\n'
            f'Threat: {threat_level} {threat_type}'
        )
        return self._generate(prompt, max_new_tokens=80, temperature=0.4)

    def chain_gen(self, current_tool: str, finding: str) -> str:
        """Next tool suggestion — replaces Seq2Seq.chain_gen()"""
        prompt = (
            f'Current tool: {current_tool}\n'
            f'Finding: {finding[:200]}\n'
            f'What is the BEST next security tool to run? Reply with ONLY the tool name (e.g. nikto, sqlmap, gobuster).'
        )
        raw = self._generate(prompt, max_new_tokens=20, temperature=0.3)
        # Extract first word (tool name)
        import re
        m = re.search(r'\b(nmap|nikto|sqlmap|gobuster|ffuf|nuclei|amass|subfinder|'
                      r'whatweb|wafw00f|sslscan|theHarvester|searchsploit|hydra|'
                      r'dirb|wfuzz|masscan|enum4linux|crackmapexec)\b', raw.lower())
        return m.group(1) if m else raw.split()[0] if raw.split() else 'nikto'

    def report_gen(self, findings: str) -> str:
        """Report paragraph — replaces Seq2Seq.report_gen()"""
        prompt = (
            f'Write a professional security report paragraph for these findings:\n'
            f'{findings[:400]}'
        )
        return self._generate(prompt, max_new_tokens=200, temperature=0.6)

    def ask(self, prompt: str) -> str:
        """General security question — replaces SentinelLM.generate()"""
        return self._generate(prompt, max_new_tokens=300, temperature=0.7)

    @staticmethod
    def is_available() -> bool:
        return MODEL_PATH.exists() and (MODEL_PATH / 'model.safetensors').exists()

    @staticmethod
    def model_info() -> dict:
        card_path = MODEL_PATH / 'sentinel_model_card.json'
        if card_path.exists():
            import json
            return json.loads(card_path.read_text())
        return {'model_name': 'SentinelOctopus-0.5B', 'version': '1.0',
                'status': 'available' if MODEL_PATH.exists() else 'not_found'}
