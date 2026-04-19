"""
SentinelLM — Qwen2.5-Coder-1.5B + LoRA Inference
===================================================
Autonomous security AI for Kali Linux.

Usage:
    from modules.ml_engine.sentinel_lm import SentinelLM
    lm = SentinelLM()
    lm.load()
    cmd    = lm.generate('scan example.com for open ports')
    cmd_ur = lm.generate('example.com ke ports scan karo')
Author: @who_is_the_black_hat
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MODELS_DIR   = Path(__file__).resolve().parents[2] / 'models'
ADAPTER_DIR  = MODELS_DIR / 'sentinel_lm_adapter'
META_PATH    = ADAPTER_DIR / 'sentinel_meta.json'

BASE_MODEL   = 'Qwen/Qwen2.5-Coder-1.5B-Instruct'

SYSTEM_PROMPT = """You are SentinelLM, an autonomous security AI running on Kali Linux.
You can:
- Understand user security objectives in any language
- Generate exact Kali Linux commands for security tools
- Plan and chain security tools (nmap → nikto → nuclei → sqlmap)
- Monitor systems and analyze findings
- Generate professional security reports
Always replace TARGET_DOMAIN with the actual target."""


class SentinelLM:
    """
    SentinelLM inference engine.

    Lazy loading — model sirf pehli generate() call pe load hota hai.
    CPU pe bhi kaam karta hai (slow but functional).
    """

    def __init__(self):
        self._model     = None
        self._tokenizer = None
        self._loaded    = False
        self._device    = None

    def load(self) -> bool:
        if self._loaded:
            return True
        if not ADAPTER_DIR.exists():
            logger.warning(f'SentinelLM adapter not found: {ADAPTER_DIR}')
            logger.warning('Colab se train karke download karo: sentinel_lm_adapter.zip')
            return False
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
            from peft import PeftModel

            self._device = 'cuda' if torch.cuda.is_available() else 'cpu'
            logger.info(f'SentinelLM loading on {self._device}...')

            self._tokenizer = AutoTokenizer.from_pretrained(
                str(ADAPTER_DIR), trust_remote_code=True
            )
            self._tokenizer.pad_token = self._tokenizer.eos_token

            # GPU pe 4-bit, CPU pe float32
            if self._device == 'cuda':
                bnb_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_quant_type='nf4',
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                )
                base = AutoModelForCausalLM.from_pretrained(
                    BASE_MODEL,
                    quantization_config=bnb_config,
                    device_map='auto',
                    trust_remote_code=True,
                )
            else:
                base = AutoModelForCausalLM.from_pretrained(
                    BASE_MODEL,
                    torch_dtype=torch.float32,
                    device_map='cpu',
                    trust_remote_code=True,
                )

            self._model = PeftModel.from_pretrained(base, str(ADAPTER_DIR))
            self._model.eval()
            self._loaded = True

            meta = {}
            if META_PATH.exists():
                meta = json.load(open(META_PATH))
            logger.info(
                f"SentinelLM v{meta.get('version','1.0')} loaded | "
                f"base={meta.get('base_model','Qwen2.5-Coder-1.5B')} | "
                f"device={self._device}"
            )
            return True

        except Exception as e:
            logger.error(f'SentinelLM load error: {e}')
            return False

    def generate(
        self,
        prompt: str,
        max_new_tokens: int = 200,
        temperature: float = 0.3,
    ) -> str:
        """
        Natural language prompt → security command / plan / report.

        Args:
            prompt: User request in any language
            max_new_tokens: Max output tokens
            temperature: 0.1=deterministic, 0.7=creative

        Returns:
            Generated response string
        """
        if not self._loaded:
            if not self.load():
                return ''
        try:
            import torch
            messages = [
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user',   'content': prompt},
            ]
            text = self._tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            inputs = self._tokenizer(
                text, return_tensors='pt', truncation=True, max_length=512
            ).to(self._model.device)

            with torch.no_grad():
                out = self._model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    temperature=temperature,
                    do_sample=temperature > 0.1,
                    pad_token_id=self._tokenizer.eos_token_id,
                    repetition_penalty=1.1,
                )
            response = self._tokenizer.decode(
                out[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True,
            )
            return response.strip()

        except Exception as e:
            logger.error(f'SentinelLM generate error: {e}')
            return ''

    def cmd_gen(self, context: str) -> str:
        """Security context → exact kali command."""
        return self.generate(
            f"Generate the exact Kali Linux command for:\n{context}",
            max_new_tokens=100,
            temperature=0.2,
        )

    def chain_gen(self, context: str) -> str:
        """Current tool + finding → next tool name."""
        out = self.generate(
            f"What is the next security tool to use?\n{context}",
            max_new_tokens=20,
            temperature=0.1,
        )
        # Sirf tool name return karo
        return out.split()[0].lower() if out else ''

    def report_gen(self, findings: str) -> str:
        """Findings → security report paragraph."""
        return self.generate(
            f"Generate a security report for these findings:\n{findings}",
            max_new_tokens=200,
            temperature=0.5,
        )

    def plan(self, target: str, objective: str = 'full recon') -> str:
        """Target + objective → full scan plan."""
        return self.generate(
            f"Create a complete security scan plan for target: {target}\nObjective: {objective}",
            max_new_tokens=300,
            temperature=0.4,
        )

    @staticmethod
    def is_available() -> bool:
        return ADAPTER_DIR.exists() and META_PATH.exists()

    @staticmethod
    def get_info() -> dict:
        if not META_PATH.exists():
            return {'status': 'not_trained'}
        meta = json.load(open(META_PATH))
        return {'status': 'trained', **meta}
