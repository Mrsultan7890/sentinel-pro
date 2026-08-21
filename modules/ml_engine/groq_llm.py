"""
Groq LLM Integration — Primary Reasoning Layer
==================================================
Groq API se Llama-3.3-70B use karo — free tier available.
Brain ke liye reasoning, planning, aur natural language understanding.

Author: @who_is_the_black_hat
"""

import json
import logging
import re
import time
import threading

import config

logger = logging.getLogger(__name__)

TOOLS = [
    'nmap', 'nikto', 'nuclei', 'sqlmap', 'gobuster', 'ffuf',
    'amass', 'subfinder', 'whatweb', 'wafw00f', 'sslscan',
    'theHarvester', 'searchsploit', 'commix', 'wpscan',
    'enum4linux', 'hydra', 'masscan', 'hashcat', 'john',
    'msfconsole', 'msfvenom', 'msfdb',
    'volatility', 'autopsy', 'sleuthkit', 'foremost', 'scalpel',
    'binwalk', 'yara', 'strings', 'dd', 'tcpdump', 'wireshark',
    'aircrack-ng', 'airmon-ng', 'reaver', 'ettercap', 'hping3',
]

SYSTEM_PROMPT = """You are SentinelOctopus, an autonomous security AI running on Kali Linux.
You help with:
1. Security tool command generation (nmap, nikto, sqlmap, nuclei, gobuster, etc.)
2. Attack chain planning (which tool to use next)
3. Vulnerability analysis and report generation
4. OSINT investigations

Rules:
- Always use TARGET_DOMAIN as placeholder for actual targets
- Be concise — commands only, no explanations unless asked
- For chain_gen: return ONLY the tool name, nothing else
- For cmd_gen: return ONLY the exact command
- For report_gen: return a professional security report paragraph
- Support Urdu/Hindi/English prompts"""


class GroqLLM:
    """
    Groq API wrapper — Llama-3.3-70B-Versatile.

    Usage:
        llm = GroqLLM()
        cmd  = llm.cmd_gen('web server port 80 open HIGH web_vuln')
        tool = llm.chain_gen('nmap', 'open web port 80 detected')
        rpt  = llm.report_gen('sql injection found', 'CRITICAL')
        plan = llm.plan('example.com', 'full pentest')
        ans  = llm.ask('example.com ke ports scan karo')
    """

    MODEL    = 'openai/gpt-oss-20b'
    FALLBACK = 'qwen/qwen3.6-27b'

    def __init__(self):
        self._client  = None
        self._ready   = False
        self._api_key = getattr(config, 'GROQ_API_KEY', '')
        
        if not self._api_key or not isinstance(self._api_key, str):
            logger.warning('GROQ_API_KEY not configured or invalid')
            return
        
        if self._api_key.startswith('<') or len(self._api_key) < 20:
            logger.warning('GROQ_API_KEY appears to be placeholder')
            return
        
        if self._api_key:
            self._init_client()

    def _init_client(self):
        try:
            from groq import Groq
            self._client = Groq(api_key=self._api_key)
            self._ready  = True
            logger.info(f'GroqLLM ready — model={self.MODEL}')
        except ImportError as e:
            logger.warning(f'groq package missing — pip install groq: {e}')
        except (ValueError, TypeError) as e:
            logger.error(f'Invalid API key format: {e}')
        except Exception as e:
            logger.error(f'GroqLLM init error: {e}')

    def _call(self, messages: list, max_tokens: int = 200,
              temperature: float = 0.3) -> str:
        if not self._ready:
            return ''
        if not messages or not isinstance(messages, list):
            logger.error('Invalid messages format')
            return ''
        if max_tokens <= 0 or max_tokens > 4096:
            max_tokens = 200
        if temperature < 0 or temperature > 2:
            temperature = 0.3
        
        for model in (self.MODEL, self.FALLBACK):
            try:
                resp = self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                if resp and resp.choices and len(resp.choices) > 0:
                    text = resp.choices[0].message.content.strip()
                    # strip <think>...</think> blocks (reasoning models like qwen)
                    text = re.sub(r'<think>.*?</think>\s*', '', text, flags=re.DOTALL).strip()
                    # if think block was not closed (truncated output), discard it entirely
                    if '<think>' in text:
                        after = text.split('</think>')
                        if len(after) > 1:
                            text = after[-1].strip()
                        else:
                            # think block never closed — no useful content
                            text = ''
                    return text
                return ''
            except (ConnectionError, TimeoutError) as e:
                logger.error(f'Network error on {model}: {e}')
                time.sleep(2)
                continue
            except Exception as e:
                err = str(e).lower()
                if 'rate' in err or '429' in err:
                    logger.warning(f'Rate limit on {model}, trying fallback...')
                    time.sleep(2)
                    continue
                if 'decommissioned' in err or '400' in err:
                    logger.warning(f'Model {model} decommissioned, trying fallback...')
                    continue
                logger.error(f'Groq call error ({model}): {e}')
                return ''
        # All models failed — SentinelOctopus fallback
        try:
            from modules.ml_engine.sentinel_octopus import SentinelOctopus
            oc = SentinelOctopus()
            if oc.load():
                text = messages[-1].get('content', '')[:200]
                pred = oc.predict(text)
                return f"{pred.get('label','')} {pred.get('threat_type','')} {pred.get('action_hint','')}"
        except Exception as e:
            logger.debug(f'SentinelOctopus fallback failed: {e}')
        return ''

    def ask(self, prompt: str, max_tokens: int = 1024) -> str:
        """General purpose — any language prompt."""
        if not prompt or not isinstance(prompt, str):
            logger.error('Invalid prompt')
            return ''
        if len(prompt) > 10000:
            prompt = prompt[:10000]
        
        messages = [
            {'role': 'system',  'content': SYSTEM_PROMPT},
            {'role': 'user',    'content': prompt},
        ]
        return self._call(messages, max_tokens=max_tokens, temperature=0.4)

    def cmd_gen(self, context: str, threat_level: str = 'HIGH',
                threat_type: str = 'web_vuln') -> str:
        """Context → exact kali command."""
        prompt = (
            f"Generate ONLY the exact Kali Linux command (no explanation):\n"
            f"Context: {context}\n"
            f"Threat: {threat_level} | Type: {threat_type}"
        )
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': prompt},
        ]
        out = self._call(messages, max_tokens=100, temperature=0.2)
        out = re.sub(r'^```\w*\n?', '', out).rstrip('`').strip()
        return out.split('\n')[0].strip()

    def chain_gen(self, current_tool: str, finding: str) -> str:
        """Current tool + finding → next tool name only."""
        prompt = (
            f"Current tool: {current_tool}\n"
            f"Finding: {finding}\n"
            f"Reply with ONLY the next tool name from this list:\n"
            f"{', '.join(TOOLS)}"
        )
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': prompt},
        ]
        out = self._call(messages, max_tokens=10, temperature=0.1)
        out = out.strip().lower().split()[0] if out.strip() else ''
        return out if out in TOOLS else ''

    def report_gen(self, findings: str, severity: str = 'HIGH',
                   threat_type: str = 'web_vuln') -> str:
        """Findings → professional security report paragraph."""
        prompt = (
            f"Write a professional security report paragraph for:\n"
            f"Findings: {findings}\n"
            f"Severity: {severity} | Type: {threat_type}\n"
            f"Use TARGET_DOMAIN as placeholder."
        )
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': prompt},
        ]
        return self._call(messages, max_tokens=200, temperature=0.5)

    def plan(self, target: str, objective: str = 'full recon') -> dict:
        """Target + objective → structured scan plan."""
        if not target or not isinstance(target, str):
            return {'steps': ['nmap'], 'reason': 'Invalid target'}
        if not objective or not isinstance(objective, str):
            objective = 'full recon'
        
        prompt = (
            f"Create a security scan plan for: {target}\n"
            f"Objective: {objective}\n\n"
            f"Reply in JSON format:\n"
            f'{{"steps": [{{"tool": "tool_name", "command": "exact bash command to run"}}, ...], "reason": "brief explanation"}}\n'
            f"Use only tools from: {', '.join(TOOLS)}"
        )
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': prompt},
        ]
        out = self._call(messages, max_tokens=300, temperature=0.3)
        try:
            m = re.search(r'\{.*\}', out, re.DOTALL)
            if m:
                data = json.loads(m.group())
                if isinstance(data, dict) and 'steps' in data:
                    return data
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f'JSON parse error in plan: {e}')
        except Exception as e:
            logger.error(f'Unexpected error in plan: {e}')
        tools_found = [t for t in TOOLS if t in out.lower()]
        return {'steps': tools_found or ['nmap', 'nikto', 'nuclei'],
                'reason': out[:200]}

    def analyze_output(self, tool: str, output: str, target: str) -> dict:
        """Tool output → structured analysis."""
        if not tool or not isinstance(tool, str):
            return {'risk': 'MEDIUM', 'findings': [], 'next_tool': '', 'summary': 'Invalid tool'}
        if not output or not isinstance(output, str):
            return {'risk': 'LOW', 'findings': [], 'next_tool': '', 'summary': 'No output'}
        if not target or not isinstance(target, str):
            target = 'TARGET_DOMAIN'
        
        prompt = (
            f"Analyze this {tool} output for target {target}:\n"
            f"{output[:4000]}\n\n"
            f"Reply in JSON:\n"
            f'{{"risk": "LOW/MEDIUM/HIGH/CRITICAL", '
            f'"findings": ["finding1", ...], '
            f'"next_tool": "tool_name", '
            f'"custom_command": "exact bash command for next tool", '
            f'"summary": "brief"}}'
        )
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': prompt},
        ]
        out = self._call(messages, max_tokens=300, temperature=0.2)
        try:
            m = re.search(r'\{.*\}', out, re.DOTALL)
            if m:
                data = json.loads(m.group())
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f'JSON parse error in analyze_output: {e}')
        except Exception as e:
            logger.error(f'Unexpected error in analyze_output: {e}')
        return {'risk': 'MEDIUM', 'findings': [], 'next_tool': '', 'summary': out[:200]}

    @property
    def is_ready(self) -> bool:
        return self._ready

    @staticmethod
    def is_available() -> bool:
        key = getattr(config, 'GROQ_API_KEY', '')
        return bool(key)


# ── Singleton — ek baar load, sab jagah use ───────────────────────────────────
# Sab agents yahi use karein: from modules.ml_engine.groq_llm import get_groq
_groq_instance = None
_groq_lock     = threading.Lock()

def get_groq():
    """
    Shared GroqLLM instance — lazy init, thread-safe.
    Returns None if GROQ_API_KEY not set or groq package missing.
    """
    global _groq_instance
    if _groq_instance is not None:
        return _groq_instance
    with _groq_lock:
        if _groq_instance is not None:
            return _groq_instance
        try:
            if not GroqLLM.is_available():
                return None
            g = GroqLLM()
            if g.is_ready:
                _groq_instance = g
                logger.info('get_groq(): singleton initialized')
        except Exception as e:
            logger.debug(f'get_groq() init failed: {e}')
    return _groq_instance
