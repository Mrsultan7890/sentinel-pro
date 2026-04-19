"""
Groq LLM Integration — SentinelLM Thinking Layer
==================================================
Groq API se Llama-3.1-70B use karo — free tier available.
Brain ke liye reasoning, planning, aur natural language understanding.

Author: @who_is_the_black_hat
"""

import json
import logging
import re
import time
from pathlib import Path

import config

logger = logging.getLogger(__name__)

TOOLS = [
    'nmap', 'nikto', 'nuclei', 'sqlmap', 'gobuster', 'ffuf',
    'amass', 'subfinder', 'whatweb', 'wafw00f', 'sslscan',
    'theHarvester', 'searchsploit', 'commix', 'wpscan',
    'enum4linux', 'hydra', 'masscan', 'hashcat', 'john',
    # Metasploit tools
    'msfconsole', 'msfvenom', 'msfdb',
    # Forensics tools
    'volatility', 'autopsy', 'sleuthkit', 'foremost', 'scalpel',
    'binwalk', 'yara', 'strings', 'dd', 'tcpdump', 'wireshark',
    # Additional security tools
    'aircrack-ng', 'airmon-ng', 'reaver', 'ettercap', 'hping3'
]

SYSTEM_PROMPT = """You are SentinelLM, an autonomous security AI running on Kali Linux.
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
    Groq API wrapper — Llama-3.1-70B-Versatile.

    Usage:
        llm = GroqLLM()
        cmd  = llm.cmd_gen('web server port 80 open HIGH web_vuln')
        tool = llm.chain_gen('nmap', 'open web port 80 detected')
        rpt  = llm.report_gen('sql injection found', 'CRITICAL')
        plan = llm.plan('example.com', 'full pentest')
        ans  = llm.ask('example.com ke ports scan karo')
    """

    MODEL    = 'llama-3.3-70b-versatile'
    FALLBACK = 'llama-3.1-8b-instant'   # agar 70b rate limit ho

    def __init__(self):
        self._client  = None
        self._ready   = False
        self._api_key = getattr(config, 'GROQ_API_KEY', '')
        if self._api_key:
            self._init_client()

    def _init_client(self):
        try:
            from groq import Groq
            self._client = Groq(api_key=self._api_key)
            self._ready  = True
            logger.info(f'GroqLLM ready — model={self.MODEL}')
        except ImportError:
            logger.warning('groq package missing — pip install groq')
        except Exception as e:
            logger.error(f'GroqLLM init error: {e}')

    def _call(self, messages: list, max_tokens: int = 200,
              temperature: float = 0.3) -> str:
        if not self._ready:
            return ''
        for model in (self.MODEL, self.FALLBACK):
            try:
                resp = self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                return resp.choices[0].message.content.strip()
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
        # All models failed — SentinelNet fallback
        try:
            from modules.ml_engine.sentinel_net import NeuralTrainer
            nt = NeuralTrainer()
            if nt.load():
                text = messages[-1].get('content', '')[:200]
                pred = nt.predict(text)
                return f"{pred.get('label','')} {pred.get('threat_type','')} {pred.get('action_hint','')}"
        except Exception:
            pass
        return ''

    def ask(self, prompt: str, max_tokens: int = 300) -> str:
        """General purpose — any language prompt."""
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
        # Sirf command return karo — backticks hata do
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
        # Sirf tool name extract karo
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
        prompt = (
            f"Create a security scan plan for: {target}\n"
            f"Objective: {objective}\n\n"
            f"Reply in JSON format:\n"
            f'{{"steps": ["tool1", "tool2", ...], "reason": "brief explanation"}}\n'
            f"Use only tools from: {', '.join(TOOLS)}"
        )
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': prompt},
        ]
        out = self._call(messages, max_tokens=300, temperature=0.3)
        try:
            # JSON extract karo
            m = re.search(r'\{.*\}', out, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        # Fallback — tools list extract karo
        tools_found = [t for t in TOOLS if t in out.lower()]
        return {'steps': tools_found or ['nmap', 'nikto', 'nuclei'],
                'reason': out[:200]}

    def analyze_output(self, tool: str, output: str, target: str) -> dict:
        """Tool output → structured analysis."""
        prompt = (
            f"Analyze this {tool} output for target {target}:\n"
            f"{output[:800]}\n\n"
            f"Reply in JSON:\n"
            f'{{"risk": "LOW/MEDIUM/HIGH/CRITICAL", '
            f'"findings": ["finding1", ...], '
            f'"next_tool": "tool_name", '
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
                return json.loads(m.group())
        except Exception:
            pass
        return {'risk': 'MEDIUM', 'findings': [], 'next_tool': '', 'summary': out[:200]}

    @property
    def is_ready(self) -> bool:
        return self._ready

    @staticmethod
    def is_available() -> bool:
        key = getattr(config, 'GROQ_API_KEY', '')
        return bool(key)
