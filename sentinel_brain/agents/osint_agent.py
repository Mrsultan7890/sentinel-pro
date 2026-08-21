"""
OSINT Agent v3 — AI-Driven Open Source Intelligence
===================================================
Uses LLM to dynamically select and execute OSINT tools (sherlock,
holehe, phoneinfoga, etc.) based on target type.

Author: @who_is_the_black_hat
"""

import re
import logging
import shutil
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


def _tool_available(name: str) -> bool:
    """Check if a CLI tool is installed."""
    return shutil.which(name) is not None


class OsintAgent:
    NAME = 'osint_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel
        self.terminal = kali
        from modules.ml_engine.groq_llm import get_groq
        self._groq = get_groq()

    def run(self, target: str, target_type: str = None) -> dict:
        target_type = target_type or self._detect_type(target)
        if target_type == 'domain':
            return {'_agent_summary': 'domain target — osint skipped', '_risk': 'LOW', 'success': True}
        logger.info(f"[OsintAgent] {target_type} on {target}")

        plan = self._build_plan(target, target_type)
        logger.info(f"[OsintAgent] Plan: {plan.get('steps', [])}")

        chain_results = self._execute_chain(target, plan, target_type)

        result = self._aggregate_results(chain_results, target_type)

        risk     = result.get('risk_level', 'LOW')
        profiles = len(result.get('social_profiles', []))
        summary  = f"{target_type} OSINT: {profiles} profiles, risk={risk}"

        self.memory.remember_scan(target, f'osint_{target_type}', risk, summary, result)
        self.memory.remember_decision(target, self.NAME, f'osint_{target_type}', 'OSINT', summary)

        if result.get('total_breaches', 0) > 0:
            self.memory.remember_finding(target, self.NAME, 'HIGH',
                'Breach Data', f"{result.get('total_breaches',0)} breaches", 'Passwords change karo, 2FA enable karo')

        result['_agent_summary'] = summary
        result['_risk']          = risk
        result['_target_type']   = target_type
        result['chain_results']  = chain_results

        # Groq
        if self._groq and target_type == 'person':
            profiles_list = result.get('social_profiles', [])
            if profiles_list:
                try:
                    platform_list = ', '.join(p['platform'] for p in profiles_list[:5])
                    groq_summary = self._groq.ask(
                        f"OSINT target found on: {platform_list}. Risk level: {risk}. In 1 sentence: what is the OSINT threat profile of this person?",
                        max_tokens=80
                    )
                    if groq_summary:
                        result['_groq_profile'] = groq_summary
                except Exception as e:
                    logger.debug(f"[OsintAgent] Groq profile failed: {e}")

        return result

    def _detect_type(self, target: str) -> str:
        if re.match(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', target):
            return 'email'
        if re.match(r'\+?\d{10,15}$', target.replace(' ', '')):
            return 'phone'
        if target.endswith(('.jpg', '.jpeg', '.png', '.webp')):
            return 'image'
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$', target):
            return 'domain'
        # username — has underscores/hyphens, no spaces, no dots suggesting domain
        if re.match(r'^[a-zA-Z][\w._-]{2,}$', target) and '.' not in target:
            return 'username'
        return 'person'

    def _build_plan(self, target: str, target_type: str) -> dict:
        # Strict defaults per type — only use tools that are actually installed
        candidates = {
            'person':   ['maigret', 'sherlock'],
            'username': ['sherlock', 'maigret'],
            'email':    ['holehe', 'mx'],
            'phone':    ['phoneinfoga'],
            'image':    ['exiftool'],
        }
        all_steps = candidates.get(target_type, ['sherlock'])
        # Filter to only installed tools
        available = [t for t in all_steps if _tool_available(t) or t == 'mx']
        if not available:
            logger.warning(f'[OsintAgent] No tools available for {target_type} — tried: {all_steps}')
            available = ['web_search']  # fallback: passive web search
        return {'steps': available, 'reason': f'OSINT chain for {target_type}'}

    def _execute_chain(self, target: str, plan: dict, target_type: str) -> dict:
        results = {}
        steps   = plan.get('steps', [])
        domain  = target.split('@')[-1] if target_type == 'email' else ''

        TOOL_CMDS = {
            'sherlock':    f'sherlock {target} --timeout 10 --print-found 2>/dev/null | head -80',
            'maigret':     f'maigret {target} --print-found --no-color 2>/dev/null | head -80',
            'holehe':      f'holehe {target} 2>/dev/null | head -80',
            'mx':          f'dig +short MX {domain}',
            'phoneinfoga': f'phoneinfoga scan -n "{target}" 2>/dev/null | head -80',
            'exiftool':    f'exiftool "{target}" 2>/dev/null',
        }

        for step in steps[:6]:
            tool_name = step.get('tool', '') if isinstance(step, dict) else step
            cmd       = step.get('command', TOOL_CMDS.get(tool_name)) if isinstance(step, dict) else TOOL_CMDS.get(tool_name)

            # web_search fallback — passive Groq-based search
            if tool_name == 'web_search':
                results['web_search'] = self._groq_web_search(target, target_type)
                continue

            if not tool_name or not cmd:
                continue

            # Skip if tool not installed
            if not _tool_available(tool_name) and tool_name not in ('mx',):
                logger.warning(f'[OsintAgent] {tool_name} not installed — skipping')
                results[tool_name] = {'stdout': '', 'success': False,
                                      'error': f'{tool_name} not installed'}
                continue

            logger.info(f'[OsintAgent] Running: {tool_name}')
            r = self.kali.run(cmd, timeout=120)
            results[tool_name] = {
                'stdout':  r['stdout'][:4000],
                'parsed':  r.get('parsed', {}),
                'success': r['success'],
            }

            if self._groq and r['stdout'] and r['success']:
                analysis = self._groq.analyze_output(tool_name, r['stdout'], target)
                results[tool_name]['analysis'] = analysis
                next_tool = analysis.get('next_tool', '')
                custom_cmd = analysis.get('custom_command', '')

                existing_tools = [s.get('tool') if isinstance(s, dict) else s for s in steps]
                if next_tool and next_tool not in existing_tools:
                    if custom_cmd:
                        steps.append({'tool': next_tool, 'command': custom_cmd})
                        logger.info(f"[OsintAgent] Groq added custom step: {next_tool} ({custom_cmd})")
                    elif next_tool in TOOL_CMDS:
                        steps.append(next_tool)
                        logger.info(f"[OsintAgent] Groq added step: {next_tool}")

        return results

    def _groq_web_search(self, target: str, target_type: str) -> dict:
        """Passive OSINT via Groq when no tools available."""
        if not self._groq:
            return {'stdout': '', 'success': False, 'error': 'Groq not available'}
        try:
            prompt = (
                f'You are an OSINT analyst. Target: "{target}" (type: {target_type}).\n'
                f'Based on your knowledge, provide:\n'
                f'1. Likely social media platforms where this username/person may exist\n'
                f'2. Any known public information\n'
                f'3. Recommended manual search queries\n'
                f'Be factual only. If unknown, say so.'
            )
            resp = self._groq.ask(prompt, max_tokens=400)
            return {'stdout': resp, 'success': True, 'source': 'groq_passive'}
        except Exception as e:
            return {'stdout': '', 'success': False, 'error': str(e)}

    def _aggregate_results(self, chain_results: dict, target_type: str) -> dict:
        results = {'target_type': target_type, 'social_profiles': [], 'risk_level': 'LOW'}

        for tool, data in chain_results.items():
            stdout = data.get('stdout', '')
            parsed = data.get('parsed', {})

            if tool == 'sherlock':
                profiles = []
                for line in stdout.splitlines():
                    if line.startswith('[+]'):
                        url = line.replace('[+]', '').strip()
                        platform = url.split('/')[2] if '/' in url else url
                        profiles.append({'platform': platform, 'url': url})
                results['social_profiles'].extend(profiles)
                results['sherlock_raw'] = stdout
            elif tool == 'maigret':
                # Parse maigret found lines
                profiles = []
                for line in stdout.splitlines():
                    if '[+]' in line or 'Found' in line:
                        profiles.append({'platform': line.strip(), 'url': ''})
                results['social_profiles'].extend(profiles)
                results['maigret_raw'] = stdout
            elif tool == 'holehe':
                results['holehe_raw'] = stdout
            elif tool == 'mx':
                results['mx'] = parsed
            elif tool == 'phoneinfoga':
                results['phoneinfoga_raw'] = stdout
            elif tool == 'web_search':
                results['passive_intel'] = stdout
                if stdout:
                    results['risk_level'] = 'LOW'
            elif data.get('error'):
                results[f'{tool}_error'] = data['error']

        if results['social_profiles']:
            results['risk_level'] = 'MEDIUM'
        if len(results['social_profiles']) > 5:
            results['risk_level'] = 'HIGH'

        return results
