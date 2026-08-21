"""
OSINT Agent v3 — AI-Driven Open Source Intelligence
===================================================
Uses LLM to dynamically select and execute OSINT tools (sherlock,
holehe, phoneinfoga, etc.) based on target type.

Author: @who_is_the_black_hat
"""

import re
import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

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
        # Strict defaults per type — never use network tools for person/username
        defaults = {
            'person':   ['sherlock', 'maigret'],
            'username': ['sherlock', 'maigret'],
            'email':    ['holehe', 'mx'],
            'phone':    ['phoneinfoga'],
            'image':    ['exiftool'],
        }
        return {'steps': defaults.get(target_type, ['sherlock']), 'reason': 'OSINT chain'}

    def _execute_chain(self, target: str, plan: dict, target_type: str) -> dict:
        results = {}
        steps   = plan.get('steps', [])

        domain = target.split('@')[-1] if target_type == 'email' else ''

        TOOL_CMDS = {
            'sherlock':    f'sherlock {target} --timeout 5 --print-found 2>/dev/null | head -50',
            'maigret':     f'maigret {target} --print-found --no-color 2>/dev/null | head -50',
            'holehe':      f'holehe {target} 2>/dev/null | head -50',
            'mx':          f'dig +short MX {domain}',
            'phoneinfoga': f'phoneinfoga scan -n {target} 2>/dev/null | head -50',
        }

        for step in steps[:6]:
            if isinstance(step, dict):
                tool_name = step.get('tool', '')
                cmd = step.get('command', TOOL_CMDS.get(tool_name))
            else:
                tool_name = step
                cmd = TOOL_CMDS.get(tool_name)

            if not tool_name or not cmd:
                continue
            
            logger.info(f"[OsintAgent] Running: {tool_name} with command: {cmd}")
            r = self.kali.run(cmd, timeout=90)
            results[tool_name] = {
                'stdout':  r['stdout'][:4000],
                'parsed':  r.get('parsed', {}),
                'success': r['success']
            }

            if self._groq and r['stdout']:
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
                results['maigret_raw'] = stdout
            elif tool == 'holehe':
                results['holehe_raw'] = stdout
            elif tool == 'mx':
                results['mx'] = parsed
            elif tool == 'phoneinfoga':
                results['phoneinfoga_raw'] = stdout

        if results['social_profiles']:
            results['risk_level'] = 'MEDIUM'
            
        return results
