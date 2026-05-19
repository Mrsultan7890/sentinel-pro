"""
Recon Agent v3 — AI-Driven Dynamic Reconnaissance
==================================================
Uses LLM to dynamically select and execute recon tools (whois, subfinder,
amass, httpx, theHarvester) based on intermediate findings.

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


class ReconAgent:
    NAME = 'recon_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel
        self.terminal = kali
        from modules.ml_engine.groq_llm import get_groq
        self._groq = get_groq()

    def run(self, target: str, skip_nmap: bool = False) -> dict:
        logger.info(f"[ReconAgent] {target}{' (nmap skipped)' if skip_nmap else ''}")

        # Build dynamic plan
        plan = self._build_plan(target)
        logger.info(f"[ReconAgent] Plan: {plan.get('steps', [])}")

        # Execute dynamic chain
        chain_results = self._execute_chain(target, plan, skip_nmap)

        # Aggregate results for compatibility
        result = self._aggregate_results(chain_results)

        subs  = result.get('subdomains', {}).get('total_found', 0)
        cloud = result.get('cloud_assets', {}).get('total', 0)
        gh    = result.get('github_dorks', {}).get('total_secrets', 0)
        risk  = 'CRITICAL' if gh > 0 else ('HIGH' if cloud > 0 else 'MEDIUM')
        summary = f"{subs} subdomains, {cloud} cloud assets, {gh} GitHub secrets"

        self.memory.remember_scan(target, 'recon', risk, summary, result)
        if gh > 0:
            self.memory.remember_finding(target, self.NAME, 'CRITICAL',
                'GitHub Secrets', f'{gh} secrets in public repos', 'Rotate credentials immediately')
        if cloud > 0:
            self.memory.remember_finding(target, self.NAME, 'HIGH',
                'Cloud Assets Exposed', f'{cloud} assets found', 'Disable public access')
        self.memory.remember_decision(target, self.NAME, 'recon', 'Reconnaissance', summary)

        result['_agent_summary'] = summary
        result['_risk'] = risk
        result['chain_results'] = chain_results

        # Groq — critical next step
        if self._groq and (gh > 0 or cloud > 0 or subs > 0):
            try:
                context = f"Recon on {target}: {subs} subdomains, {cloud} cloud assets, {gh} GitHub secrets"
                next_step = self._groq.ask(
                    f"{context}. In 1 sentence: what is the most critical next pentest step?",
                    max_tokens=60
                )
                if next_step:
                    result['_groq_next_step'] = next_step
                    logger.info(f"[ReconAgent] Groq next step: {next_step[:80]}")
            except Exception as e:
                logger.debug(f"[ReconAgent] Groq suggestion failed: {e}")

        return result

    def _build_plan(self, target: str) -> dict:
        if self._groq:
            objective = f"Target: {target} | Need full reconnaissance, subdomains, and OSINT"
            plan = self._groq.plan(target, objective)
            if plan.get('steps'):
                return plan
        return {
            'steps': ['whois', 'dns', 'subfinder', 'amass', 'httpx', 'theHarvester'],
            'reason': 'Default recon chain'
        }

    def _execute_chain(self, target: str, plan: dict, skip_nmap: bool) -> dict:
        results = {}
        steps   = plan.get('steps', [])

        TOOL_CMDS = {
            'whois':        f'whois {target} 2>/dev/null | head -50',
            'dns':          f'dig +short {target} A && dig +short {target} MX && dig +short {target} NS',
            'subfinder':    f'subfinder -d {target} -silent 2>/dev/null | head -100',
            'amass':        f'amass enum -passive -d {target} -timeout 3 2>/dev/null | head -50',
            'httpx':        f'httpx -u {target} -title -status-code -silent 2>/dev/null | head -100',
            'theHarvester': f'theHarvester -d {target} -b bing,google -l 50 2>/dev/null | tail -20',
            'nmap':         f'nmap -sV -sC -T4 --open {target} 2>/dev/null',
            'cloud_enum':   f'cloud_enum -k {target} 2>/dev/null | tail -20',
        }

        for step in steps[:8]:
            if isinstance(step, dict):
                tool_name = step.get('tool', '')
                cmd = step.get('command', TOOL_CMDS.get(tool_name))
            else:
                tool_name = step
                cmd = TOOL_CMDS.get(tool_name)

            if not tool_name or not cmd:
                continue
            if tool_name == 'nmap' and skip_nmap:
                logger.info(f"[ReconAgent] nmap skipped — already done")
                continue
            if not self.kali.tool_available(tool_name) and tool_name not in ['whois', 'dns']:
                logger.debug(f"[ReconAgent] {tool_name} not available, skipping")
                continue

            logger.info(f"[ReconAgent] Running: {tool_name} with command: {cmd}")
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
                        logger.info(f"[ReconAgent] Groq added custom step: {next_tool} ({custom_cmd})")
                    elif next_tool in TOOL_CMDS:
                        steps.append(next_tool)
                        logger.info(f"[ReconAgent] Groq added step: {next_tool}")

        return results

    def _aggregate_results(self, chain_results: dict) -> dict:
        # Compatibility layer to map chain results to the expected unified format
        result = {'subdomains': {'subdomains': [], 'total_found': 0}, 'cloud_assets': {'total': 0}, 'github_dorks': {'total_secrets': 0}}
        
        for tool, data in chain_results.items():
            parsed = data.get('parsed', {})
            stdout = data.get('stdout', '')

            if tool == 'whois':
                result['whois_raw'] = stdout
            elif tool == 'dns':
                result['dns_raw'] = stdout
            elif tool == 'nmap':
                result['nmap'] = parsed
            elif tool == 'httpx':
                result['httpx'] = stdout
            elif tool == 'theHarvester':
                result['harvester'] = stdout
            elif tool in ('subfinder', 'amass'):
                subs = parsed.get('subdomains', [])
                for s in subs:
                    if {'subdomain': s} not in result['subdomains']['subdomains']:
                        result['subdomains']['subdomains'].append({'subdomain': s})
                result['subdomains']['total_found'] = len(result['subdomains']['subdomains'])

        result['risk_level'] = 'MEDIUM'
        return result
