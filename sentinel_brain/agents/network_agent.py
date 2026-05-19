"""
Network Agent v3 — AI-Driven Deep Network Scanning
===================================================
Uses LLM to dynamically select port scanning strategies, nmap scripts,
and follow-up service enumerations.

Author: @who_is_the_black_hat
"""

import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

RISKY_PORTS = {
    21:    ('FTP',        'HIGH',     'Anonymous FTP possible'),
    22:    ('SSH',        'MEDIUM',   'Brute force possible'),
    23:    ('Telnet',     'CRITICAL', 'Unencrypted protocol'),
    445:   ('SMB',        'HIGH',     'EternalBlue/ransomware risk'),
    3306:  ('MySQL',      'HIGH',     'Database exposed'),
    3389:  ('RDP',        'HIGH',     'Remote desktop exposed'),
    6379:  ('Redis',      'CRITICAL', 'No auth by default'),
    27017: ('MongoDB',    'CRITICAL', 'No auth by default'),
}

class NetworkAgent:
    NAME = 'network_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel
        from modules.ml_engine.groq_llm import get_groq
        self._groq = get_groq()

    def run(self, target: str, fast: bool = False) -> dict:
        logger.info(f"[NetworkAgent] {target} fast={fast}")

        # Build plan
        plan = self._build_plan(target, fast)
        logger.info(f"[NetworkAgent] Plan: {plan.get('steps', [])}")

        # Execute chain
        chain_results = self._execute_chain(target, plan)

        # Aggregate findings
        findings = self._extract_findings(target, chain_results)
        risk     = self._overall_risk(findings)
        summary   = f"{len(findings)} findings | risk={risk}"

        self.memory.remember_scan(target, 'network', risk, summary, chain_results)
        for f in findings:
            self.memory.remember_finding(
                target, self.NAME, f['severity'], f['title'], f['detail'], f.get('fix', '')
            )
        self.memory.remember_decision(target, self.NAME, 'network', 'Network scan', summary)

        # Groq overall summary
        if self._groq and findings:
            try:
                critical = [f for f in findings if f['severity'] in ('CRITICAL', 'HIGH')][:3]
                if critical:
                    finding_text = '; '.join(f"{f['title']}: {f['detail'][:80]}" for f in critical)
                    analysis = self._groq.ask(
                        f"Network findings on {target}: {finding_text}\n"
                        f"In 2 sentences: what is the most critical network vector?",
                        max_tokens=80
                    )
                    if analysis:
                        logger.info(f"[NetworkAgent] Groq vector: {analysis[:80]}")
            except Exception as e:
                logger.debug(f"[NetworkAgent] Groq summary failed: {e}")

        return {
            '_findings': findings,
            '_risk': risk,
            '_agent_summary': summary,
            'chain_results': chain_results
        }

    def _build_plan(self, target: str, fast: bool) -> dict:
        if self._groq:
            objective = f"Target: {target} | Network port scan and service enumeration. Fast={fast}"
            plan = self._groq.plan(target, objective)
            if plan.get('steps'):
                return plan
        return {
            'steps': ['nmap' if fast else 'masscan', 'nmap_deep', 'sslscan'],
            'reason': 'Default network chain'
        }

    def _execute_chain(self, target: str, plan: dict) -> dict:
        results = {}
        steps   = plan.get('steps', [])

        TOOL_CMDS = {
            'masscan':   f'masscan {target} -p1-65535 --rate=1000 2>/dev/null | head -100',
            'nmap':      f'nmap -T4 --open {target} 2>/dev/null',
            'nmap_deep': f'nmap -sV -sC -A -p- --min-rate 1000 {target} 2>/dev/null',
            'sslscan':   f'sslscan --no-colour {target} 2>/dev/null | tail -50',
            'ftp':       f'nmap --script ftp-anon,ftp-vuln* -p 21 {target} 2>/dev/null',
            'smb':       f'nmap --script smb-vuln*,smb-security-mode -p 445 {target} 2>/dev/null',
            'mysql':     f'nmap --script mysql-info,mysql-empty-password -p 3306 {target} 2>/dev/null',
            'redis':     f'redis-cli -h {target} ping 2>/dev/null',
            'mongodb':   f'nmap --script mongodb-info -p 27017 {target} 2>/dev/null',
        }

        for step in steps[:10]:
            if isinstance(step, dict):
                tool_name = step.get('tool', '')
                cmd = step.get('command', TOOL_CMDS.get(tool_name))
            else:
                tool_name = step
                cmd = TOOL_CMDS.get(tool_name)

            if not tool_name or not cmd:
                continue

            logger.info(f"[NetworkAgent] Running: {tool_name} with command: {cmd}")
            r = self.kali.run(cmd, timeout=120)
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
                        logger.info(f"[NetworkAgent] Groq added custom step: {next_tool} ({custom_cmd})")
                    elif next_tool in TOOL_CMDS:
                        steps.append(next_tool)
                        logger.info(f"[NetworkAgent] Groq added step: {next_tool}")

        return results

    def _extract_findings(self, target: str, chain_results: dict) -> list:
        findings = []
        for tool, data in chain_results.items():
            stdout = data.get('stdout', '')
            parsed = data.get('parsed', {})

            if tool in ['nmap', 'nmap_deep']:
                for port_info in parsed.get('open_ports', []):
                    port = port_info.get('port')
                    if port in RISKY_PORTS:
                        svc_name, sev, reason = RISKY_PORTS[port]
                        findings.append({
                            'type': f'port_{port}',
                            'title': f'{svc_name} Port Open ({port})',
                            'severity': sev,
                            'detail': f"Port {port} ({svc_name}) open — {reason} | version: {port_info.get('version','unknown')}",
                            'fix': f'Close port {port} if not needed, or restrict with firewall',
                        })

            elif tool == 'sslscan':
                if 'SSLv3' in stdout or 'SSLv2' in stdout:
                    findings.append({'severity': 'CRITICAL', 'title': 'SSLv2/3 enabled', 'detail': 'Legacy protocols', 'fix': 'Disable SSL'})
            
            elif tool == 'redis':
                if 'PONG' in stdout:
                    findings.append({'severity': 'CRITICAL', 'title': 'Redis Unauthenticated', 'detail': 'Redis responds to PING', 'fix': 'Requirepass'})

            elif tool == 'smb':
                if 'VULNERABLE' in stdout.upper():
                    findings.append({'severity': 'CRITICAL', 'title': 'SMB Vuln', 'detail': stdout[:200], 'fix': 'Patch SMB'})

            # General risk assessment from LLM
            analysis = data.get('analysis', {})
            risk = analysis.get('risk', '')
            if risk in ['HIGH', 'CRITICAL'] and analysis.get('findings'):
                for f in analysis['findings']:
                    findings.append({'severity': risk, 'title': 'AI Discovered Vuln', 'detail': f, 'fix': 'Investigate'})

        return findings

    def _overall_risk(self, findings: list) -> str:
        if not findings:
            return 'LOW'
        return min(findings, key=lambda f: _SEV_ORDER.get(f.get('severity', 'LOW'), 4), default={'severity': 'LOW'}).get('severity', 'LOW')
