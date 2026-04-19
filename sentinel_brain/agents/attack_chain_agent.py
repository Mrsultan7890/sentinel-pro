"""
Attack Chain Agent — Groq + Full Exploit Chain
===============================================
- Groq se full attack plan banao
- CVE → exploit → payload → execute chain
- Metasploit / searchsploit integration
- Post-exploitation checks
- Auto remediation suggestions

Author: @who_is_the_black_hat
"""

import logging
import time
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


class AttackChainAgent:
    NAME = 'attack_chain_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel
        self._groq    = self._load_groq()

    def _load_groq(self):
        try:
            from modules.ml_engine.groq_llm import GroqLLM
            if GroqLLM.is_available():
                g = GroqLLM()
                return g if g.is_ready else None
        except Exception:
            pass
        return None

    def run(self, target: str, recon_data: dict = None,
            threat_intel: dict = None, auto: bool = False) -> dict:
        logger.info(f"[AttackChainAgent] {target} auto={auto}")

        # ── Step 1: Groq se attack plan banao ────────────────────────────────
        plan = self._build_plan(target, recon_data, threat_intel)
        logger.info(f"[AttackChainAgent] Plan: {plan.get('steps', [])}")

        # ── Step 2: Chain execute karo ────────────────────────────────────────
        chain_results = self._execute_chain(target, plan, auto)

        # ── Step 3: Post-exploitation checks ─────────────────────────────────
        post_results = self._post_exploitation(target, chain_results)

        # ── Step 4: Remediation ───────────────────────────────────────────────
        remediations = self._generate_remediations(chain_results, post_results)

        # ── Findings ──────────────────────────────────────────────────────────
        findings = self._extract_findings(target, chain_results, post_results)
        risk     = self._overall_risk(findings)
        summary  = (
            f"Chain: {len(plan.get('steps',[]))} steps | "
            f"{len(findings)} findings | "
            f"{len(remediations)} remediations | risk={risk}"
        )

        self.memory.remember_scan(target, 'attack_chain', risk, summary, chain_results)
        for f in findings:
            self.memory.remember_finding(
                target, self.NAME, f['severity'], f['title'], f['detail'], f.get('fix', '')
            )
        self.memory.remember_decision(target, self.NAME, 'attack_chain', 'Attack Chain', summary)

        return {
            'plan':          plan,
            'chain_results': chain_results,
            'post_results':  post_results,
            'remediations':  remediations,
            '_findings':     findings,
            '_risk':         risk,
            '_agent_summary': summary,
        }

    # ── Plan ──────────────────────────────────────────────────────────────────

    def _build_plan(self, target: str, recon: dict, intel: dict) -> dict:
        """Groq se intelligent attack plan banao."""
        if self._groq:
            # Context build karo
            context_parts = [f"Target: {target}"]
            if recon:
                ports = recon.get('nmap', {}).get('open_ports', [])
                if ports:
                    context_parts.append(f"Open ports: {[p['port'] for p in ports[:5]]}")
                subs = recon.get('subdomains', {}).get('total_found', 0)
                if subs:
                    context_parts.append(f"Subdomains: {subs}")
            if intel:
                cves = intel.get('cves', {}).get('total_cves', 0)
                if cves:
                    context_parts.append(f"CVEs found: {cves}")
                exploits = intel.get('searchsploit', {}).get('total', 0)
                if exploits:
                    context_parts.append(f"Public exploits: {exploits}")

            objective = ' | '.join(context_parts)
            plan = self._groq.plan(target, objective)
            if plan.get('steps'):
                return plan

        # Fallback — default plan
        return {
            'steps': ['nmap', 'nikto', 'nuclei', 'sqlmap', 'gobuster'],
            'reason': 'Default attack chain',
        }

    # ── Execute Chain ─────────────────────────────────────────────────────────

    def _execute_chain(self, target: str, plan: dict, auto: bool) -> dict:
        results = {}
        steps   = plan.get('steps', [])

        TOOL_CMDS = {
            'nmap':         f'nmap -sV -sC -T4 --open {target} 2>/dev/null',
            'nikto':        f'nikto -h https://{target} -maxtime 60 -nointeractive 2>/dev/null',
            'nuclei':       f'nuclei -u https://{target} -severity critical,high -silent 2>/dev/null | head -20',
            'sqlmap':       f'sqlmap -u "https://{target}" --batch --crawl=1 --forms --level=1 2>/dev/null | tail -20',
            'gobuster':     f'gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -q -t 20 2>/dev/null | head -20',
            'ffuf':         f'ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -s 2>/dev/null | head -20',
            'wpscan':       f'wpscan --url https://{target} --no-update --enumerate vp 2>/dev/null | tail -20',
            'enum4linux':   f'enum4linux -a {target} 2>/dev/null | tail -30',
            'hydra':        f'hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target} ssh -t 4 2>/dev/null | tail -10',
            'searchsploit': f'searchsploit {target} --disable-colour 2>/dev/null | head -10',
            'commix':       f'commix --url="https://{target}/?id=1" --batch 2>/dev/null | tail -10',
            'masscan':      f'masscan {target} --top-ports 1000 --rate=500 2>/dev/null | head -20',
            'subfinder':    f'subfinder -d {target} -silent 2>/dev/null | head -30',
            'amass':        f'amass enum -passive -d {target} -timeout 3 2>/dev/null | head -20',
            'whatweb':      f'whatweb -a 3 https://{target} --color=never 2>/dev/null',
            'wafw00f':      f'wafw00f https://{target} 2>/dev/null',
            'sslscan':      f'sslscan --no-colour {target} 2>/dev/null | tail -20',
            'theHarvester': f'theHarvester -d {target} -b bing -l 50 2>/dev/null | tail -20',
        }

        for step in steps[:8]:  # Max 8 steps
            if step not in TOOL_CMDS:
                continue
            if not self.kali.tool_available(step):
                logger.debug(f"[AttackChain] {step} not available, skipping")
                continue

            logger.info(f"[AttackChain] Running: {step}")
            r = self.kali.run(TOOL_CMDS[step], timeout=90)
            results[step] = {
                'stdout':  r['stdout'][:500],
                'parsed':  r.get('parsed', {}),
                'success': r['success'],
            }

            # Groq se output analyze karo — next step adapt karo
            if self._groq and r['stdout']:
                analysis = self._groq.analyze_output(step, r['stdout'], target)
                results[step]['analysis'] = analysis
                next_tool = analysis.get('next_tool', '')
                if next_tool and next_tool not in steps and next_tool in TOOL_CMDS:
                    steps.append(next_tool)
                    logger.info(f"[AttackChain] Groq added step: {next_tool}")

        return results

    # ── Post-exploitation ─────────────────────────────────────────────────────

    def _post_exploitation(self, target: str, chain_results: dict) -> dict:
        post = {}

        # SQLi confirmed → try DB dump
        sqlmap = chain_results.get('sqlmap', {})
        if 'injectable' in str(sqlmap.get('stdout', '')).lower():
            r = self.kali.run(
                f'sqlmap -u "https://{target}" --batch --dbs 2>/dev/null | tail -10',
                timeout=60
            )
            post['sqli_dbs'] = r['stdout'][:300]

        # Searchsploit found → check metasploit
        sploit = chain_results.get('searchsploit', {})
        if sploit.get('stdout', '').strip():
            post['exploits_available'] = True
            post['exploit_note'] = 'Public exploits found — manual verification recommended'

        return post

    # ── Remediations ──────────────────────────────────────────────────────────

    def _generate_remediations(self, chain: dict, post: dict) -> list:
        remediations = []

        if self._groq:
            # Findings summary banao
            findings_text = []
            for tool, result in chain.items():
                analysis = result.get('analysis', {})
                if analysis.get('risk') in ('HIGH', 'CRITICAL'):
                    findings_text.append(f"{tool}: {analysis.get('summary','')[:100]}")

            if findings_text:
                report = self._groq.report_gen(
                    ' | '.join(findings_text[:3]),
                    severity='HIGH',
                    threat_type='web_vuln'
                )
                if report:
                    remediations.append({
                        'source': 'groq',
                        'recommendation': report[:300],
                        'priority': 1,
                    })

        # Static remediations
        STATIC = {
            'sqlmap':   ('SQL Injection', 'Use parameterized queries, never concatenate user input in SQL', 'CRITICAL'),
            'nikto':    ('Web Vulnerabilities', 'Update web server, remove default files, harden configuration', 'HIGH'),
            'nuclei':   ('Known CVEs', 'Apply vendor patches immediately, implement WAF rules', 'CRITICAL'),
            'wpscan':   ('WordPress', 'Update WordPress core, plugins, themes. Remove unused plugins', 'HIGH'),
            'hydra':    ('Brute Force', 'Implement account lockout, use strong passwords, enable 2FA', 'HIGH'),
            'enum4linux':('SMB Enumeration', 'Restrict SMB access, disable null sessions, use SMBv3', 'HIGH'),
        }
        for tool, (vuln, fix, sev) in STATIC.items():
            if tool in chain and chain[tool].get('stdout', '').strip():
                remediations.append({
                    'source': tool,
                    'vulnerability': vuln,
                    'recommendation': fix,
                    'severity': sev,
                    'priority': 1 if sev == 'CRITICAL' else 2,
                })

        remediations.sort(key=lambda x: x.get('priority', 3))
        return remediations

    # ── Findings ──────────────────────────────────────────────────────────────

    def _extract_findings(self, target: str, chain: dict, post: dict) -> list:
        findings = []

        for tool, result in chain.items():
            analysis = result.get('analysis', {})
            risk = analysis.get('risk', 'LOW')
            if risk not in ('CRITICAL', 'HIGH', 'MEDIUM'):
                continue
            summary = analysis.get('summary', result.get('stdout', '')[:100])
            findings.append({
                'type':     f'chain_{tool}',
                'title':    f'{tool.upper()} Finding',
                'severity': risk,
                'detail':   summary[:200],
                'fix':      f'Review {tool} output and apply patches',
            })

        if post.get('sqli_dbs'):
            findings.append({
                'type':     'sqli_confirmed',
                'title':    'SQL Injection Confirmed — DB Access',
                'severity': 'CRITICAL',
                'detail':   f'Database names extracted: {post["sqli_dbs"][:150]}',
                'fix':      'Immediately patch SQL injection, rotate DB credentials',
            })

        return findings

    def _overall_risk(self, findings: list) -> str:
        if not findings:
            return 'LOW'
        return min(findings, key=lambda f: _SEV_ORDER.get(f['severity'], 4))['severity']
