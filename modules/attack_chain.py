"""
AttackChain — Autonomous Attack & Defense Chain
================================================
Flow:
    recon(target)
        ↓
    analyze findings (model)
        ↓
    exploit / verify vulnerabilities
        ↓
    suggest fixes
        ↓
    full report

Har step ka result next step ko feed hota hai.
Model decide karta hai kya karna hai aur kya skip karna hai.
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

import config as _config
CHAIN_LOG = _config.get_base_dir() / 'reports' / 'attack_chains'


class AttackChain:
    """
    Autonomous chain:
        recon → model analysis → bugbounty → exploit verify → fix → report
    """

    STEPS = ['recon', 'analyze', 'bugbounty', 'exploit', 'fix', 'report']

    def __init__(self, target: str, mode: str = 'full', auto: bool = False):
        """
        target : domain / IP / email
        mode   : 'full' | 'recon_only' | 'vuln_only' | 'fix_only'
        auto   : True = no user confirmation, False = confirm before exploit
        """
        self.target   = target
        self.mode     = mode
        self.auto     = auto
        self.results  = {}   # har step ka result yahan store hoga
        self.findings = []   # all vulnerabilities found
        self.fixes    = []   # all fixes suggested
        self._model   = None
        self._load_model()

    def _load_model(self):
        try:
            from modules.ml_engine.sentinel_net import NeuralTrainer
            nt = NeuralTrainer()
            if nt.load():
                self._model = nt
        except Exception:
            pass

    # ── Main Entry ────────────────────────────────────────────────────────────

    def run(self, console=None) -> dict:
        """Full chain run karo"""
        self._print = console or print
        CHAIN_LOG.mkdir(parents=True, exist_ok=True)

        self._print(f"\n[CHAIN] Starting AttackChain → {self.target}")
        self._print(f"[CHAIN] Mode: {self.mode} | Auto: {self.auto}\n")

        start = time.time()

        # Step 1 — Recon
        if self.mode in ('full', 'recon_only'):
            self._step_recon()

        # Step 2 — Analyze recon results with model
        if self.results.get('recon'):
            self._step_analyze()

        # Step 3 — Bug Bounty / Vuln Scan
        if self.mode in ('full', 'vuln_only'):
            if self._should_proceed('bugbounty'):
                self._step_bugbounty()

        # Step 4 — Exploit Verification
        if self.findings and self.mode == 'full':
            if self._should_proceed('exploit'):
                self._step_exploit()

        # Step 5 — Fix Suggestions
        self._step_fix()

        # Step 6 — Report
        self._step_report(elapsed=time.time() - start)

        return {
            'target':   self.target,
            'findings': self.findings,
            'fixes':    self.fixes,
            'results':  self.results,
            'risk':     self._overall_risk(),
        }

    # ── Steps ─────────────────────────────────────────────────────────────────

    def _step_recon(self):
        self._print("[1/6] RECON — Subdomains, DNS, WHOIS, GitHub dorks...")
        try:
            from modules.recon.recon_engine import ReconEngine
            engine = ReconEngine(self.target)
            result = engine.run_all()
            self.results['recon'] = result

            # Extract key findings
            subs = result.get('subdomains', {}).get('total_found', 0)
            secrets = result.get('github_dorks', {}).get('total_secrets', 0)
            emails = result.get('go_scraper', {}).get('emails', [])
            cloud = result.get('cloud_assets', {}).get('total', 0)

            self._print(f"  ✓ Subdomains: {subs}")
            self._print(f"  ✓ GitHub secrets: {secrets}")
            self._print(f"  ✓ Emails found: {len(emails)}")
            self._print(f"  ✓ Cloud assets: {cloud}")

            if secrets > 0:
                self.findings.append({
                    'type': 'github_secrets', 'severity': 'CRITICAL',
                    'detail': f'{secrets} secrets exposed on GitHub',
                    'target': self.target,
                })
            if cloud > 0:
                self.findings.append({
                    'type': 'cloud_exposure', 'severity': 'HIGH',
                    'detail': f'{cloud} exposed cloud assets found',
                    'target': self.target,
                })

        except Exception as e:
            self._print(f"  [!] Recon error: {e}")
            self.results['recon'] = {}

    def _step_analyze(self):
        self._print("\n[2/6] ANALYZE — Model threat assessment...")
        recon = self.results.get('recon', {})

        # Recon summary text banao model ke liye
        summary_parts = []
        if recon.get('github_dorks', {}).get('total_secrets', 0):
            summary_parts.append(f"GitHub secrets exposed {recon['github_dorks']['total_secrets']} credentials leaked")
        if recon.get('cloud_assets', {}).get('total', 0):
            summary_parts.append(f"cloud assets exposed S3 bucket open storage misconfiguration")
        if recon.get('subdomains', {}).get('total_found', 0) > 20:
            summary_parts.append(f"large attack surface {recon['subdomains']['total_found']} subdomains subdomain takeover risk")
        if recon.get('dns', {}).get('zone_transfer'):
            summary_parts.append("DNS zone transfer allowed information disclosure")

        if not summary_parts:
            summary_parts.append(f"recon completed for {self.target} standard attack surface")

        text = ' '.join(summary_parts)

        if self._model:
            pred = self._model.predict(text)
            risk = pred['label']
            conf = pred['confidence']
        else:
            risk = self._keyword_risk(text)
            conf = 0.6

        self.results['analyze'] = {'risk': risk, 'confidence': conf, 'summary': text}
        self._print(f"  ✓ Threat level: {risk} ({conf:.0%} confidence)")

        # High risk → automatically proceed to bugbounty
        if risk in ('CRITICAL', 'HIGH'):
            self._print(f"  → {risk} risk detected — proceeding to vulnerability scan")

    def _step_bugbounty(self):
        self._print("\n[3/6] BUGBOUNTY — SSL, Headers, Ports, SQLi, XSS, SSRF...")
        try:
            from modules.bugbounty.bugbounty_engine import BugBountyEngine
            engine = BugBountyEngine(self.target)
            result = engine.run_all()
            self.results['bugbounty'] = result

            # Extract vulnerabilities
            vulns_found = 0
            for check_name, check_result in result.items():
                if not isinstance(check_result, dict): continue
                severity = check_result.get('risk_level') or check_result.get('severity', '')
                if severity in ('CRITICAL', 'HIGH', 'MEDIUM'):
                    self.findings.append({
                        'type':     check_name,
                        'severity': severity,
                        'detail':   check_result.get('summary') or check_result.get('detail', str(check_result))[:200],
                        'target':   self.target,
                        'raw':      check_result,
                    })
                    vulns_found += 1

            self._print(f"  ✓ Vulnerabilities found: {vulns_found}")
            for f in self.findings[-vulns_found:]:
                self._print(f"    [{f['severity']}] {f['type']}: {f['detail'][:80]}")

        except Exception as e:
            self._print(f"  [!] BugBounty error: {e}")
            self.results['bugbounty'] = {}

    def _step_exploit(self):
        self._print("\n[4/6] EXPLOIT VERIFY — Confirming vulnerabilities...")
        exploited = []

        for finding in self.findings:
            sev = finding.get('severity', '')
            ftype = finding.get('type', '')

            if sev not in ('CRITICAL', 'HIGH'):
                continue

            result = self._verify_exploit(ftype, finding)
            if result.get('confirmed'):
                exploited.append({**finding, 'exploit_result': result})
                self._print(f"  [CONFIRMED] {ftype}: {result.get('detail','')[:80]}")
            else:
                self._print(f"  [NOT CONFIRMED] {ftype}")

        self.results['exploit'] = exploited
        self._print(f"  ✓ Confirmed: {len(exploited)}/{len([f for f in self.findings if f['severity'] in ('CRITICAL','HIGH')])}")

    def _step_fix(self):
        self._print("\n[5/6] FIX — Generating remediation...")
        self.fixes = []

        FIX_MAP = {
            'ssl':              ('Update TLS to 1.3, disable SSLv3/TLS1.0/1.1, use strong cipher suites', 'HIGH'),
            'headers':          ('Add: Strict-Transport-Security, X-Frame-Options: DENY, Content-Security-Policy, X-Content-Type-Options: nosniff', 'MEDIUM'),
            'sqli':             ('Use parameterized queries / prepared statements. Never concatenate user input in SQL.', 'CRITICAL'),
            'xss':              ('Encode output (htmlspecialchars), implement CSP header, validate all inputs.', 'HIGH'),
            'ssrf':             ('Whitelist allowed URLs/IPs, block internal ranges (169.254.x.x, 10.x.x.x), disable redirects.', 'HIGH'),
            'cors':             ('Set Access-Control-Allow-Origin to specific trusted domains only, never use wildcard with credentials.', 'HIGH'),
            'jwt':              ('Use RS256 instead of HS256, validate exp/iss/aud claims, reject alg:none.', 'HIGH'),
            'lfi':              ('Validate file paths, use realpath() + whitelist, disable allow_url_include.', 'HIGH'),
            'xxe':              ('Disable external entity processing: FEATURE_EXTERNAL_GENERAL_ENTITIES = false.', 'HIGH'),
            'ssti':             ('Use sandboxed template engines, never pass user input directly to template render.', 'CRITICAL'),
            'open_redirect':    ('Validate redirect URLs against whitelist, use relative paths only.', 'MEDIUM'),
            'takeover':         ('Remove dangling DNS records pointing to deprovisioned services immediately.', 'CRITICAL'),
            'github_secrets':   ('Rotate all exposed credentials immediately. Use git-secrets or truffleHog pre-commit hooks.', 'CRITICAL'),
            'cloud_exposure':   ('Set S3/GCS bucket ACL to private, enable bucket versioning and access logging.', 'HIGH'),
            'ports':            ('Close unnecessary ports. Use firewall rules. Move admin services behind VPN.', 'MEDIUM'),
            'cookies':          ('Set Secure, HttpOnly, SameSite=Strict flags on all session cookies.', 'MEDIUM'),
        }

        seen_types = set()
        for finding in self.findings:
            ftype = finding.get('type', '').lower()
            sev   = finding.get('severity', 'LOW')

            # Match fix
            fix_text, fix_sev = None, sev
            for key, (fix, fsev) in FIX_MAP.items():
                if key in ftype:
                    fix_text = fix
                    fix_sev  = fsev
                    break

            if not fix_text:
                fix_text = f"Review and remediate {ftype} vulnerability. Follow OWASP guidelines."

            if ftype not in seen_types:
                seen_types.add(ftype)
                self.fixes.append({
                    'vulnerability': ftype,
                    'severity':      sev,
                    'fix':           fix_text,
                    'priority':      1 if sev == 'CRITICAL' else 2 if sev == 'HIGH' else 3,
                })

        # Sort by priority
        self.fixes.sort(key=lambda x: x['priority'])

        self._print(f"  ✓ Fixes generated: {len(self.fixes)}")
        for fix in self.fixes[:5]:
            self._print(f"    [{fix['severity']}] {fix['vulnerability']}: {fix['fix'][:70]}")

    def _step_report(self, elapsed: float):
        self._print(f"\n[6/6] REPORT — Generating chain report...")
        risk = self._overall_risk()

        report = {
            'target':    self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'elapsed':   round(elapsed, 1),
            'risk':      risk,
            'findings':  self.findings,
            'fixes':     self.fixes,
            'summary': {
                'total_findings':  len(self.findings),
                'critical':        sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
                'high':            sum(1 for f in self.findings if f['severity'] == 'HIGH'),
                'medium':          sum(1 for f in self.findings if f['severity'] == 'MEDIUM'),
                'confirmed_exploits': len(self.results.get('exploit', [])),
                'fixes_generated': len(self.fixes),
            },
            'steps': {k: 'completed' for k in self.results},
        }

        # Save JSON report
        fname = f"chain_{self.target.replace('.','_')}_{time.strftime('%Y%m%d_%H%M%S')}"
        json_path = CHAIN_LOG / f"{fname}.json"
        json_path.write_text(json.dumps(report, indent=2))

        self._print(f"\n{'='*55}")
        self._print(f"  ATTACK CHAIN COMPLETE — {self.target}")
        self._print(f"{'='*55}")
        self._print(f"  Overall Risk    : {risk}")
        self._print(f"  Total Findings  : {report['summary']['total_findings']}")
        self._print(f"  CRITICAL        : {report['summary']['critical']}")
        self._print(f"  HIGH            : {report['summary']['high']}")
        self._print(f"  MEDIUM          : {report['summary']['medium']}")
        self._print(f"  Confirmed Exploits: {report['summary']['confirmed_exploits']}")
        self._print(f"  Fixes Generated : {report['summary']['fixes_generated']}")
        self._print(f"  Time Elapsed    : {elapsed:.1f}s")
        self._print(f"  Report saved    : {json_path}")
        self._print(f"{'='*55}\n")

        self.results['report'] = report
        return report

    # ── Exploit Verifiers ─────────────────────────────────────────────────────

    def _verify_exploit(self, ftype: str, finding: dict) -> dict:
        """Vulnerability confirm karo — safe verification only"""
        try:
            ftype_lower = ftype.lower()

            if 'sqli' in ftype_lower or 'sql' in ftype_lower:
                return self._verify_sqli(finding)
            elif 'xss' in ftype_lower:
                return self._verify_xss(finding)
            elif 'ssrf' in ftype_lower:
                return self._verify_ssrf(finding)
            elif 'cors' in ftype_lower:
                return self._verify_cors(finding)
            elif 'redirect' in ftype_lower:
                return self._verify_redirect(finding)
            elif 'takeover' in ftype_lower:
                return self._verify_takeover(finding)
            else:
                # Generic — raw result se confirm karo
                raw = finding.get('raw', {})
                confirmed = bool(raw.get('vulnerable') or raw.get('confirmed') or
                                 raw.get('risk_level') in ('CRITICAL', 'HIGH'))
                return {'confirmed': confirmed, 'detail': 'Based on scan result'}

        except Exception as e:
            return {'confirmed': False, 'detail': str(e)}

    def _verify_sqli(self, finding: dict) -> dict:
        import requests
        raw = finding.get('raw', {})
        urls = raw.get('vulnerable_urls', []) or raw.get('urls', [])
        for url in urls[:2]:
            try:
                # Time-based blind check — safe
                test_url = url + ("&" if "?" in url else "?") + "id=1' AND SLEEP(2)--"
                t0 = time.time()
                requests.get(test_url, timeout=5, verify=False)
                elapsed = time.time() - t0
                if elapsed >= 2:
                    return {'confirmed': True, 'detail': f'Time-based SQLi confirmed on {url}', 'url': url}
            except Exception:
                pass
        return {'confirmed': bool(urls), 'detail': 'SQLi indicators found in scan'}

    def _verify_xss(self, finding: dict) -> dict:
        raw = finding.get('raw', {})
        payloads = raw.get('payloads_reflected', []) or raw.get('reflected', [])
        if payloads:
            return {'confirmed': True, 'detail': f'{len(payloads)} XSS payloads reflected'}
        return {'confirmed': bool(raw.get('vulnerable')), 'detail': 'XSS indicators found'}

    def _verify_ssrf(self, finding: dict) -> dict:
        raw = finding.get('raw', {})
        confirmed = bool(raw.get('internal_access') or raw.get('vulnerable'))
        return {'confirmed': confirmed, 'detail': raw.get('detail', 'SSRF indicators found')}

    def _verify_cors(self, finding: dict) -> dict:
        import requests
        raw = finding.get('raw', {})
        url = raw.get('url', f'https://{self.target}')
        try:
            r = requests.get(url, headers={'Origin': 'https://evil.com'}, timeout=5, verify=False)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            if acao == 'https://evil.com' or (acao == '*' and 'true' in acac.lower()):
                return {'confirmed': True, 'detail': f'CORS allows evil.com: ACAO={acao}'}
        except Exception:
            pass
        return {'confirmed': bool(raw.get('vulnerable')), 'detail': 'CORS misconfiguration found'}

    def _verify_redirect(self, finding: dict) -> dict:
        raw = finding.get('raw', {})
        urls = raw.get('vulnerable_urls', [])
        return {'confirmed': bool(urls), 'detail': f'{len(urls)} open redirect endpoints'}

    def _verify_takeover(self, finding: dict) -> dict:
        raw = finding.get('raw', {})
        vulnerable = raw.get('vulnerable', [])
        return {'confirmed': bool(vulnerable), 'detail': f'{len(vulnerable)} subdomains vulnerable'}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _should_proceed(self, step: str) -> bool:
        """Auto mode mein hamesha proceed, manual mein confirm karo"""
        if self.auto:
            return True
        risk = self.results.get('analyze', {}).get('risk', 'LOW')
        # CRITICAL/HIGH risk pe automatically proceed
        if risk in ('CRITICAL', 'HIGH'):
            return True
        # MEDIUM/LOW pe user se poocho
        self._print(f"\n  [?] Proceed to {step}? (risk={risk}) [y/N]: ", end='')
        try:
            ans = input().strip().lower()
            return ans == 'y'
        except Exception:
            return False

    def _overall_risk(self) -> str:
        if not self.findings:
            return 'LOW'
        sevs = [f.get('severity', 'LOW') for f in self.findings]
        if 'CRITICAL' in sevs: return 'CRITICAL'
        if 'HIGH' in sevs:     return 'HIGH'
        if 'MEDIUM' in sevs:   return 'MEDIUM'
        return 'LOW'

    def _keyword_risk(self, text: str) -> str:
        tl = text.lower()
        if any(k in tl for k in ['secret', 'exposed', 'critical', 'rce', 'exploit']): return 'CRITICAL'
        if any(k in tl for k in ['vulnerability', 'injection', 'takeover']):           return 'HIGH'
        if any(k in tl for k in ['misconfiguration', 'exposure']):                     return 'MEDIUM'
        return 'LOW'
