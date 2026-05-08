# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
Telegram Notifications — instant alerts for CRITICAL/HIGH findings
"""

import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)


class TelegramNotifier:

    def __init__(self, token: str, chat_id: str):
        # Validate inputs
        if not token or not isinstance(token, str):
            logger.warning("Invalid Telegram token provided")
            self.enabled = False
            self.token = ''
            self.chat_id = ''
            self._base = ''
            self._last_send_time = 0
            self._min_interval = 2.0
            return
        
        if not chat_id or not isinstance(chat_id, str):
            logger.warning("Invalid Telegram chat_id provided")
            self.enabled = False
            self.token = ''
            self.chat_id = ''
            self._base = ''
            self._last_send_time = 0
            self._min_interval = 2.0
            return
        
        self.token   = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id and token != 'YOUR_BOT_TOKEN')
        self._base   = f"https://api.telegram.org/bot{token}"
        self._last_send_time = 0
        self._min_interval = 2.0  # Minimum 2 seconds between messages (rate limiting)

    @staticmethod
    def _clean(text: str) -> str:
        import re
        # HTML tags hatao
        text = re.sub(r'<[^>]+>', '', text)
        # SSTI/code payloads sanitize karo
        text = re.sub(r'\{\{.*?\}\}', '[SSTI payload]', text)
        text = re.sub(r'\$\{.*?\}', '[SSTI payload]', text)
        text = re.sub(r'#\{.*?\}', '[SSTI payload]', text)
        text = re.sub(r'<%.*?%>', '[SSTI payload]', text)
        text = re.sub(r'\{[0-9*+\-/]+\}', '[SSTI payload]', text)
        return text.strip()

    def _send(self, text: str, retry_count: int = 3) -> bool:
        if not self.enabled:
            return False
        
        # Rate limiting - wait if needed
        import time
        elapsed = time.time() - self._last_send_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        
        # Retry logic
        for attempt in range(retry_count):
            try:
                r = requests.post(
                    f"{self._base}/sendMessage",
                    json={"chat_id": self.chat_id, "text": self._clean(text)},
                    timeout=10
                )
                self._last_send_time = time.time()
                
                if r.status_code == 200:
                    return True
                elif r.status_code == 429:  # Too Many Requests
                    retry_after = r.json().get('parameters', {}).get('retry_after', 5)
                    logger.warning(f"Telegram rate limit hit, waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue
                else:
                    logger.warning(f"Telegram send failed: HTTP {r.status_code}")
                    if attempt < retry_count - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    return False
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Telegram timeout (attempt {attempt + 1}/{retry_count})")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)
                    continue
                return False
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Telegram connection error: {e}")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)
                    continue
                return False
            except requests.exceptions.RequestException as e:
                logger.error(f"Telegram request error: {e}")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)
                    continue
                return False
            except Exception as e:
                logger.warning(f"Telegram send failed: {e}")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)
                    continue
                return False
        
        return False

    # ── public helpers ──────────────────────────────────────────────────────

    def alert_bugbounty(self, domain: str, data: dict, max_findings: int = None) -> bool:
        """Send bug bounty alert with ALL findings (no limit by default)."""
        if not self.enabled:
            return False
        
        # Validate inputs
        if not domain or not isinstance(domain, str):
            logger.error("Invalid domain for alert_bugbounty")
            return False
        
        if not data or not isinstance(data, dict):
            logger.error("Invalid data for alert_bugbounty")
            return False
        
        # Check if unified report format (has 'findings' array)
        if 'findings' in data and isinstance(data['findings'], list):
            findings_list = data['findings']
            total_count = len(findings_list)
            
            # If no findings, send success message
            if total_count == 0:
                lines = [
                    f"✅ BUG BOUNTY SCAN COMPLETE",
                    f"Target : {domain}",
                    f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    f"Status : [green]No vulnerabilities found[/green]",
                    f"",
                    f"🛡️ All security checks passed!",
                    f"",
                    f"Sentinel Pro — @who_is_the_black_hat"
                ]
                return self._send('\n'.join(lines))
            
            # Apply limit only if specified
            display_findings = findings_list[:max_findings] if max_findings else findings_list
            
            lines = [
                f"🚨 BUG BOUNTY ALERT",
                f"Target : {domain}",
                f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"Found  : {total_count} issue(s)",
                f"",
                f"ALL FINDINGS:",
            ]
            
            for finding in display_findings:
                severity = finding.get('severity', 'MEDIUM')
                title = finding.get('title', 'Unknown')
                detail = finding.get('detail', '')[:80]
                
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                lines.append(f"{icon} [{severity}] {title}")
                if detail:
                    lines.append(f"  {detail}")
            
            if max_findings and total_count > max_findings:
                lines.append(f"")
                lines.append(f"... and {total_count - max_findings} more findings")
            
            lines.append(f"")
            lines.append(f"Sentinel Pro — @who_is_the_black_hat")
            return self._send('\n'.join(lines))
        
        # Old format (individual scanner results)
        criticals = self._extract_bugbounty_criticals(data)
        fuzz_count = data.get('fuzzer', {}).get('total_findings', 0)
        smug_count = len(data.get('smuggling', {}).get('findings', []))
        lfi_count  = data.get('lfi', {}).get('total', 0)
        
        if not criticals and not fuzz_count and not smug_count and not lfi_count:
            # Send success message for old format too
            lines = [
                f"✅ BUG BOUNTY SCAN COMPLETE",
                f"Target : {domain}",
                f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"Status : No critical/high issues found",
                f"",
                f"🛡️ Target appears secure!",
                f"",
                f"Sentinel Pro — @who_is_the_black_hat"
            ]
            return self._send('\n'.join(lines))
        
        # Deduplicate by type
        seen_types, unique = set(), []
        for c in criticals:
            t = c.split(']')[0].replace('[','').strip()
            if t not in seen_types:
                seen_types.add(t)
                unique.append(c)
        
        display_findings = unique[:max_findings] if max_findings else unique
        total_count = len(unique)
        
        lines = [
            f"🚨 BUG BOUNTY ALERT",
            f"Target : {domain}",
            f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"Found  : {total_count} issue(s)",
            f"",
            f"ALL FINDINGS:",
        ]
        
        for item in display_findings:
            import re
            sev  = re.search(r'\[([A-Z]+)\]', item)
            rest = re.sub(r'\[[A-Z]+\]\s*', '', item).strip()
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(
                sev.group(1) if sev else 'MEDIUM', '⚪'
            )
            lines.append(f"{icon} {rest[:100]}")
        
        if max_findings and total_count > max_findings:
            lines.append(f"")
            lines.append(f"... and {total_count - max_findings} more findings")
        
        lines.append(f"")
        lines.append(f"Sentinel Pro — @who_is_the_black_hat")
        return self._send('\n'.join(lines))

    def alert_recon(self, domain: str, data: dict, max_findings: int = None) -> bool:
        """Send recon alert with ALL findings (no limit by default)."""
        if not self.enabled:
            return False
        
        # Validate inputs
        if not domain or not isinstance(domain, str):
            logger.error("Invalid domain for alert_recon")
            return False
        
        if not data or not isinstance(data, dict):
            logger.error("Invalid data for alert_recon")
            return False
        
        criticals = self._extract_recon_criticals(data)
        if not criticals:
            return False
        
        display_findings = criticals[:max_findings] if max_findings else criticals
        total_count = len(criticals)
        
        lines = [
            f"🔍 RECON ALERT",
            f"Target : {domain}",
            f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"Found  : {total_count} finding(s)",
            f"",
            f"ALL FINDINGS:",
        ]
        for item in display_findings:
            import re
            sev  = re.search(r'\[([A-Z]+)\]', item)
            rest = re.sub(r'\[[A-Z]+\]\s*', '', item).strip()
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(
                sev.group(1) if sev else 'MEDIUM', '⚠️'
            )
            lines.append(f"{icon} {rest[:100]}")
        
        if max_findings and total_count > max_findings:
            lines.append(f"")
            lines.append(f"... and {total_count - max_findings} more findings")
        
        lines.append(f"")
        lines.append(f"Sentinel Pro — @who_is_the_black_hat")
        return self._send('\n'.join(lines))

    def alert_breach(self, target: str, data: dict):
        if not self.enabled:
            return False
        
        # Validate inputs
        if not target or not isinstance(target, str):
            logger.error("Invalid target for alert_breach")
            return False
        
        if not data or not isinstance(data, dict):
            logger.error("Invalid data for alert_breach")
            return False
        
        risk = data.get('risk_level', 'LOW')
        if risk not in ('CRITICAL', 'HIGH'):
            return False
        lines = [
            f"💀 BREACH ALERT — {target}",
            f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"⚠️ Risk: {risk}",
            f"📋 Breaches: {data.get('total_breaches', 0)}",
            f"🦠 Stealer logs: {data.get('total_stealer_logs', 0)}",
            f"",
            f"Sentinel Pro — @who_is_the_black_hat"
        ]
        return self._send("\n".join(lines))

    def send(self, text: str) -> bool:
        """Public send — agent aur autonomous loop use karte hain"""
        if not text or not isinstance(text, str):
            logger.error("Invalid text for send")
            return False
        return self._send(text)

    def test(self) -> bool:
        return self._send("✅ <b>Sentinel Pro</b> — Telegram alerts connected!")

    # ── private extractors ──────────────────────────────────────────────────

    def _extract_bugbounty_criticals(self, data: dict) -> list:
        """Extract ALL findings (CRITICAL, HIGH, MEDIUM, LOW)."""
        if not isinstance(data, dict):
            return []
        
        items = []
        _sev = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}  # Include all severities

        def _add(label, findings, key='severity', msg_key='evidence'):
            for f in (findings or []):
                if f.get(key, '').upper() in _sev:
                    items.append(f"[{f[key]}] {label}: {str(f.get(msg_key,''))[:80]}")

        # CVEs
        for c in data.get('cves', {}).get('cves', []):
            if c.get('severity') in _sev:
                items.append(f"[{c['severity']}] CVE: {c['cve_id']} ({c['tech']})")

        # Subdomain takeover
        for v in data.get('takeover', {}).get('vulnerable', []):
            items.append(f"[CRITICAL] Takeover: {v['subdomain']} → {v['service']}")

        # Zone transfer
        for v in data.get('zone_transfer', {}).get('vulnerable', []):
            items.append(f"[CRITICAL] Zone Transfer: {v['ns']} ({v['records_count']} records)")

        # HTTP Smuggling
        for f in data.get('smuggling', {}).get('findings', []):
            items.append(f"[CRITICAL] HTTP Smuggling: {f['technique']}")

        # Nuclei
        for f in data.get('nuclei', {}).get('findings', []):
            if f.get('severity', '').upper() in _sev:
                items.append(f"[{f['severity'].upper()}] Nuclei: {f['name']}")

        _add("CORS",      data.get('cors', {}).get('findings', []),      msg_key='issue')
        _add("Auth",      data.get('auth_bypass', {}).get('findings', []), msg_key='evidence')
        _add("API",       data.get('api', {}).get('findings', []),        msg_key='evidence')
        _add("LFI",       data.get('lfi', {}).get('findings', []),        msg_key='evidence')
        _add("XXE",       data.get('xxe', {}).get('findings', []),        msg_key='evidence')
        _add("SSTI",      data.get('ssti', {}).get('findings', []),       msg_key='payload')
        _add("ProtoPollu",data.get('proto_pollution', {}).get('findings',[]), msg_key='evidence')
        _add("OAuth",     data.get('oauth', {}).get('findings', []),      msg_key='evidence')
        _add("Clickjack", data.get('clickjacking', {}).get('findings', []), msg_key='detail')

        # Fuzzer — sensitive files exposed
        for r in data.get('fuzzer', {}).get('findings', []):
            if r.get('risk') in _sev:
                fname = r.get('url', '').split('/')[-1] or r.get('url', '')
                items.append(f"[{r['risk']}] Sensitive file exposed: {fname}")

        # URL Override / header injection
        for v in (data.get('vulns', {}).get('header_inj', []) +
                  data.get('vulns', {}).get('url_override', [])):
            if v.get('severity', '').upper() in _sev:
                items.append(f"[{v['severity'].upper()}] {v['type']}: {str(v.get('evidence',''))[:60]}")

        # JS secrets
        for s in data.get('js', {}).get('secrets', []):
            if s.get('severity') in _sev:
                items.append(f"[{s['severity']}] JS Secret: {s['type']} in {s['file'].split('/')[-1]}")

        return items

    def _extract_recon_criticals(self, data: dict) -> list:
        """Extract ALL findings (CRITICAL, HIGH, MEDIUM, LOW)."""
        if not isinstance(data, dict):
            return []
        
        items = []
        _sev = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}  # Include all severities

        for rf in data.get('whois', {}).get('risk_flags', []):
            if rf.get('severity') in _sev:
                items.append(f"[{rf['severity']}] {rf['flag']}: {rf['detail']}")

        for f in data.get('github_dorks', {}).get('findings', []):
            items.append(f"[CRITICAL] GitHub Secret: {f['secret_type']} in {f['repo']}")

        for f in data.get('cloud_assets', {}).get('findings', []):
            if f.get('severity') in _sev:
                pub = 'PUBLIC' if f.get('public') else 'private'
                items.append(f"[{f['severity']}] Cloud: {f['provider']} {f['name']} ({pub})")

        for rf in data.get('cert_transparency', {}).get('risk_flags', []):
            if rf.get('severity') in _sev:
                items.append(f"[{rf['severity']}] CT: {rf['flag']}")

        return items
