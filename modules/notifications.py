"""
Telegram Notifications — instant alerts for CRITICAL/HIGH findings
"""

import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)


class TelegramNotifier:

    def __init__(self, token: str, chat_id: str):
        self.token   = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id)
        self._base   = f"https://api.telegram.org/bot{token}"

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

    def _send(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            r = requests.post(
                f"{self._base}/sendMessage",
                json={"chat_id": self.chat_id, "text": self._clean(text)},
                timeout=10
            )
            return r.status_code == 200
        except Exception as e:
            logger.warning(f"Telegram send failed: {e}")
            return False

    # ── public helpers ──────────────────────────────────────────────────────

    def alert_bugbounty(self, domain: str, data: dict) -> bool:
        if not self.enabled:
            return False
        criticals = self._extract_bugbounty_criticals(data)
        # Also alert if fuzzer found sensitive files (even if main risk shows MEDIUM)
        fuzz_count = data.get('fuzzer', {}).get('total_findings', 0)
        smug_count = len(data.get('smuggling', {}).get('findings', []))
        lfi_count  = data.get('lfi', {}).get('total', 0)
        if not criticals and not fuzz_count and not smug_count and not lfi_count:
            return False
        # Deduplicate by type
        seen_types, unique = set(), []
        for c in criticals:
            t = c.split(']')[0].replace('[','').strip()
            if t not in seen_types:
                seen_types.add(t)
                unique.append(c)
        lines = [
            f"🚨 BUG BOUNTY ALERT",
            f"Target : {domain}",
            f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"Found  : {len(criticals)} critical/high issues",
            f"",
            f"TOP FINDINGS:",
        ]
        for item in unique[:8]:
            # Clean brackets and make readable
            import re
            sev  = re.search(r'\[([A-Z]+)\]', item)
            rest = re.sub(r'\[[A-Z]+\]\s*', '', item).strip()
            icon = '🔴' if sev and sev.group(1) == 'CRITICAL' else '🟠'
            lines.append(f"{icon} {rest[:80]}")
        lines.append(f"")
        lines.append(f"Sentinel Pro — @who_is_the_black_hat")
        return self._send('\n'.join(lines))

    def alert_recon(self, domain: str, data: dict) -> bool:
        if not self.enabled:
            return False
        criticals = self._extract_recon_criticals(data)
        if not criticals:
            return False
        lines = [
            f"🔍 RECON ALERT",
            f"Target : {domain}",
            f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"",
            f"FINDINGS:",
        ]
        for item in criticals[:8]:
            import re
            rest = re.sub(r'\[[A-Z]+\]\s*', '', item).strip()
            lines.append(f"⚠️  {rest[:80]}")
        lines.append(f"")
        lines.append(f"Sentinel Pro — @who_is_the_black_hat")
        return self._send('\n'.join(lines))

    def alert_breach(self, target: str, data: dict):
        if not self.enabled:
            return
        risk = data.get('risk_level', 'LOW')
        if risk not in ('CRITICAL', 'HIGH'):
            return
        lines = [
            f"💀 <b>Breach Alert — {target}</b>",
            f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"⚠️ Risk: <b>{risk}</b>",
            f"📋 Breaches: {data.get('total_breaches', 0)}",
            f"🦠 Stealer logs: {data.get('total_stealer_logs', 0)}",
        ]
        self._send("\n".join(lines))

    def send(self, text: str) -> bool:
        """Public send — agent aur autonomous loop use karte hain"""
        return self._send(text)

    def test(self) -> bool:
        return self._send("✅ <b>Sentinel Pro</b> — Telegram alerts connected!")

    # ── private extractors ──────────────────────────────────────────────────

    def _extract_bugbounty_criticals(self, data: dict) -> list:
        items = []
        _sev = {'CRITICAL', 'HIGH'}

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
        items = []
        _sev = {'CRITICAL', 'HIGH'}

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
