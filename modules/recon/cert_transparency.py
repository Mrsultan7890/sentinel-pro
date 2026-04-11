"""
Certificate Transparency — crt.sh
Queries crt.sh for all certificates issued for a domain.
Extracts subdomains, wildcard certs, expired certs, and suspicious issuances.
"""

import re
import logging
from datetime import datetime, timezone
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)


class CertTransparency:

    def run(self, domain: str) -> dict:
        result = {
            'domain':       domain,
            'subdomains':   [],
            'certificates': [],
            'wildcards':    [],
            'expired':      [],
            'risk_flags':   [],
            'total_certs':  0,
            'total_unique_subdomains': 0,
            'error':        None,
        }

        # ── Query crt.sh JSON API ─────────────────────────────────────────────
        r = rate_limited_get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            namespace='crt',
            timeout=20,
        )
        if not r:
            result['error'] = 'crt.sh unreachable'
            return result

        try:
            certs_raw = r.json()
        except Exception:
            result['error'] = 'Invalid JSON from crt.sh'
            return result

        if not certs_raw:
            result['error'] = 'No certificates found'
            return result

        result['total_certs'] = len(certs_raw)

        seen_subdomains = set()
        seen_cert_ids   = set()
        certs_out       = []

        for cert in certs_raw:
            cert_id = cert.get('id')
            if cert_id in seen_cert_ids:
                continue
            seen_cert_ids.add(cert_id)

            name_value  = cert.get('name_value', '')
            issuer      = cert.get('issuer_name', '')
            not_before  = cert.get('not_before', '')
            not_after   = cert.get('not_after', '')
            common_name = cert.get('common_name', '')

            # Extract all names from name_value (newline separated)
            names = [n.strip().lower() for n in name_value.replace(',', '\n').split('\n')
                     if n.strip() and domain in n.strip()]

            for name in names:
                if name not in seen_subdomains:
                    seen_subdomains.add(name)
                    if name.startswith('*.'):
                        result['wildcards'].append(name)

            # Check expiry
            expired = False
            try:
                exp_dt = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                if exp_dt < datetime.now(timezone.utc):
                    expired = True
                    result['expired'].append({
                        'common_name': common_name,
                        'expired_on':  not_after,
                        'issuer':      self._short_issuer(issuer),
                    })
            except Exception:
                pass

            cert_entry = {
                'id':          cert_id,
                'common_name': common_name,
                'names':       names[:10],
                'issuer':      self._short_issuer(issuer),
                'not_before':  not_before,
                'not_after':   not_after,
                'expired':     expired,
            }
            certs_out.append(cert_entry)

        # Sort subdomains
        result['subdomains'] = sorted(seen_subdomains)
        result['certificates'] = certs_out[:100]  # cap for report
        result['total_unique_subdomains'] = len(seen_subdomains)

        # ── Risk flags ────────────────────────────────────────────────────────
        if result['wildcards']:
            result['risk_flags'].append({
                'severity': 'MEDIUM',
                'flag': 'Wildcard Certificates',
                'detail': f"{len(result['wildcards'])} wildcard cert(s) — broad attack surface",
            })

        if result['expired']:
            result['risk_flags'].append({
                'severity': 'HIGH',
                'flag': 'Expired Certificates',
                'detail': f"{len(result['expired'])} expired cert(s) found in CT logs",
            })

        # Suspicious issuers (Let's Encrypt on sensitive subdomains)
        le_sensitive = [
            c for c in certs_out
            if 'Let\'s Encrypt' in c['issuer']
            and any(k in c['common_name'] for k in
                    ('admin', 'vpn', 'internal', 'dev', 'staging', 'api', 'mail'))
        ]
        if le_sensitive:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag': 'Sensitive Subdomains via LE',
                'detail': f"{len(le_sensitive)} sensitive subdomain(s) with Let's Encrypt certs",
            })

        # Many certs = active target
        if result['total_certs'] > 500:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag': 'High Certificate Volume',
                'detail': f"{result['total_certs']} certificates issued — active/large target",
            })

        return result

    def _short_issuer(self, issuer: str) -> str:
        m = re.search(r'O=([^,]+)', issuer)
        return m.group(1).strip() if m else issuer[:50]
