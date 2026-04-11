"""
WHOIS Lookup + Full DNS Records
Covers: WHOIS, A, MX, NS, TXT, SPF, DMARC, CNAME, SOA
"""

import logging
import socket
from datetime import datetime

logger = logging.getLogger(__name__)


class WhoisLookup:

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'whois': self._whois(domain),
            'dns': self._dns_records(domain),
            'timestamp': datetime.now().isoformat()
        }
        result['risk_flags'] = self._analyze_risk(result)
        return result

    # ------------------------------------------------------------------ #
    #  WHOIS                                                               #
    # ------------------------------------------------------------------ #

    def _whois(self, domain: str) -> dict:
        try:
            import whois
            w = whois.whois(domain)
            return {
                'registrar':       self._str(w.registrar),
                'creation_date':   self._date(w.creation_date),
                'expiration_date': self._date(w.expiration_date),
                'updated_date':    self._date(w.updated_date),
                'name_servers':    self._list(w.name_servers),
                'status':          self._list(w.status),
                'emails':          self._list(w.emails),
                'org':             self._str(w.org),
                'country':         self._str(w.country),
                'dnssec':          self._str(w.dnssec),
            }
        except Exception as e:
            logger.warning(f"WHOIS failed for {domain}: {e}")
            return {'error': str(e)}

    # ------------------------------------------------------------------ #
    #  DNS Records                                                         #
    # ------------------------------------------------------------------ #

    def _dns_records(self, domain: str) -> dict:
        try:
            import dns.resolver
            import dns.exception
        except ImportError:
            return {'error': 'dnspython not installed'}

        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                records[rtype] = []
            except Exception as e:
                records[rtype] = []
                logger.debug(f"DNS {rtype} failed for {domain}: {e}")

        # SPF - parse from TXT
        records['SPF'] = [r for r in records.get('TXT', []) if 'v=spf1' in r]

        # DMARC
        try:
            import dns.exception
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
            records['DMARC'] = [str(r) for r in answers]
        except Exception:
            records['DMARC'] = []

        # DKIM (common selectors)
        records['DKIM'] = []
        for selector in ['default', 'google', 'mail', 'dkim', 'k1']:
            try:
                answers = dns.resolver.resolve(
                    f'{selector}._domainkey.{domain}', 'TXT', lifetime=3
                )
                for r in answers:
                    records['DKIM'].append({'selector': selector, 'record': str(r)})
            except Exception:
                pass

        # Reverse DNS for A records
        records['PTR'] = []
        for ip in records.get('A', []):
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                records['PTR'].append({'ip': ip, 'ptr': ptr})
            except Exception:
                pass

        return records

    # ------------------------------------------------------------------ #
    #  Risk Analysis                                                       #
    # ------------------------------------------------------------------ #

    def _analyze_risk(self, result: dict) -> list:
        flags = []
        whois = result.get('whois', {})
        dns   = result.get('dns', {})

        # Recently registered domain
        creation = whois.get('creation_date', '')
        if creation and isinstance(creation, str):
            try:
                from datetime import timezone
                created = datetime.fromisoformat(creation.replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days < 90:
                    flags.append({
                        'flag': 'RECENTLY_REGISTERED',
                        'severity': 'HIGH',
                        'detail': f'Domain registered {age_days} days ago'
                    })
            except Exception:
                pass

        # No SPF record
        if not dns.get('SPF'):
            flags.append({
                'flag': 'NO_SPF',
                'severity': 'MEDIUM',
                'detail': 'No SPF record - email spoofing possible'
            })

        # No DMARC record
        if not dns.get('DMARC'):
            flags.append({
                'flag': 'NO_DMARC',
                'severity': 'MEDIUM',
                'detail': 'No DMARC record - phishing risk'
            })

        # No DKIM
        if not dns.get('DKIM'):
            flags.append({
                'flag': 'NO_DKIM',
                'severity': 'LOW',
                'detail': 'No DKIM selectors found'
            })

        # Zone transfer check (basic)
        for ns in dns.get('NS', []):
            ns_clean = ns.rstrip('.')
            try:
                import dns.zone
                import dns.query
                zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, result['domain'], timeout=3))
                if zone:
                    flags.append({
                        'flag': 'ZONE_TRANSFER_ALLOWED',
                        'severity': 'CRITICAL',
                        'detail': f'Zone transfer allowed on {ns_clean}'
                    })
            except Exception:
                pass

        return flags

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _str(self, val) -> str:
        if val is None:
            return ''
        if isinstance(val, list):
            return str(val[0]) if val else ''
        return str(val)

    def _date(self, val) -> str:
        if val is None:
            return ''
        if isinstance(val, list):
            val = val[0]
        try:
            return val.isoformat()
        except Exception:
            return str(val)

    def _list(self, val) -> list:
        if val is None:
            return []
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)]
