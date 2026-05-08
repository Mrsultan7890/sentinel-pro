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
WHOIS Lookup + Full DNS Records
Covers: WHOIS, A, MX, NS, TXT, SPF, DMARC, CNAME, SOA
"""

import logging
import socket
from datetime import datetime

logger = logging.getLogger(__name__)


class WhoisLookup:

    def run(self, domain: str) -> dict:
        if not domain or not isinstance(domain, str):
            logger.error('Invalid domain')
            return {'error': 'Invalid domain'}
        
        # Domain validation
        domain = domain.strip().lower()
        if len(domain) > 253 or not domain.replace('.', '').replace('-', '').isalnum():
            logger.error(f'Invalid domain format: {domain}')
            return {'error': 'Invalid domain format'}
        
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
            if not w:
                return {'error': 'No WHOIS data'}
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
        except ImportError as e:
            logger.error(f"python-whois not installed: {e}")
            return {'error': 'python-whois not installed'}
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
            logger.error('dnspython not installed')
            return {'error': 'dnspython not installed'}

        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                records[rtype] = []
                logger.debug(f"DNS {rtype} not found for {domain}: {e}")
            except Exception as e:
                records[rtype] = []
                logger.error(f"DNS {rtype} failed for {domain}: {e}")

        # SPF - parse from TXT
        records['SPF'] = [r for r in records.get('TXT', []) if 'v=spf1' in r]

        # DMARC
        try:
            import dns.exception
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
            records['DMARC'] = [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            records['DMARC'] = []
            logger.debug(f"DMARC not found: {e}")
        except Exception as e:
            records['DMARC'] = []
            logger.error(f"DMARC query failed: {e}")

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
            except (socket.herror, socket.gaierror) as e:
                logger.debug(f"PTR lookup failed for {ip}: {e}")
            except Exception as e:
                logger.error(f"PTR lookup error for {ip}: {e}")

        return records

    # ------------------------------------------------------------------ #
    #  Risk Analysis                                                       #
    # ------------------------------------------------------------------ #

    def _analyze_risk(self, result: dict) -> list:
        if not isinstance(result, dict):
            return []
        
        flags = []
        whois = result.get('whois', {})
        dns   = result.get('dns', {})
        
        if not isinstance(whois, dict) or not isinstance(dns, dict):
            return flags

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
            if not isinstance(ns, str):
                continue
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
            except (dns.exception.FormError, dns.exception.Timeout) as e:
                logger.debug(f"Zone transfer check failed for {ns_clean}: {e}")
            except Exception as e:
                logger.debug(f"Zone transfer error for {ns_clean}: {e}")

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
