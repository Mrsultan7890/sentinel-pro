"""
DNS Zone Transfer Checker
Attempts AXFR on all authoritative NS records.
A successful transfer leaks the entire DNS zone — CRITICAL severity.
"""

import logging
import dns.resolver
import dns.zone
import dns.query
import dns.exception

logger = logging.getLogger(__name__)


class DNSZoneTransfer:

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'ns_servers': [],
            'vulnerable': [],
            'records_leaked': [],
            'total_records': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        # Resolve NS records
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS', lifetime=10)
            ns_servers = [str(r.target).rstrip('.') for r in ns_answers]
        except Exception as e:
            result['error'] = f"NS lookup failed: {e}"
            return result

        result['ns_servers'] = ns_servers

        for ns in ns_servers:
            try:
                # Resolve NS to IP
                try:
                    ns_ip = str(dns.resolver.resolve(ns, 'A', lifetime=5)[0])
                except Exception:
                    ns_ip = ns

                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8, lifetime=10))
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append({
                                'name':  str(name),
                                'type':  dns.rdatatype.to_text(rdataset.rdtype),
                                'value': str(rdata),
                            })

                result['vulnerable'].append({
                    'ns': ns,
                    'ns_ip': ns_ip,
                    'records_count': len(records),
                })
                result['records_leaked'].extend(records[:100])  # cap at 100
                result['total_records'] += len(records)
                logger.warning(f"Zone transfer SUCCESS on {ns} for {domain} — {len(records)} records")

            except (dns.exception.FormError, EOFError, ConnectionRefusedError, TimeoutError):
                # Transfer refused — expected / secure
                pass
            except Exception as e:
                logger.debug(f"ZoneTransfer {ns}: {e}")

        if result['vulnerable']:
            result['risk_level'] = 'CRITICAL'

        return result
