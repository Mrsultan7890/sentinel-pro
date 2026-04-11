"""
ASN / IP Range Mapper
- Resolves domain → IP → ASN via BGP data (bgp.he.net, ipinfo.io, rdap)
- Fetches all CIDR prefixes announced by the ASN
- Maps sibling ASNs for the same org
- Flags interesting prefixes (cloud, hosting, datacenter)
"""

import re
import logging
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

CLOUD_ASNS = {
    'AS16509': 'Amazon AWS',
    'AS14618': 'Amazon AWS',
    'AS15169': 'Google Cloud',
    'AS396982': 'Google Cloud',
    'AS8075':  'Microsoft Azure',
    'AS8069':  'Microsoft Azure',
    'AS13335': 'Cloudflare',
    'AS20940': 'Akamai',
    'AS16276': 'OVH',
    'AS14061': 'DigitalOcean',
    'AS63949': 'Linode/Akamai',
    'AS24940': 'Hetzner',
    'AS46606': 'Unified Layer',
    'AS2635':  'Automattic',
    'AS54113': 'Fastly',
    'AS22822': 'Limelight',
}


class ASNMapper:

    def run(self, domain: str) -> dict:
        result = {
            'domain':    domain,
            'ips':       [],
            'asns':      [],
            'prefixes':  [],
            'org_asns':  [],
            'risk_flags': [],
            'total_ips_in_range': 0,
            'error':     None,
        }

        # ── 1. Resolve IPs ────────────────────────────────────────────────────
        import socket
        ips = []
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = list({i[4][0] for i in infos if ':' not in i[4][0]})  # IPv4 only
        except Exception as e:
            result['error'] = f"DNS resolution failed: {e}"
            return result

        result['ips'] = ips

        # ── 2. ASN lookup per IP via ipinfo.io ────────────────────────────────
        seen_asns = set()
        for ip in ips[:3]:
            r = rate_limited_get(f"https://ipinfo.io/{ip}/json", namespace='asn', timeout=8)
            if not r:
                continue
            try:
                data = r.json()
                org  = data.get('org', '')          # e.g. "AS16509 Amazon.com, Inc."
                asn_match = re.match(r'(AS\d+)\s+(.*)', org)
                if not asn_match:
                    continue
                asn_id   = asn_match.group(1)
                asn_name = asn_match.group(2)
                if asn_id in seen_asns:
                    continue
                seen_asns.add(asn_id)

                asn_entry = {
                    'asn':      asn_id,
                    'name':     asn_name,
                    'ip':       ip,
                    'country':  data.get('country', ''),
                    'city':     data.get('city', ''),
                    'hostname': data.get('hostname', ''),
                    'is_cloud': asn_id in CLOUD_ASNS,
                    'cloud_provider': CLOUD_ASNS.get(asn_id, ''),
                }
                result['asns'].append(asn_entry)

                if asn_id in CLOUD_ASNS:
                    result['risk_flags'].append({
                        'severity': 'INFO',
                        'flag': 'Cloud Hosted',
                        'detail': f"{ip} is on {CLOUD_ASNS[asn_id]} ({asn_id})",
                    })

                # ── 3. Fetch prefixes for this ASN ────────────────────────────
                prefixes = self._fetch_prefixes(asn_id)
                result['prefixes'].extend(prefixes)

                # ── 4. Sibling ASNs (same org) ────────────────────────────────
                org_asns = self._fetch_org_asns(asn_id, asn_name)
                result['org_asns'].extend(
                    a for a in org_asns if a not in seen_asns
                )

            except Exception as e:
                logger.debug(f"ASN lookup {ip}: {e}")

        # ── 5. Count total IPs in announced ranges ────────────────────────────
        total = 0
        for p in result['prefixes']:
            try:
                import ipaddress
                net = ipaddress.ip_network(p['prefix'], strict=False)
                total += net.num_addresses
            except Exception:
                pass
        result['total_ips_in_range'] = total

        # Flag large IP ranges
        if total > 65536:
            result['risk_flags'].append({
                'severity': 'INFO',
                'flag': 'Large IP Range',
                'detail': f"Org controls {total:,} IPs across {len(result['prefixes'])} prefixes",
            })

        return result

    def _fetch_prefixes(self, asn_id: str) -> list:
        """Fetch announced prefixes from bgpview.io"""
        asn_num = asn_id.replace('AS', '')
        r = rate_limited_get(
            f"https://api.bgpview.io/asn/{asn_num}/prefixes",
            namespace='asn', timeout=5
        )
        if not r:
            return []
        try:
            data = r.json()
            prefixes = []
            for p in data.get('data', {}).get('ipv4_prefixes', [])[:50]:
                prefixes.append({
                    'prefix':      p.get('prefix', ''),
                    'name':        p.get('name', ''),
                    'description': p.get('description', ''),
                    'country':     p.get('country_code', ''),
                })
            return prefixes
        except Exception:
            return []

    def _fetch_org_asns(self, asn_id: str, asn_name: str) -> list:
        """Find other ASNs belonging to the same org via bgpview upstreams"""
        asn_num = asn_id.replace('AS', '')
        r = rate_limited_get(
            f"https://api.bgpview.io/asn/{asn_num}/upstreams",
            namespace='asn', timeout=5
        )
        if not r:
            return []
        try:
            data = r.json().get('data', {})
            related = []
            for peer in data.get('ipv4_upstreams', []):
                peer_asn = f"AS{peer.get('asn', '')}"
                if peer_asn and peer_asn != asn_id:
                    related.append(peer_asn)
            return list(set(related))[:10]
        except Exception:
            return []
