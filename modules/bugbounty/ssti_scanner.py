"""
SSTI Scanner
Server-Side Template Injection detection for:
Jinja2 (Python), Twig (PHP), Freemarker (Java),
Velocity (Java), Smarty (PHP), Pebble, Mako
"""

import re
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import tor_session

logger = logging.getLogger(__name__)

SSTI_PROBES = [
    ('{{7*7}}',       '49',        'Jinja2/Twig/generic',  'CRITICAL'),
    ('${7*7}',        '49',        'Freemarker/Velocity',  'CRITICAL'),
    ('#{7*7}',        '49',        'Ruby ERB / Pebble',    'CRITICAL'),
    ('<%= 7*7 %>',    '49',        'ERB/EJS',              'CRITICAL'),
    ("{{7*'7'}}",     '7777777',   'Jinja2',               'CRITICAL'),
    ('{7*7}',         '49',        'Smarty',               'CRITICAL'),
    ('{{config}}',    'SECRET_KEY','Jinja2 config leak',   'CRITICAL'),
    ('{{self.__dict__}}', '__dict__', 'Jinja2 object dump','HIGH'),
    ('#set($x=7*7)$x','49',        'Velocity',             'CRITICAL'),
]

SSTI_PARAMS = [
    'name', 'q', 'search', 'query', 'template', 'subject',
    'message', 'content', 'text', 'title', 'body', 'input',
    'username', 'email', 'comment', 'feedback', 'data',
]


class SSTIScanner:

    TIMEOUT     = (2, 4)
    MAX_WORKERS = 20
    MAX_TARGETS = 5
    MAX_PARAMS  = 8

    def run(self, domain: str, endpoints: list = None) -> dict:
        result = {
            'domain': domain,
            'findings': [],
            'total': 0,
            'risk_level': 'LOW',
            'error': None,
        }

        session = tor_session()
        session.verify = False
        session.headers['User-Agent'] = 'Mozilla/5.0'

        base = f"https://{domain}"

        targets = []
        if endpoints:
            for ep in endpoints[:self.MAX_TARGETS]:
                targets.append(ep.get('url') or f"{base}{ep.get('path','')}")
        targets += [base + '/', base + '/search', base + '/contact',
                    base + '/api/v1/render', base + '/template']
        targets = targets[:self.MAX_TARGETS]

        # Build all jobs: (method, url, data, param, payload, expected, engine, severity)
        jobs = []
        for target_url in targets:
            for param in SSTI_PARAMS[:self.MAX_PARAMS]:
                for payload, expected, engine, severity in SSTI_PROBES:
                    get_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                    jobs.append(('GET',  get_url,     None,           param, payload, expected, engine, severity))
                    jobs.append(('POST', target_url,  {param: payload}, param, payload, expected, engine, severity))

        found_params = set()
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as ex:
            futures = {
                ex.submit(self._probe, session, method, url, data,
                          param, payload, expected, engine, severity): param
                for method, url, data, param, payload, expected, engine, severity in jobs
            }
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    key = (finding['param'], finding['engine'])
                    if key not in found_params:
                        found_params.add(key)
                        result['findings'].append(finding)

        result['total'] = len(result['findings'])
        if any(f['severity'] == 'CRITICAL' for f in result['findings']):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in result['findings']):
            result['risk_level'] = 'HIGH'
        elif result['findings']:
            result['risk_level'] = 'MEDIUM'
        return result

    def _probe(self, session, method, url, data,
               param, payload, expected, engine, severity) -> dict:
        try:
            if method == 'GET':
                r = session.get(url, timeout=self.TIMEOUT, allow_redirects=True)
            else:
                r = session.post(url, data=data, timeout=self.TIMEOUT, allow_redirects=True)
            if r.status_code == 404:
                return {}

            # Baseline check — pehle bina payload ke response lo
            try:
                if method == 'GET':
                    base_url = url.split('?')[0] + f'?{param}=SENTINEL_TEST_STRING'
                    base_r = session.get(base_url, timeout=self.TIMEOUT)
                else:
                    base_r = session.post(url, data={param: 'SENTINEL_TEST_STRING'}, timeout=self.TIMEOUT)
                # Agar baseline mein bhi expected string hai to false positive
                if expected in base_r.text:
                    return {}
            except Exception:
                pass

            # Actual check
            if expected in r.text:
                # Extra verify — payload ka result response mein clearly dikhna chahiye
                # Static sites pe '49' common number hai — strict match karo
                import re as _re
                # Response mein payload evaluated form clearly hona chahiye
                strict_patterns = [
                    rf'\b{expected}\b',           # word boundary
                    rf'>{expected}<',              # HTML tag ke andar
                    rf'"result":\s*"{expected}"',  # JSON
                    rf'value="{expected}"',         # form value
                ]
                matched = any(_re.search(p, r.text) for p in strict_patterns)
                if not matched:
                    return {}  # False positive

                return {
                    'severity': severity, 'type': 'SSTI', 'engine': engine,
                    'url': url, 'param': param, 'payload': payload,
                    'expected': expected, 'method': method,
                    'evidence': f"{engine} — payload evaluated: '{payload}' → '{expected}' found",
                }
        except Exception:
            pass
        return {}

