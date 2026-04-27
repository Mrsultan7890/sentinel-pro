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
Nuclei Template Runner Bridge
Runs nuclei against target, parses JSON findings, returns structured results.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class NucleiBridge:

    # Template tags to run — covers most bug bounty findings
    DEFAULT_TAGS = 'cve,misconfig,exposure,takeover,default-login,xss,sqli,ssrf,lfi,rce'
    SEVERITY     = 'critical,high,medium'
    TIMEOUT      = 300  # 5 min max

    def run(self, domain: str, tags: str = None, severity: str = None) -> dict:
        result = {
            'domain':    domain,
            'findings':  [],
            'total':     0,
            'critical':  0,
            'high':      0,
            'medium':    0,
            'risk_level': 'LOW',
            'nuclei_version': None,
            'error':     None
        }

        nuclei_bin = shutil.which('nuclei')
        if not nuclei_bin:
            result['error'] = 'nuclei not installed — run: apt install nuclei'
            return result

        # Get version
        try:
            v = subprocess.run([nuclei_bin, '--version'],
                               capture_output=True, text=True, timeout=10)
            for line in (v.stdout + v.stderr).splitlines():
                if 'Engine Version' in line or 'nuclei' in line.lower():
                    result['nuclei_version'] = line.strip()
                    break
        except Exception:
            pass

        cmd = [
            nuclei_bin,
            '-u',       f'https://{domain}',
            '-tags',    tags or self.DEFAULT_TAGS,
            '-severity', severity or self.SEVERITY,
            '-json',
            '-silent',
            '-no-color',
            '-timeout', '10',
            '-rate-limit', '50',
            '-bulk-size', '25',
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.TIMEOUT
            )
        except subprocess.TimeoutExpired:
            result['error'] = f'Nuclei timed out after {self.TIMEOUT}s'
            return result
        except Exception as e:
            result['error'] = str(e)
            return result

        # Parse JSONL output (one JSON object per line)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                item = json.loads(line)
                finding = self._parse_finding(item)
                result['findings'].append(finding)
            except json.JSONDecodeError:
                continue

        result['findings'].sort(
            key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(
                x['severity'].lower(), 4)
        )
        result['total']    = len(result['findings'])
        result['critical'] = sum(1 for f in result['findings'] if f['severity'].lower() == 'critical')
        result['high']     = sum(1 for f in result['findings'] if f['severity'].lower() == 'high')
        result['medium']   = sum(1 for f in result['findings'] if f['severity'].lower() == 'medium')

        if result['critical'] > 0:
            result['risk_level'] = 'CRITICAL'
        elif result['high'] > 0:
            result['risk_level'] = 'HIGH'
        elif result['medium'] > 0:
            result['risk_level'] = 'MEDIUM'

        # Capture stderr warnings (template errors etc.) but don't fail
        if proc.stderr and not result['findings']:
            result['error'] = proc.stderr[:300]

        return result

    def _parse_finding(self, item: dict) -> dict:
        info = item.get('info', {})
        return {
            'template_id': item.get('template-id', ''),
            'name':        info.get('name', ''),
            'severity':    info.get('severity', 'unknown'),
            'description': info.get('description', '')[:200],
            'tags':        info.get('tags', []),
            'url':         item.get('matched-at', item.get('host', '')),
            'type':        item.get('type', ''),
            'matcher':     item.get('matcher-name', ''),
            'extracted':   item.get('extracted-results', []),
            'reference':   info.get('reference', [])[:3],
            'cvss_score':  info.get('classification', {}).get('cvss-score', None),
            'cve_id':      info.get('classification', {}).get('cve-id', []),
        }
