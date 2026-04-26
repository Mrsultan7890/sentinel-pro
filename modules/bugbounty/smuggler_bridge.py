"""
HTTP Request Smuggling Bridge
Calls the Go smuggler binary and returns structured findings.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

import config as _config
SMUGGLER_BIN = _config.get_base_dir() / 'smuggler' / 'smuggler'


class SmugglerBridge:

    TIMEOUT = 60

    def run(self, domain: str) -> dict:
        result = {
            'domain':   domain,
            'findings': [],
            'total':    0,
            'risk_level': 'LOW',
            'error':    None
        }

        if not SMUGGLER_BIN.exists():
            result['error'] = f'smuggler binary not found — run: cd smuggler && go build -o smuggler main.go'
            return result

        try:
            proc = subprocess.run(
                [str(SMUGGLER_BIN), domain],
                capture_output=True, text=True, timeout=self.TIMEOUT
            )
            data = json.loads(proc.stdout)
            result['findings'] = data.get('findings', [])
            result['total']    = data.get('total', 0)
            if data.get('error'):
                result['error'] = data['error']
        except subprocess.TimeoutExpired:
            result['error'] = 'Smuggler timed out'
        except json.JSONDecodeError as e:
            result['error'] = f'Invalid JSON from smuggler: {e}'
        except Exception as e:
            result['error'] = str(e)

        if result['findings']:
            sevs = [f.get('severity', 'LOW') for f in result['findings']]
            result['risk_level'] = 'CRITICAL' if 'CRITICAL' in sevs else 'HIGH'

        return result
