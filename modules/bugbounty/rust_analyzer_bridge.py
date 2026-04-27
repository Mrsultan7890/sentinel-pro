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
Rust Analyzer Bridge
Feeds bugbounty findings (exposed endpoint content) to the Rust analyzer binary.
Rust uses rayon (parallel) to extract entities and find correlations at native speed.
"""

import json
import subprocess
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

import config as _config
BASE_DIR     = _config.get_base_dir()
ANALYZER_BIN = _config.ANALYZER_BIN


class RustAnalyzerBridge:

    def run(self, bugbounty_data: dict) -> dict:
        """
        Takes bugbounty scan result dict, builds input for Rust analyzer,
        runs it, returns correlation + risk analysis.
        """
        result = {
            'domain':               bugbounty_data.get('target', ''),
            'rust_analysis':        None,
            'error':                None,
            'entities_found':       {},
            'correlations':         [],
            'risk_indicators':      [],
            'timestamp':            datetime.now().isoformat()
        }

        if not ANALYZER_BIN.exists():
            result['error'] = f"Analyzer binary not found: {ANALYZER_BIN}"
            logger.warning(result['error'])
            return result

        # Build input payload for Rust analyzer
        payload = self._build_payload(bugbounty_data)

        if not payload['scraped_data']:
            result['error'] = "No content to analyze from bugbounty findings"
            return result

        try:
            proc = subprocess.run(
                [str(ANALYZER_BIN)],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=60
            )
            if proc.returncode != 0:
                result['error'] = f"Analyzer exited {proc.returncode}: {proc.stderr[:200]}"
                logger.warning(result['error'])
                return result

            analysis = json.loads(proc.stdout)
            result['rust_analysis'] = analysis

            # Flatten for easy display
            result['entities_found'] = {
                'emails':    payload['entities']['emails'],
                'usernames': payload['entities']['usernames'],
                'urls':      payload['entities']['urls'][:20],
            }
            result['correlations']    = analysis.get('cross_platform_matches', [])
            result['risk_indicators'] = analysis.get('risk_indicators', [])

        except subprocess.TimeoutExpired:
            result['error'] = "Rust analyzer timed out after 60s"
            logger.warning(result['error'])
        except json.JSONDecodeError as e:
            result['error'] = f"Invalid JSON from analyzer: {e}"
            logger.warning(result['error'])
        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"RustAnalyzerBridge error: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  Build Rust analyzer input from bugbounty findings                  #
    # ------------------------------------------------------------------ #

    def _build_payload(self, data: dict) -> dict:
        """
        Rust analyzer expects:
        {
          target: str,
          scraped_data: [{url, content, status}],
          entities: {emails, phones, usernames, urls, locations, names},
          timestamp: float
        }
        """
        import re
        import time

        scraped_data = []
        all_content  = []

        # From exposed endpoints - these have actual content
        for ep in data.get('endpoints', {}).get('exposed', []):
            snippet = ep.get('snippet', '')
            url     = ep.get('url', '')
            if snippet:
                scraped_data.append({
                    'url':     url,
                    'content': snippet,
                    'status':  'success'
                })
                all_content.append(snippet)

        # From port banners
        for port in data.get('ports', {}).get('open_ports', []):
            banner = port.get('banner', '')
            if banner:
                scraped_data.append({
                    'url':     f"{data.get('target', '')}:{port['port']}",
                    'content': banner,
                    'status':  'success'
                })
                all_content.append(banner)

        # From SSL cert info
        ssl = data.get('ssl', {})
        if ssl and not ssl.get('error'):
            ssl_content = (
                f"SSL issuer: {ssl.get('issuer_cn', '')} "
                f"org: {ssl.get('issuer_org', '')} "
                f"SANs: {' '.join(ssl.get('sans', []))}"
            )
            scraped_data.append({
                'url':     f"https://{data.get('target', '')}",
                'content': ssl_content,
                'status':  'success'
            })
            all_content.append(ssl_content)

        combined = ' '.join(all_content)

        # Extract entities from combined content
        emails    = list(set(re.findall(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', combined
        )))
        phones    = list(set(re.findall(
            r'(\+\d{1,3}[\-.\s]?)?\(?\d{3}\)?[\-.\s]?\d{3}[\-.\s]?\d{4}', combined
        )))
        urls      = list(set(re.findall(r'https?://[^\s\'"<>]{5,100}', combined)))
        usernames = list(set(re.findall(r'@([a-zA-Z0-9_]{3,20})', combined)))

        return {
            'target':       data.get('target', ''),
            'scraped_data': scraped_data,
            'entities': {
                'emails':    emails,
                'phones':    phones,
                'usernames': usernames,
                'urls':      urls,
                'locations': [],
                'names':     []
            },
            'timestamp': time.time()
        }
