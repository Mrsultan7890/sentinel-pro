"""
Dark Web Content Analyzer — Groq AI powered
Crawled dark web content ko analyze karo: entities, threats, translation
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class DarkWebContentAnalyzer:

    def __init__(self, groq_client=None):
        self.groq = groq_client

    def analyze(self, target: str, darkweb_data: dict) -> dict:
        """Full AI analysis of all collected dark web data"""
        result = {
            'target':          target,
            'entities':        [],
            'threat_summary':  '',
            'risk_level':      'LOW',
            'key_findings':    [],
            'languages':       [],
            'groq_analysis':   None,
        }

        # Collect all text content
        all_text = self._collect_text(darkweb_data)
        if not all_text.strip():
            result['threat_summary'] = 'No dark web content found to analyze.'
            return result

        # Entity extraction (regex-based, no spaCy dependency)
        result['entities'] = self._extract_entities(all_text)

        # Language detection
        result['languages'] = self._detect_languages(all_text)

        # Groq AI analysis
        if self.groq:
            result['groq_analysis'] = self._groq_analyze(target, all_text[:3000])

        # Key findings
        result['key_findings'] = self._extract_key_findings(darkweb_data, result)

        # Overall risk
        result['risk_level'] = self._calculate_risk(darkweb_data, result)
        result['threat_summary'] = self._build_summary(target, result, darkweb_data)

        return result

    def _collect_text(self, data: dict) -> str:
        """Collect all text from darkweb scan results"""
        parts = []

        for item in data.get('onion_results', []):
            if item.get('content'):
                parts.append(item['content'][:1000])

        for item in data.get('paste_results', []):
            if item.get('content'):
                parts.append(item['content'][:500])

        for item in data.get('forum_mentions', []):
            if item.get('post_content'):
                parts.append(item['post_content'])

        for item in data.get('telegram_mentions', {}).get('mentions', []):
            if item.get('message'):
                parts.append(item['message'])

        for v in data.get('ransomware_hits', {}).get('victims', []):
            if v.get('description'):
                parts.append(v['description'])

        return '\n'.join(parts)

    def _extract_entities(self, text: str) -> list:
        """Extract emails, IPs, domains, hashes from text"""
        entities = []
        seen = set()

        patterns = {
            'email':  r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip':     r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|de|uk|onion)\b',
            'hash_md5':    r'\b[a-fA-F0-9]{32}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'btc':    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'api_key': r'\b[A-Za-z0-9_\-]{32,45}\b',
        }

        for etype, pattern in patterns.items():
            for match in re.findall(pattern, text):
                if match not in seen:
                    seen.add(match)
                    entities.append({'type': etype, 'value': match})

        return entities[:50]  # cap at 50

    def _detect_languages(self, text: str) -> list:
        """Simple language detection based on character patterns"""
        langs = ['english']  # default

        if re.search(r'[\u0400-\u04FF]', text):
            langs.append('russian')
        if re.search(r'[\u4E00-\u9FFF]', text):
            langs.append('chinese')
        if re.search(r'[\u0600-\u06FF]', text):
            langs.append('arabic')
        if re.search(r'[\u0900-\u097F]', text):
            langs.append('hindi')

        return langs

    def _groq_analyze(self, target: str, text: str) -> Optional[dict]:
        """Use Groq to analyze dark web content"""
        try:
            prompt = (
                f"You are a cybersecurity threat analyst. Analyze this dark web content about '{target}'.\n\n"
                f"Content:\n{text}\n\n"
                f"Provide a JSON response with:\n"
                f"1. threat_level: LOW/MEDIUM/HIGH/CRITICAL\n"
                f"2. summary: 2-3 sentence threat summary\n"
                f"3. key_threats: list of specific threats found\n"
                f"4. recommended_actions: list of immediate actions\n"
                f"Respond with valid JSON only."
            )

            response = self.groq.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[{'role': 'user', 'content': prompt}],
                max_tokens=500,
                temperature=0.1,
            )

            content = response.choices[0].message.content.strip()
            # Extract JSON
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                import json
                return json.loads(json_match.group())

        except Exception as e:
            logger.debug(f'[ContentAnalyzer] Groq error: {e}')

        return None

    def _extract_key_findings(self, data: dict, analysis: dict) -> list:
        """Extract key findings from all sources"""
        findings = []

        # Ransomware hits
        for v in data.get('ransomware_hits', {}).get('victims', []):
            findings.append({
                'type':     'ransomware_leak',
                'severity': 'CRITICAL',
                'title':    f"Found on {v.get('group', 'unknown').upper()} leak site",
                'detail':   v.get('description', '')[:150],
                'date':     v.get('date', 'N/A'),
            })

        # Telegram mentions
        for m in data.get('telegram_mentions', {}).get('mentions', []):
            findings.append({
                'type':     'telegram_mention',
                'severity': m.get('severity', 'HIGH'),
                'title':    f"Mentioned in Telegram: {m.get('channel', 'N/A')}",
                'detail':   m.get('message', '')[:150],
                'date':     m.get('date', 'N/A'),
            })

        # Emails found
        emails = [e['value'] for e in analysis.get('entities', []) if e['type'] == 'email']
        if emails:
            findings.append({
                'type':     'email_exposure',
                'severity': 'HIGH',
                'title':    f"{len(emails)} email(s) found in dark web content",
                'detail':   ', '.join(emails[:5]),
                'date':     'N/A',
            })

        # Groq findings
        groq = analysis.get('groq_analysis')
        if groq and groq.get('key_threats'):
            for threat in groq['key_threats'][:3]:
                findings.append({
                    'type':     'ai_finding',
                    'severity': groq.get('threat_level', 'MEDIUM'),
                    'title':    f"AI: {threat}",
                    'detail':   '',
                    'date':     'N/A',
                })

        return findings

    def _calculate_risk(self, data: dict, analysis: dict) -> str:
        if data.get('ransomware_hits', {}).get('total_hits', 0) > 0:
            return 'CRITICAL'
        if data.get('telegram_mentions', {}).get('total_hits', 0) > 0:
            return 'HIGH'
        groq = analysis.get('groq_analysis')
        if groq and groq.get('threat_level') in ('CRITICAL', 'HIGH'):
            return groq['threat_level']
        if data.get('onion_results') or data.get('paste_results'):
            return 'MEDIUM'
        return 'LOW'

    def _build_summary(self, target: str, analysis: dict, data: dict) -> str:
        parts = []

        ransomware = data.get('ransomware_hits', {}).get('total_hits', 0)
        telegram   = data.get('telegram_mentions', {}).get('total_hits', 0)
        onion      = len(data.get('onion_results', []))
        pastes     = len(data.get('paste_results', []))
        entities   = len(analysis.get('entities', []))

        if ransomware:
            parts.append(f"⚠️  CRITICAL: {target} found on {ransomware} ransomware leak site(s)")
        if telegram:
            parts.append(f"📢 {telegram} mention(s) in Telegram dark channels")
        if onion:
            parts.append(f"🧅 {onion} .onion site(s) crawled")
        if pastes:
            parts.append(f"📋 {pastes} paste site mention(s)")
        if entities:
            parts.append(f"🔍 {entities} entities extracted (emails, IPs, hashes)")

        groq = analysis.get('groq_analysis')
        if groq and groq.get('summary'):
            parts.append(f"🤖 AI: {groq['summary']}")

        return ' | '.join(parts) if parts else f"No significant dark web presence found for {target}"
