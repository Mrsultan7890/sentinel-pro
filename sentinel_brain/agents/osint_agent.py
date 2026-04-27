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
OSINT Agent v2 — KaliController directly use karta hai
Person, Email, Phone, Image + Kali tools (sherlock, holehe, theHarvester, phoneinfoga)
"""

import re
import logging
from sentinel_brain.kali_controller import KaliController
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


class OsintAgent:
    NAME = 'osint_agent'

    def __init__(self, kali: KaliController, memory: Memory, sentinel=None):
        self.kali     = kali
        self.memory   = memory
        self.sentinel = sentinel
        self.terminal = kali
        # Groq singleton — person profile summary ke liye
        from modules.ml_engine.groq_llm import get_groq
        self._groq = get_groq()

    def run(self, target: str, target_type: str = None) -> dict:
        target_type = target_type or self._detect_type(target)
        # Domain pe osint skip karo
        if target_type == 'domain':
            return {'_agent_summary': 'domain target — osint skipped', '_risk': 'LOW', 'success': True}
        logger.info(f"[OsintAgent] {target_type} on {target}")
        result = {}

        if self.sentinel:
            try:
                if target_type == 'email':
                    self.sentinel._handle_email(f'email {target}')
                    result = self.sentinel.session_data.get('email', {})
                elif target_type == 'phone':
                    self.sentinel._handle_phone(f'phone {target}')
                    result = self.sentinel.session_data.get('phone', {})
                elif target_type == 'image':
                    self.sentinel._handle_image(f'image {target}')
                    result = self.sentinel.session_data.get('image', {})
                else:
                    self.sentinel._handle_person(f'person {target}')
                    result = self.sentinel.session_data.get('person', {})
            except Exception as e:
                logger.error(f"[OsintAgent] sentinel failed: {e}")
                result = self._kali_osint(target, target_type)
        else:
            # Check if any Kali tools are available before proceeding
            available_tools = []
            if self.kali.tool_available('sherlock'):
                available_tools.append('sherlock')
            if self.kali.tool_available('holehe'):
                available_tools.append('holehe')
            if self.kali.tool_available('phoneinfoga'):
                available_tools.append('phoneinfoga')
            
            if not available_tools and target_type != 'domain':
                logger.warning(f"[OsintAgent] No OSINT tools available for {target_type}")
                result = {
                    'error': f'No OSINT tools available for {target_type}',
                    'risk_level': 'LOW',
                    'target_type': target_type,
                    'social_profiles': [],
                    'available_tools': available_tools
                }
            else:
                result = self._kali_osint(target, target_type)

        risk     = result.get('risk_level', 'LOW')
        profiles = len(result.get('social_profiles', []))
        summary  = f"{target_type} OSINT: {profiles} profiles, risk={risk}"

        self.memory.remember_scan(target, f'osint_{target_type}', risk, summary, result)
        self.memory.remember_decision(target, self.NAME, f'osint_{target_type}', 'OSINT', summary)

        if result.get('total_breaches', 0) > 0:
            self.memory.remember_finding(target, self.NAME, 'HIGH',
                'Breach Data', f"{result.get('total_breaches',0)} breaches", 'Passwords change karo, 2FA enable karo')
        if result.get('total_stealer_logs', 0) > 0:
            self.memory.remember_finding(target, self.NAME, 'CRITICAL',
                'Infostealer Logs', f"{result.get('total_stealer_logs',0)} logs", 'Sab credentials rotate karo')

        result['_agent_summary'] = summary
        result['_risk']          = risk
        result['_target_type']   = target_type

        # Groq — person profile ke liye threat narrative banao
        if self._groq and target_type == 'person':
            profiles = result.get('social_profiles', [])
            if profiles:
                try:
                    platform_list = ', '.join(p['platform'] for p in profiles[:5])
                    groq_summary = self._groq.ask(
                        f"OSINT target found on: {platform_list}. "
                        f"Risk level: {risk}. "
                        f"In 1 sentence: what is the OSINT threat profile of this person?",
                        max_tokens=80
                    )
                    if groq_summary:
                        result['_groq_profile'] = groq_summary
                except Exception as e:
                    logger.debug(f"[OsintAgent] Groq profile failed: {e}")

        return result

    def _detect_type(self, target: str) -> str:
        if re.match(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', target):
            return 'email'
        if re.match(r'\+?\d{10,15}$', target.replace(' ', '')):
            return 'phone'
        if target.endswith(('.jpg', '.jpeg', '.png', '.webp')):
            return 'image'
        # Domain hai to person OSINT mat karo
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$', target):
            return 'domain'
        return 'person'

    def _kali_osint(self, target: str, target_type: str) -> dict:
        """Direct Kali OSINT tools"""
        results = {'target_type': target_type, 'social_profiles': []}

        if target_type == 'person':
            # Sherlock
            if self.kali.tool_available('sherlock'):
                r = self.kali.run(
                    f'sherlock {target} --timeout 5 --print-found 2>/dev/null | head -30',
                    timeout=60
                )
                profiles = []
                for line in r['stdout'].splitlines():
                    if line.startswith('[+]'):
                        url = line.replace('[+]', '').strip()
                        platform = url.split('/')[2] if '/' in url else url
                        profiles.append({'platform': platform, 'url': url, 'username': target})
                results['social_profiles'] = profiles
                results['sherlock_raw']    = r['stdout']

            # Maigret
            if self.kali.tool_available('maigret'):
                r = self.kali.run(
                    f'maigret {target} --print-found --no-color 2>/dev/null | head -30',
                    timeout=60
                )
                results['maigret_raw'] = r['stdout']

        elif target_type == 'email':
            # Holehe
            if self.kali.tool_available('holehe'):
                r = self.kali.run(f'holehe {target} 2>/dev/null | head -30', timeout=30)
                results['holehe_raw'] = r['stdout']
            # MX check
            domain = target.split('@')[-1]
            r = self.kali.run(f'dig +short MX {domain}', timeout=10)
            results['mx'] = r['parsed']

        elif target_type == 'phone':
            # PhoneInfoga
            if self.kali.tool_available('phoneinfoga'):
                r = self.kali.run(f'phoneinfoga scan -n {target} 2>/dev/null | head -30', timeout=30)
                results['phoneinfoga_raw'] = r['stdout']

        results['risk_level'] = 'LOW'
        return results
