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
SSL/TLS Checker
Certificate details, expiry, grade, weak protocols, vulnerabilities
"""

import ssl
import socket
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SSLChecker:

    def run(self, domain: str, port: int = 443) -> dict:
        result = {
            'domain': domain,
            'port': port,
            'timestamp': datetime.now().isoformat()
        }
        try:
            cert_info = self._get_cert(domain, port)
            result.update(cert_info)
            result['grade']      = self._grade(result)
            result['risk_flags'] = self._risk_flags(result)
        except Exception as e:
            result['error'] = str(e)
            result['grade'] = 'F'
            result['risk_flags'] = [{'flag': 'SSL_ERROR', 'severity': 'CRITICAL', 'detail': str(e)}]
        return result

    def _get_cert(self, domain: str, port: int) -> dict:
        # First try: with verification to get full cert details
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return self._parse_cert(ssock)
        except ssl.SSLCertVerificationError as e:
            logger.debug(f"ssl_checker error: {e}")
        except Exception as e:
            logger.debug(f"ssl_checker error: {e}")
        # Second try: without verification (self-signed certs)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(ssl.get_default_verify_paths().cafile or '/etc/ssl/certs/ca-certificates.crt')
        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return self._parse_cert(ssock)
        except Exception as e:
            logger.debug(f"ssl_checker error: {e}")
        # Last resort: no verification but use cryptography lib for cert parsing
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                return self._parse_cert_binary(ssock, domain)

    def _parse_cert(self, ssock) -> dict:
        cert     = ssock.getpeercert()
        protocol = ssock.version()
        cipher   = ssock.cipher()

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))

        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert['notAfter'],  '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        now        = datetime.now(timezone.utc)
        days_left  = (not_after - now).days

        sans = [val for typ, val in cert.get('subjectAltName', []) if typ == 'DNS']
        is_wildcard   = any(s.startswith('*') for s in sans)
        is_self_signed = subject.get('commonName') == issuer.get('commonName')

        return {
            'subject_cn':     subject.get('commonName', ''),
            'issuer_cn':      issuer.get('commonName', ''),
            'issuer_org':     issuer.get('organizationName', ''),
            'not_before':     not_before.isoformat(),
            'not_after':      not_after.isoformat(),
            'days_remaining': days_left,
            'expired':        days_left < 0,
            'expiring_soon':  0 <= days_left <= 30,
            'sans':           sans,
            'wildcard':       is_wildcard,
            'self_signed':    is_self_signed,
            'protocol':       protocol,
            'cipher_name':    cipher[0] if cipher else '',
            'cipher_bits':    cipher[2] if cipher else 0,
            'serial_number':  cert.get('serialNumber', ''),
        }

    def _parse_cert_binary(self, ssock, domain: str = '') -> dict:
        """Parse cert from binary DER when getpeercert() returns empty (CERT_NONE mode)"""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der, default_backend())
            now  = datetime.now(timezone.utc)

            not_after  = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
            days_left  = (not_after - now).days

            subject_cn = ''
            issuer_cn  = ''
            issuer_org = ''
            try:
                from cryptography.x509.oid import NameOID
                subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                issuer_cn  = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            except Exception as e:
                logger.debug(f"ssl_checker error: {e}")
            sans = []
            try:
                from cryptography.x509 import SubjectAlternativeName, DNSName
                ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
                sans = [n.value for n in ext.value.get_values_for_type(DNSName)]
            except Exception as e:
                logger.debug(f"ssl_checker error: {e}")
            protocol = ssock.version()
            cipher   = ssock.cipher()

            return {
                'subject_cn':     subject_cn,
                'issuer_cn':      issuer_cn,
                'issuer_org':     issuer_org,
                'not_before':     not_before.isoformat(),
                'not_after':      not_after.isoformat(),
                'days_remaining': days_left,
                'expired':        days_left < 0,
                'expiring_soon':  0 <= days_left <= 30,
                'sans':           sans,
                'wildcard':       any(s.startswith('*') for s in sans),
                'self_signed':    subject_cn == issuer_cn,
                'protocol':       protocol,
                'cipher_name':    cipher[0] if cipher else '',
                'cipher_bits':    cipher[2] if cipher else 0,
                'serial_number':  str(cert.serial_number),
            }
        except ImportError:
            # cryptography lib not available, return minimal info
            protocol = ssock.version()
            cipher   = ssock.cipher()
            return {
                'subject_cn': domain,
                'issuer_cn':  'Unknown',
                'issuer_org': 'Unknown',
                'not_before': '', 'not_after': '',
                'days_remaining': 999,
                'expired': False, 'expiring_soon': False,
                'sans': [], 'wildcard': False, 'self_signed': False,
                'protocol': protocol,
                'cipher_name': cipher[0] if cipher else '',
                'cipher_bits': cipher[2] if cipher else 0,
                'serial_number': '',
            }

    def _grade(self, r: dict) -> str:
        if r.get('expired') or r.get('self_signed'):
            return 'F'
        proto = r.get('protocol', '')
        if proto in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
            return 'C'
        bits = r.get('cipher_bits', 0)
        if bits and bits < 128:
            return 'C'
        if r.get('expiring_soon'):
            return 'B'
        if proto == 'TLSv1.2':
            return 'B'
        if proto == 'TLSv1.3':
            return 'A'
        return 'B'

    def _risk_flags(self, r: dict) -> list:
        flags = []

        if r.get('expired'):
            flags.append({'flag': 'CERT_EXPIRED', 'severity': 'CRITICAL',
                          'detail': f"Certificate expired {abs(r['days_remaining'])} days ago"})

        if r.get('self_signed'):
            flags.append({'flag': 'SELF_SIGNED', 'severity': 'HIGH',
                          'detail': 'Certificate is self-signed'})

        if r.get('expiring_soon'):
            flags.append({'flag': 'EXPIRING_SOON', 'severity': 'MEDIUM',
                          'detail': f"Certificate expires in {r['days_remaining']} days"})

        proto = r.get('protocol', '')
        if proto in ('SSLv2', 'SSLv3'):
            flags.append({'flag': 'DEPRECATED_PROTOCOL', 'severity': 'CRITICAL',
                          'detail': f'{proto} is critically vulnerable (POODLE/DROWN)'})
        elif proto in ('TLSv1', 'TLSv1.1'):
            flags.append({'flag': 'WEAK_PROTOCOL', 'severity': 'HIGH',
                          'detail': f'{proto} is deprecated and insecure'})

        bits = r.get('cipher_bits', 0)
        if bits and bits < 128:
            flags.append({'flag': 'WEAK_CIPHER', 'severity': 'HIGH',
                          'detail': f'Cipher key length {bits} bits is too weak'})

        return flags
