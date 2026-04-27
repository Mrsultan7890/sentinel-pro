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
Subdomain Takeover Checker
Resolves CNAME chains and detects dangling pointers to dead services.
"""

import logging
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# Service fingerprints: CNAME suffix -> (service_name, verification_string_in_body)
TAKEOVER_SIGNATURES = {
    'amazonaws.com':          ('AWS S3',            'NoSuchBucket'),
    's3.amazonaws.com':       ('AWS S3',            'NoSuchBucket'),
    'cloudfront.net':         ('AWS CloudFront',    'Bad request'),
    'github.io':              ('GitHub Pages',      "There isn't a GitHub Pages site here"),
    'githubusercontent.com':  ('GitHub',            "There isn't a GitHub Pages site here"),
    'herokuapp.com':          ('Heroku',            'No such app'),
    'herokudns.com':          ('Heroku',            'No such app'),
    'azurewebsites.net':      ('Azure',             'Web App - Unavailable'),
    'azure-api.net':          ('Azure API',         'Web App - Unavailable'),
    'cloudapp.net':           ('Azure',             'Web App - Unavailable'),
    'trafficmanager.net':     ('Azure Traffic Mgr', 'Web App - Unavailable'),
    'zendesk.com':            ('Zendesk',           "Help Center Closed"),
    'freshdesk.com':          ('Freshdesk',         'There is no helpdesk here'),
    'helpscoutdocs.com':      ('HelpScout',         'No settings were found'),
    'ghost.io':               ('Ghost',             'The thing you were looking for is no longer here'),
    'myshopify.com':          ('Shopify',           'Sorry, this shop is currently unavailable'),
    'shopify.com':            ('Shopify',           'Sorry, this shop is currently unavailable'),
    'fastly.net':             ('Fastly',            'Fastly error: unknown domain'),
    'pantheonsite.io':        ('Pantheon',          '404 error unknown site'),
    'domains.tumblr.com':     ('Tumblr',            'Whatever you were looking for'),
    'wpengine.com':           ('WP Engine',         'The site you were looking for'),
    'surge.sh':               ('Surge',             "project not found"),
    'bitbucket.io':           ('Bitbucket',         'Repository not found'),
    'netlify.app':            ('Netlify',           'Not Found'),
    'netlify.com':            ('Netlify',           'Not Found'),
    'readthedocs.io':         ('ReadTheDocs',       'unknown to Read the Docs'),
    'readme.io':              ('Readme',            'Project doesnt exist'),
    'statuspage.io':          ('Statuspage',        'You are being redirected'),
    'uservoice.com':          ('UserVoice',         'This UserVoice subdomain'),
    'desk.com':               ('Desk',              'Please try again'),
    'tilda.ws':               ('Tilda',             'Please renew your subscription'),
    'webflow.io':             ('Webflow',           'The page you are looking for'),
    'strikingly.com':         ('Strikingly',        'page not found'),
    'cargo.site':             ('Cargo',             'If you\'re the site owner'),
}


class SubdomainTakeover:

    def run(self, domain: str, subdomains: list = None) -> dict:
        result = {
            'domain':      domain,
            'vulnerable':  [],
            'checked':     0,
            'risk_level':  'LOW',
            'error':       None
        }

        targets = subdomains or self._get_subdomains(domain)
        if not targets:
            result['error'] = 'No subdomains to check'
            return result

        result['checked'] = len(targets)

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._check, sub): sub for sub in targets}
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result['vulnerable'].append(finding)

        if result['vulnerable']:
            severities = [f['severity'] for f in result['vulnerable']]
            result['risk_level'] = 'CRITICAL' if 'CRITICAL' in severities else 'HIGH'

        return result

    def _get_subdomains(self, domain: str) -> list:
        """Fallback: resolve common subdomains if none passed in."""
        common = ['www', 'mail', 'ftp', 'dev', 'staging', 'api', 'cdn',
                  'static', 'assets', 'blog', 'shop', 'app', 'portal',
                  'admin', 'beta', 'test', 'demo', 'docs', 'help', 'support']
        return [f"{sub}.{domain}" for sub in common]

    def _check(self, subdomain: str) -> dict | None:
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            cname   = str(answers[0].target).rstrip('.')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return None
        except Exception:
            return None

        # Check if CNAME points to a known takeover-prone service
        matched_service = None
        matched_sig     = None
        for suffix, (service, sig) in TAKEOVER_SIGNATURES.items():
            if cname.endswith(suffix):
                matched_service = service
                matched_sig     = sig
                break

        if not matched_service:
            return None

        # Verify: try to reach the subdomain and check for fingerprint string
        vulnerable = False
        evidence   = f'CNAME → {cname} ({matched_service})'

        for scheme in ('https', 'http'):
            resp = rate_limited_get(f'{scheme}://{subdomain}', namespace='takeover',
                                    timeout=8, allow_redirects=True,
                                    headers={'User-Agent': 'Mozilla/5.0'})
            if resp is not None:
                if matched_sig.lower() in resp.text.lower():
                    vulnerable = True
                    evidence   = f'CNAME → {cname} | Body contains: "{matched_sig}"'
                break
            # resp is None = network error / timeout — not enough to confirm

        if not vulnerable:
            return None

        return {
            'subdomain': subdomain,
            'cname':     cname,
            'service':   matched_service,
            'evidence':  evidence,
            'severity':  'CRITICAL',
            'detail':    f'{subdomain} CNAME points to unclaimed {matched_service} resource'
        }
