"""
Go Scraper Bridge
Runs the Go scraper binary and extracts structured data for recon mode.
Extracts: emails, links, subdomains, tech stack hints, exposed files
"""

import json
import re
import subprocess
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

BASE_DIR    = Path(__file__).resolve().parents[2]
SCRAPER_BIN = BASE_DIR / 'scraper' / 'scraper'


class GoScraperBridge:

    def run(self, domain: str) -> dict:
        result = {
            'domain':      domain,
            'raw_pages':   [],
            'emails':      [],
            'links':       [],
            'subdomains':  [],
            'tech_hints':  [],
            'exposed_files': [],
            'error':       None,
            'timestamp':   datetime.now().isoformat()
        }

        if not SCRAPER_BIN.exists():
            result['error'] = f"Scraper binary not found: {SCRAPER_BIN}"
            logger.warning(result['error'])
            return result

        try:
            proc = subprocess.run(
                [str(SCRAPER_BIN), domain],
                capture_output=True,
                text=True,
                timeout=120
            )
            if proc.returncode != 0:
                result['error'] = f"Scraper exited {proc.returncode}: {proc.stderr[:200]}"
                logger.warning(result['error'])
                return result

            raw = json.loads(proc.stdout)
            result['raw_pages'] = raw

        except subprocess.TimeoutExpired:
            result['error'] = "Scraper timed out after 120s"
            logger.warning(result['error'])
            return result
        except json.JSONDecodeError as e:
            result['error'] = f"Invalid JSON from scraper: {e}"
            logger.warning(result['error'])
            return result
        except Exception as e:
            result['error'] = str(e)
            logger.warning(f"GoScraperBridge error: {e}")
            return result

        # Parse scraped pages
        result.update(self._extract_entities(raw, domain))
        return result

    # ------------------------------------------------------------------ #
    #  Entity Extraction from scraped HTML                                 #
    # ------------------------------------------------------------------ #

    def _extract_entities(self, pages: list, domain: str) -> dict:
        emails       = set()
        links        = set()
        subdomains   = set()
        tech_hints   = set()
        exposed_files = set()

        email_re    = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
        link_re     = re.compile(r'https?://[^\s\'"<>]+')
        subdomain_re = re.compile(
            r'(?:href|src|action|url)[=:\s]+["\']?(https?://([a-zA-Z0-9\-]+\.' +
            re.escape(domain) + r')[^\s\'"<>]*)', re.IGNORECASE
        )

        # Tech fingerprint patterns — strict matching only
        tech_patterns = {
            'WordPress':   [r'wp-content/', r'wp-includes/', r'/wordpress/'],
            'Drupal':      [r'sites/default/files', r'drupal\.js'],
            'Joomla':      [r'/components/com_', r'joomla!'],
            'Laravel':     [r'laravel_session', r'_token.*csrf.*laravel'],
            'Django':      [r'csrfmiddlewaretoken', r'django-admin'],
            'React':       [r'react-dom\.', r'__REACT_DEVTOOLS', r'data-reactroot'],
            'Angular':     [r'ng-version=', r'angular\.min\.js'],
            'Vue':         [r'vue\.min\.js', r'__vue__', r'data-v-[a-f0-9]{8}'],
            'jQuery':      [r'jquery\.min\.js', r'jquery-\d+\.\d+'],
            'Bootstrap':   [r'bootstrap\.min\.css', r'bootstrap\.bundle\.min\.js'],
            'ASP.NET':     [r'__VIEWSTATE', r'__EVENTVALIDATION', r'\.aspx"'],
            'PHP':         [r'X-Powered-By: PHP', r'\.php\?', r'\.php"'],
            'Cloudflare':  [r'cf-ray:', r'__cf_bm'],
        }

        # Exposed file patterns (interesting findings)
        exposed_patterns = [
            r'\.env', r'config\.php', r'wp-config\.php',
            r'\.git/', r'backup\.zip', r'backup\.sql',
            r'phpinfo\.php', r'adminer\.php', r'\.htaccess',
        ]

        for page in pages:
            if page.get('status') != 'success':
                continue
            content = page.get('content', '')
            url     = page.get('url', '')

            # Emails
            for e in email_re.findall(content):
                if not e.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                    emails.add(e.lower())

            # Links
            for link in link_re.findall(content):
                link = link.rstrip('.,;)')
                if len(link) < 200:
                    links.add(link)

            # Subdomains
            for match in subdomain_re.finditer(content):
                sub = match.group(2).lower()
                if sub != domain:
                    subdomains.add(sub)

            # Tech hints
            content_lower = content.lower()
            for tech, patterns in tech_patterns.items():
                for pat in patterns:
                    if re.search(pat, content_lower):
                        tech_hints.add(tech)
                        break

            # Exposed files
            for pat in exposed_patterns:
                if re.search(pat, url + content_lower):
                    exposed_files.add(pat.replace(r'\.', '.').replace('/', ''))

        return {
            'emails':        sorted(emails),
            'links':         sorted(links)[:100],   # cap at 100
            'subdomains':    sorted(subdomains),
            'tech_hints':    sorted(tech_hints),
            'exposed_files': sorted(exposed_files),
        }
