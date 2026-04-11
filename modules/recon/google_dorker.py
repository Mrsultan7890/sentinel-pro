import logging
import time
import requests
import config
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

DORK_TEMPLATES = {
    'exposed_files':    'site:{target} ext:sql OR ext:bak OR ext:env OR ext:log OR ext:conf',
    'login_pages':      'site:{target} inurl:login OR inurl:admin OR inurl:signin OR inurl:dashboard',
    'config_files':     'site:{target} inurl:config OR inurl:setup OR inurl:install',
    'api_endpoints':    'site:{target} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:swagger',
    'error_pages':      'site:{target} "sql syntax" OR "mysql_fetch" OR "ORA-" OR "stack trace"',
    'open_dirs':        'site:{target} intitle:"index of" OR intitle:"directory listing"',
    'git_exposed':      'site:{target} inurl:.git OR inurl:.svn OR inurl:.env',
    'docs_exposed':     'site:{target} ext:pdf OR ext:doc OR ext:docx OR ext:xls filetype:pdf',
    'subdomains':       'site:*.{target} -www',
    'pastebin_leaks':   'site:pastebin.com "{target}"',
    'github_leaks':     'site:github.com "{target}" password OR secret OR key',
    'cached_pages':     'cache:{target}',
}

RISK_MAP = {
    'exposed_files':  'CRITICAL',
    'git_exposed':    'CRITICAL',
    'error_pages':    'HIGH',
    'open_dirs':      'HIGH',
    'pastebin_leaks': 'HIGH',
    'github_leaks':   'HIGH',
    'login_pages':    'MEDIUM',
    'config_files':   'MEDIUM',
    'api_endpoints':  'LOW',
    'docs_exposed':   'LOW',
    'subdomains':     'INFO',
    'cached_pages':   'INFO',
}

class GoogleDorker:
    SERP_URL = 'https://serpapi.com/search'
    TIMEOUT  = 10

    def __init__(self):
        self.serp_key = config.SERPAPI_KEY

    def run(self, target: str, dork_types: list = None) -> dict:
        result = {
            'target': target,
            'findings': [],
            'by_category': {},
            'total_results': 0,
            'risk_level': 'LOW',
            'error': None
        }

        selected = dork_types or list(DORK_TEMPLATES.keys())

        if self.serp_key:
            self._run_serpapi(target, selected, result)
        else:
            self._run_fallback(target, selected, result)

        result['total_results'] = len(result['findings'])

        severities = [f['severity'] for f in result['findings']]
        if 'CRITICAL' in severities:
            result['risk_level'] = 'CRITICAL'
        elif 'HIGH' in severities:
            result['risk_level'] = 'HIGH'
        elif 'MEDIUM' in severities:
            result['risk_level'] = 'MEDIUM'

        return result

    def _run_serpapi(self, target: str, selected: list, result: dict):
        for dork_type in selected:
            query = DORK_TEMPLATES[dork_type].format(target=target)
            resp = rate_limited_get(self.SERP_URL, namespace='serpapi', params={
                'q': query, 'api_key': self.serp_key,
                'num': 10, 'engine': 'google'
            }, timeout=self.TIMEOUT)
            if resp and resp.status_code == 200:
                data     = resp.json()
                organic  = data.get('organic_results', [])
                severity = RISK_MAP.get(dork_type, 'LOW')
                category_results = []
                for r in organic:
                    entry = {
                        'dork_type': dork_type,
                        'query':     query,
                        'title':     r.get('title', ''),
                        'url':       r.get('link', ''),
                        'snippet':   r.get('snippet', '')[:200],
                        'severity':  severity
                    }
                    result['findings'].append(entry)
                    category_results.append(entry)
                result['by_category'][dork_type] = category_results

    def _run_fallback(self, target: str, selected: list, result: dict):
        """No API key — return dork queries for manual use.
        Note: These are NOT executed automatically. Set SERPAPI_KEY to auto-execute.
        """
        result['error'] = 'SERPAPI_KEY not set — manual dork URLs returned (not executed)'
        for dork_type in selected:
            query    = DORK_TEMPLATES[dork_type].format(target=target)
            severity = RISK_MAP.get(dork_type, 'LOW')
            entry = {
                'dork_type': dork_type,
                'query':     query,
                'url':       f'https://www.google.com/search?q={requests.utils.quote(query)}',
                'title':     f'[Manual] {dork_type}',
                'snippet':   'Set SERPAPI_KEY to auto-execute',
                'severity':  severity
            }
            result['findings'].append(entry)
            result['by_category'].setdefault(dork_type, []).append(entry)
