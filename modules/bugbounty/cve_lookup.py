"""
CVE Lookup
NVD (National Vulnerability Database) API v2 se CVEs fetch karta hai
detected technologies ke liye CVSS scoring ke saath.
"""
import logging
import re
import time
import requests
import config
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# Tech name normalization for NVD CPE search
TECH_NORMALIZE = {
    'nginx':      'nginx',
    'apache':     'apache_http_server',
    'iis':        'internet_information_services',
    'php':        'php',
    'wordpress':  'wordpress',
    'drupal':     'drupal',
    'joomla':     'joomla',
    'jquery':     'jquery',
    'react':      'react',
    'angular':    'angular',
    'vue':        'vue.js',
    'express':    'express',
    'django':     'django',
    'flask':      'flask',
    'laravel':    'laravel',
    'rails':      'ruby_on_rails',
    'tomcat':     'tomcat',
    'spring':     'spring_framework',
    'openssl':    'openssl',
    'openssh':    'openssh',
}

SEVERITY_SCORE = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0}

class CVELookup:
    NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    TIMEOUT = 12

    def __init__(self):
        self.nvd_key = config.NVD_API_KEY

    def run(self, technologies: dict) -> dict:
        """
        technologies: dict like {'Server': 'nginx/1.18.0', 'X-Powered-By': 'PHP/7.4.3'}
        """
        result = {
            'technologies_checked': [],
            'cves': [],
            'total_cves': 0,
            'critical_count': 0,
            'high_count': 0,
            'risk_level': 'LOW',
            'error': None
        }

        parsed = self._parse_technologies(technologies)
        if not parsed:
            result['error'] = 'No recognizable technologies found'
            return result

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(self._lookup_cves, tech, version): (tech, version)
                       for tech, version in parsed}
            for future in as_completed(futures):
                tech, version = futures[future]
                try:
                    cves = future.result()
                    result['technologies_checked'].append({'tech': tech, 'version': version, 'cves_found': len(cves)})
                    result['cves'].extend(cves)
                except Exception as e:
                    logger.debug(f"CVE lookup error {tech}: {e}")

        result['cves'].sort(key=lambda x: SEVERITY_SCORE.get(x.get('severity', 'NONE'), 0), reverse=True)
        result['total_cves']    = len(result['cves'])
        result['critical_count'] = sum(1 for c in result['cves'] if c.get('severity') == 'CRITICAL')
        result['high_count']    = sum(1 for c in result['cves'] if c.get('severity') == 'HIGH')

        if result['critical_count'] > 0:
            result['risk_level'] = 'CRITICAL'
        elif result['high_count'] > 0:
            result['risk_level'] = 'HIGH'
        elif result['total_cves'] > 0:
            result['risk_level'] = 'MEDIUM'

        return result

    def _parse_technologies(self, technologies: dict) -> list:
        parsed = []
        version_re = re.compile(r'(\d+\.\d+[\.\d]*)')

        for key, value in technologies.items():
            if not value:
                continue
            value_lower = value.lower()
            for tech_key, tech_name in TECH_NORMALIZE.items():
                if tech_key in value_lower:
                    version_match = version_re.search(value)
                    version = version_match.group(1) if version_match else None
                    parsed.append((tech_name, version))
                    break

        return parsed

    def _lookup_cves(self, tech: str, version: str) -> list:
        cves    = []
        headers = {'apiKey': self.nvd_key} if self.nvd_key else {}
        params  = {
            'keywordSearch': f"{tech} {version}" if version else tech,
            'resultsPerPage': 20,
            'startIndex': 0
        }

        resp = rate_limited_get(self.NVD_URL, namespace='nvd',
                                params=params, headers=headers, timeout=self.TIMEOUT)
        # NVD 403 = rate limited, retry once after delay
        if resp and resp.status_code == 403:
            time.sleep(6)
            resp = rate_limited_get(self.NVD_URL, namespace='nvd',
                                    params=params, headers=headers, timeout=self.TIMEOUT)

        if not resp or resp.status_code != 200:
            return cves

        try:
            data = resp.json()
        except Exception:
            return cves

        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id   = cve_data.get('id', '')
            severity, score = self._extract_severity(cve_data)
            descs = cve_data.get('descriptions', [])
            desc  = next((d['value'] for d in descs if d.get('lang') == 'en'), '')[:300]
            if version and not self._version_affected(cve_data, version):
                continue
            cves.append({
                'cve_id':      cve_id,
                'tech':        tech,
                'version':     version,
                'severity':    severity,
                'score':       score,
                'description': desc,
                'url':         f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            })

        return cves

    def _extract_severity(self, cve_data: dict) -> tuple:
        metrics = cve_data.get('metrics', {})

        # Try CVSSv3.1 first, then v3.0, then v2
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            entries = metrics.get(key, [])
            if entries:
                cvss = entries[0].get('cvssData', {})
                score    = cvss.get('baseScore', 0)
                severity = cvss.get('baseSeverity', entries[0].get('baseSeverity', 'NONE'))
                return severity.upper(), score

        return 'NONE', 0.0

    def _version_affected(self, cve_data: dict, version: str) -> bool:
        """Basic version range check from NVD configurations"""
        try:
            configs = cve_data.get('configurations', [])
            if not configs:
                return True  # No config data, include it

            version_parts = [int(x) for x in version.split('.')[:3]]

            for config in configs:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if not cpe_match.get('vulnerable', False):
                            continue
                        v_start = cpe_match.get('versionStartIncluding') or cpe_match.get('versionStartExcluding')
                        v_end   = cpe_match.get('versionEndIncluding') or cpe_match.get('versionEndExcluding')

                        if not v_start and not v_end:
                            return True

                        if v_start:
                            start_parts = [int(x) for x in v_start.split('.')[:3]]
                            if version_parts < start_parts:
                                continue
                        if v_end:
                            end_parts = [int(x) for x in v_end.split('.')[:3]]
                            if version_parts > end_parts:
                                continue
                        return True
        except Exception:
            return True  # On parse error, include CVE

        return False
