import logging
from urllib.parse import urlparse
from collections import defaultdict
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

INTERESTING_EXTENSIONS = {'.sql', '.bak', '.zip', '.tar', '.gz', '.env', '.log',
                           '.conf', '.config', '.xml', '.json', '.csv', '.xls', '.xlsx'}
INTERESTING_PATHS = ['admin', 'login', 'api', 'backup', 'config', 'debug',
                     'upload', 'phpinfo', 'wp-admin', 'swagger', '.git', '.env']

class WaybackMachine:
    CDX_URL = 'https://web.archive.org/cdx/search/cdx'

    def run(self, domain: str) -> dict:
        result = {
            'domain': domain,
            'total_urls': 0,
            'unique_paths': [],
            'interesting_urls': [],
            'parameters': [],
            'by_extension': {},
            'oldest_snapshot': None,
            'newest_snapshot': None,
            'error': None
        }

        try:
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'original,timestamp,statuscode,mimetype',
                'collapse': 'urlkey',
                'limit': 5000,
                'filter': 'statuscode:200'
            }
            resp = rate_limited_get(self.CDX_URL, namespace='wayback', params=params, timeout=20)
            if resp is None:
                result['error'] = 'Request failed (network error or timeout)'
                return result
            resp.raise_for_status()

            rows = resp.json()
            if not rows or len(rows) < 2:
                result['error'] = 'No snapshots found'
                return result

            # First row is header
            header, *data = rows
            col = {name: i for i, name in enumerate(header)}

            timestamps = []
            ext_map    = defaultdict(list)
            params_set = set()
            interesting = []
            paths_seen  = set()

            for row in data:
                url       = row[col['original']]
                ts        = row[col['timestamp']]
                parsed    = urlparse(url)
                path      = parsed.path.lower()
                ext       = '.' + path.rsplit('.', 1)[-1] if '.' in path.split('/')[-1] else ''
                timestamps.append(ts)

                if path not in paths_seen:
                    paths_seen.add(path)

                if ext in INTERESTING_EXTENSIONS:
                    ext_map[ext].append(url)

                if parsed.query:
                    for param in parsed.query.split('&'):
                        k = param.split('=')[0]
                        if k:
                            params_set.add(k)

                # Check interesting paths
                if any(p in path for p in INTERESTING_PATHS) or ext in INTERESTING_EXTENSIONS:
                    interesting.append({'url': url, 'timestamp': ts})

            result['total_urls']      = len(data)
            result['unique_paths']    = list(paths_seen)[:200]
            result['interesting_urls'] = interesting[:100]
            result['parameters']      = sorted(params_set)[:50]
            result['by_extension']    = {k: len(v) for k, v in ext_map.items()}

            if timestamps:
                timestamps.sort()
                result['oldest_snapshot'] = timestamps[0]
                result['newest_snapshot'] = timestamps[-1]

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Wayback error for {domain}: {e}")

        return result
