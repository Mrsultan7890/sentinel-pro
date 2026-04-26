import logging
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

CHROMIUM_BINS = ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']

class ScreenshotCapture:
    def __init__(self, output_dir: str = '/tmp/screenshots'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.chromium = self._find_chromium()

    def _find_chromium(self) -> str | None:
        for bin_name in CHROMIUM_BINS:
            path = shutil.which(bin_name)
            if path:
                return path
        # Fallback: known Kali path
        if Path('/usr/bin/chromium').exists():
            return '/usr/bin/chromium'
        return None

    def capture(self, url: str, filename: str = None) -> dict:
        result = {'url': url, 'path': None, 'error': None}

        if not self.chromium:
            result['error'] = 'Chromium not found'
            return result

        if not filename:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe = url.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"{safe}_{ts}.png"

        out_path = self.output_dir / filename

        cmd = [
            self.chromium,
            '--headless=new',
            '--no-sandbox',
            '--disable-gpu',
            '--disable-dev-shm-usage',
            '--disable-software-rasterizer',
            '--hide-scrollbars',
            '--window-size=1280,900',
            '--virtual-time-budget=5000',
            f'--screenshot={out_path}',
            url
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=45)
            if out_path.exists() and out_path.stat().st_size > 0:
                result['path'] = str(out_path)
            else:
                # Fallback: try older headless flag
                cmd2 = [
                    self.chromium,
                    '--headless',
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-dev-shm-usage',
                    '--hide-scrollbars',
                    '--window-size=1280,900',
                    f'--screenshot={out_path}',
                    url
                ]
                proc2 = subprocess.run(cmd2, capture_output=True, timeout=45)
                if out_path.exists() and out_path.stat().st_size > 0:
                    result['path'] = str(out_path)
                else:
                    result['error'] = proc.stderr.decode(errors='ignore')[:300] or 'Screenshot file empty'
        except subprocess.TimeoutExpired:
            result['error'] = 'Screenshot timeout (45s)'
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Screenshot failed for {url}: {e}")

        return result

    def capture_domain(self, domain: str) -> dict:
        """Capture both http and https for a domain"""
        results = {}
        for scheme in ('https', 'http'):
            url = f"{scheme}://{domain}"
            res = self.capture(url)
            results[scheme] = res
            if res['path']:  # https worked, skip http
                break
        return results

    def capture_endpoints(self, domain: str, paths: list) -> list:
        """Capture screenshots of multiple endpoints"""
        results = []
        for path in paths[:10]:  # cap at 10
            url = f"https://{domain}{path}"
            res = self.capture(url)
            results.append(res)
        return results
