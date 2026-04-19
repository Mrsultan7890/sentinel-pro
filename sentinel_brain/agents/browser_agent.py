"""
Browser Agent — Automated Browser Control
==========================================
- Chromium headless/headful control
- Screenshots, form filling, JS execution
- Cookie/session capture
- Multi-page crawling
- Login bypass testing

Author: @who_is_the_black_hat
"""

import logging
import subprocess
import shutil
import time
from pathlib import Path
from datetime import datetime

import config

logger = logging.getLogger(__name__)

SCREENSHOTS_DIR = config.BASE_DIR / 'screenshots'
SCREENSHOTS_DIR.mkdir(exist_ok=True)

CHROMIUM_BINS = ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']


class BrowserAgent:
    NAME = 'browser_agent'

    def __init__(self):
        self._chromium  = self._find_chromium()
        self._playwright = None
        self._browser    = None
        self._page       = None

    def _find_chromium(self) -> str:
        for b in CHROMIUM_BINS:
            p = shutil.which(b)
            if p:
                return p
        if Path('/usr/bin/chromium').exists():
            return '/usr/bin/chromium'
        return None

    # ── Screenshot ────────────────────────────────────────────────────────────

    def screenshot(self, url: str, filename: str = None) -> dict:
        """URL ka screenshot lo."""
        result = {'url': url, 'path': None, 'error': None}
        if not self._chromium:
            result['error'] = 'Chromium not found'
            return result

        if not filename:
            ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe = url.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"{safe[:60]}_{ts}.png"

        out_path = SCREENSHOTS_DIR / filename
        cmd = [
            self._chromium,
            '--headless=new', '--no-sandbox',
            '--disable-gpu', '--disable-dev-shm-usage',
            '--hide-scrollbars', '--window-size=1280,900',
            f'--screenshot={out_path}', url
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=30)
            if out_path.exists() and out_path.stat().st_size > 0:
                result['path'] = str(out_path)
                logger.info(f"[BrowserAgent] Screenshot: {out_path}")
            else:
                result['error'] = 'Screenshot empty or failed'
        except subprocess.TimeoutExpired:
            result['error'] = 'Timeout (30s)'
        except Exception as e:
            result['error'] = str(e)
        return result

    def screenshot_domain(self, domain: str) -> dict:
        """Domain ke http + https dono screenshot lo."""
        for scheme in ('https', 'http'):
            r = self.screenshot(f"{scheme}://{domain}")
            if r['path']:
                return r
        return r

    # ── Page Source ───────────────────────────────────────────────────────────

    def get_source(self, url: str) -> dict:
        """Page HTML source lo."""
        result = {'url': url, 'html': '', 'error': None}
        if not self._chromium:
            result['error'] = 'Chromium not found'
            return result
        cmd = [
            self._chromium,
            '--headless=new', '--no-sandbox',
            '--disable-gpu', '--dump-dom', url
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
            result['html'] = r.stdout[:50000]
        except Exception as e:
            result['error'] = str(e)
        return result

    # ── Playwright (advanced) ─────────────────────────────────────────────────

    def _init_playwright(self) -> bool:
        try:
            from playwright.sync_api import sync_playwright
            self._pw_module = sync_playwright
            return True
        except ImportError:
            logger.warning('[BrowserAgent] playwright not installed — pip install playwright')
            return False

    def crawl(self, url: str, max_pages: int = 5) -> dict:
        """Site crawl karo — links, forms, inputs collect karo."""
        result = {'url': url, 'pages': [], 'forms': [], 'inputs': [], 'links': []}

        if not self._init_playwright():
            # Fallback — chromium dump-dom
            src = self.get_source(url)
            result['pages'].append({'url': url, 'html': src['html'][:5000]})
            return result

        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page    = browser.new_page()
                page.goto(url, timeout=15000)
                page.wait_for_load_state('networkidle', timeout=10000)

                # Links
                links = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
                result['links'] = list(set(links))[:50]

                # Forms
                forms = page.eval_on_selector_all('form', '''forms => forms.map(f => ({
                    action: f.action, method: f.method,
                    inputs: Array.from(f.querySelectorAll("input,textarea,select"))
                             .map(i => ({name: i.name, type: i.type, id: i.id}))
                }))''')
                result['forms'] = forms[:10]

                # Input fields
                inputs = page.eval_on_selector_all('input,textarea', '''els => els.map(e => ({
                    name: e.name, type: e.type, id: e.id, placeholder: e.placeholder
                }))''')
                result['inputs'] = inputs[:20]

                result['pages'].append({'url': url, 'title': page.title()})
                browser.close()
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"[BrowserAgent] crawl error: {e}")

        return result

    def fill_and_submit(self, url: str, form_data: dict) -> dict:
        """Form fill karke submit karo — login testing ke liye."""
        result = {'url': url, 'submitted': False, 'response_url': '', 'error': None}

        if not self._init_playwright():
            result['error'] = 'playwright not available'
            return result

        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page    = browser.new_page()
                page.goto(url, timeout=15000)

                for selector, value in form_data.items():
                    try:
                        page.fill(selector, value)
                    except Exception:
                        pass

                page.keyboard.press('Enter')
                page.wait_for_load_state('networkidle', timeout=8000)

                result['submitted']    = True
                result['response_url'] = page.url
                result['title']        = page.title()

                # Screenshot after submit
                ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
                out = SCREENSHOTS_DIR / f"form_submit_{ts}.png"
                page.screenshot(path=str(out))
                result['screenshot'] = str(out)

                browser.close()
        except Exception as e:
            result['error'] = str(e)

        return result

    def execute_js(self, url: str, js_code: str) -> dict:
        """Page pe JavaScript execute karo."""
        result = {'url': url, 'result': None, 'error': None}

        if not self._init_playwright():
            result['error'] = 'playwright not available'
            return result

        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page    = browser.new_page()
                page.goto(url, timeout=15000)
                result['result'] = page.evaluate(js_code)
                browser.close()
        except Exception as e:
            result['error'] = str(e)

        return result

    def get_cookies(self, url: str) -> dict:
        """Site ke cookies capture karo."""
        result = {'url': url, 'cookies': [], 'error': None}

        if not self._init_playwright():
            result['error'] = 'playwright not available'
            return result

        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                ctx     = browser.new_context()
                page    = ctx.new_page()
                page.goto(url, timeout=15000)
                cookies = ctx.cookies()
                result['cookies'] = [
                    {'name': c['name'], 'value': c['value'][:50],
                     'httpOnly': c.get('httpOnly'), 'secure': c.get('secure'),
                     'sameSite': c.get('sameSite')}
                    for c in cookies
                ]
                browser.close()
        except Exception as e:
            result['error'] = str(e)

        return result

    @staticmethod
    def is_available() -> bool:
        for b in CHROMIUM_BINS:
            if shutil.which(b):
                return True
        return Path('/usr/bin/chromium').exists()
