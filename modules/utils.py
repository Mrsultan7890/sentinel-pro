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
Shared utilities — rate limiter, safe request wrapper
"""

import time
import logging
import threading
import warnings
import requests
import urllib3
import config

# Suppress connection pool warnings — harmless, requests retries automatically
warnings.filterwarnings('ignore', message='Connection pool is full')
logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)

# Suppress SSL warnings — intentional: scanner must handle self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_last_call: dict[str, float] = {}
_rate_lock = threading.Lock()


def rate_limited_get(url: str, namespace: str = 'default', **kwargs) -> requests.Response | None:
    """
    GET (or POST) request with per-namespace rate limiting and error handling.
    Automatically routes through Tor if config.is_tor_active().
    Returns None on any network/timeout error instead of raising.
    """
    now = time.monotonic()
    with _rate_lock:
        last = _last_call.get(namespace, 0.0)
        min_gap = config.RATE_LIMIT_PERIOD / max(config.RATE_LIMIT_REQUESTS, 1)
        wait = min_gap - (now - last)
        if wait > 0:
            time.sleep(wait)
        _last_call[namespace] = time.monotonic()

    method = kwargs.pop('method', 'GET').upper()
    kwargs.setdefault('timeout', config.REQUEST_TIMEOUT)
    kwargs.setdefault('headers', {'User-Agent': config.USER_AGENTS[0]})

    if config.is_tor_active() and 'proxies' not in kwargs:
        kwargs['proxies'] = config.get_proxies()

    try:
        if method == 'POST':
            return requests.post(url, **kwargs)
        return requests.get(url, **kwargs)
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout: {url}")
    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection error: {url}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request failed {url}: {e}")
    return None


def tor_session(pool_size: int = 10) -> requests.Session:
    """
    Returns a requests.Session pre-configured with Tor SOCKS5 proxy.
    pool_size: set higher (e.g. 30-50) for modules using ThreadPoolExecutor.
    """
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=0
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    if config.is_tor_active():
        session.proxies = config.get_proxies()
    return session
