# ============================================================================
# Example Extension: Auto Header Injector
# Automatically adds custom headers to every request.
# ============================================================================
from sentinel_proxy.extensions.base import SentinelExtension


class AutoHeaderInjector(SentinelExtension):
    name        = 'Auto Header Injector'
    description = 'Injects custom headers into every request automatically'
    version     = '1.0'
    author      = 'SentinelProxy'

    # ── Configure headers to inject here ─────────────────────────────────────
    INJECT_HEADERS = {
        # 'Authorization': 'Bearer YOUR_TOKEN_HERE',
        # 'X-Forwarded-For': '127.0.0.1',
        # 'X-Custom-Header': 'value',
    }

    def on_request(self, flow: dict) -> dict:
        if self.INJECT_HEADERS:
            flow.setdefault('headers', {}).update(self.INJECT_HEADERS)
        return flow
