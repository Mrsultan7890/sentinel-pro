# ============================================================================
# Sentinel Pro v3.1 — SentinelProxy Extension Base Class
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

class SentinelExtension:
    """
    Base class for all SentinelProxy extensions.

    Override any hook you need:
      on_request(flow)   — called before request is forwarded
      on_response(flow)  — called after response is received
      on_intercept(flow) — called when request is intercepted

    flow dict keys:
      method, url, host, path, headers (dict), body (str), is_https
    response flow adds:
      status_code, resp_headers (dict), resp_body (str), response_time
    """

    # Extension metadata — override in subclass
    name        = 'Unnamed Extension'
    description = ''
    version     = '1.0'
    author      = ''
    enabled     = True

    def on_request(self, flow: dict) -> dict:
        """Modify or inspect request. Return modified flow dict."""
        return flow

    def on_response(self, flow: dict) -> dict:
        """Modify or inspect response. Return modified flow dict."""
        return flow

    def on_intercept(self, flow: dict) -> dict:
        """Called when request hits intercept. Return modified flow dict."""
        return flow

    def on_load(self):
        """Called when extension is loaded/enabled."""
        pass

    def on_unload(self):
        """Called when extension is disabled/removed."""
        pass
