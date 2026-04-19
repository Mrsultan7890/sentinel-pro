"""
Proxy Core — mitmproxy background engine
=========================================
Intercepts HTTP/HTTPS traffic, logs to DB,
sends to AI analyzer in real-time.
"""

import threading
import logging
import time
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ProxyCore:
    """
    mitmproxy wrapper — runs in background thread.
    Callbacks: on_request, on_response
    """

    def __init__(self, host='127.0.0.1', port=8082):
        self.host        = host
        self.port        = port
        self._thread     = None
        self._running    = False
        self._master     = None
        self.intercept   = False          # intercept mode on/off
        self._intercepted = None          # pending intercepted flow
        self._intercept_event = threading.Event()

        # Callbacks
        self.on_request  = None   # fn(flow_dict)
        self.on_response = None   # fn(flow_dict)

    # ── Start / Stop ──────────────────────────────────────────────────────────

    def start(self) -> bool:
        try:
            import mitmproxy
        except ImportError:
            logger.error("mitmproxy not installed — pip install mitmproxy")
            return False

        self._running = True
        self._thread  = threading.Thread(
            target=self._run_proxy, daemon=True, name='sentinel-proxy'
        )
        self._thread.start()
        time.sleep(1.5)
        logger.info(f"[ProxyCore] Started on {self.host}:{self.port}")
        return True

    def stop(self):
        self._running = False
        if self._master:
            try:
                self._master.shutdown()
            except Exception:
                pass
        logger.info("[ProxyCore] Stopped")

    def is_running(self) -> bool:
        return self._running and self._thread and self._thread.is_alive()

    # ── mitmproxy runner ──────────────────────────────────────────────────────

    def _run_proxy(self):
        try:
            import asyncio
            from mitmproxy import http as mhttp
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            class SentinelAddon:
                def __init__(self, core):
                    self.core = core
                def request(self, flow: mhttp.HTTPFlow):
                    fd = self.core._flow_to_dict(flow, 'request')
                    if self.core.on_request:
                        self.core.on_request(fd)
                def response(self, flow: mhttp.HTTPFlow):
                    fd = self.core._flow_to_dict(flow, 'response')
                    if self.core.on_response:
                        self.core.on_response(fd)

            async def _amain():
                opts = Options(
                    listen_host=self.host,
                    listen_port=self.port,
                    ssl_insecure=True,
                )
                master = DumpMaster(opts, with_termlog=False, with_dumper=False)
                master.addons.add(SentinelAddon(self))
                self._master = master
                try:
                    await master.run()
                finally:
                    master.shutdown()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(_amain())
            finally:
                loop.close()

        except Exception:
            import traceback
            traceback.print_exc()
            self._running = False

    # ── Flow → Dict ───────────────────────────────────────────────────────────

    def _flow_to_dict(self, flow, stage: str) -> dict:
        req = flow.request
        d = {
            'id':        str(id(flow)),
            'timestamp': datetime.now().isoformat(),
            'stage':     stage,
            'method':    req.method,
            'url':       req.pretty_url,
            'host':      req.pretty_host,
            'path':      req.path,
            'http_ver':  req.http_version,
            'headers':   dict(req.headers),
            'body':      req.content.decode('utf-8', errors='replace')[:5000],
            'params':    dict(req.query),
        }
        if stage == 'response' and flow.response:
            resp = flow.response
            d['status_code']    = resp.status_code
            d['resp_headers']   = dict(resp.headers)
            d['resp_body']      = resp.content.decode('utf-8', errors='replace')[:10000]
            d['resp_length']    = len(resp.content)
            d['content_type']   = resp.headers.get('content-type', '')
        return d
