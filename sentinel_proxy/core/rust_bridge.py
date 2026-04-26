"""
Rust Core Bridge — bidirectional IPC with Rust proxy core.

Rust → Python : request / response / intercepted / websocket / error events
Python → Rust : forward / drop / forward_modified / intercept_on / intercept_off
"""
import asyncio
import json
import os
import socket
import threading
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class RustCoreBridge:
    """
    Connects to Rust proxy core via two Unix sockets:
      {socket_path}         — Python sends commands TO Rust
      {socket_path}.events  — Python receives events FROM Rust
    """

    def __init__(self, socket_path: str = '/tmp/sentinel_proxy_v2.sock'):
        self.socket_path   = socket_path
        self.events_path   = socket_path + '.events'
        self.on_request    = None
        self.on_response   = None
        self.on_websocket  = None
        self.on_intercepted = None   # called when Rust holds a flow
        self._cmd_sock     = None    # blocking socket for commands → Rust
        self._cmd_lock     = threading.Lock()
        self._event_thread = None
        self._running      = False
        # Fake intercept attribute so UI code doesn't crash
        self.intercept     = False

    # ── Start / Stop ──────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._event_thread = threading.Thread(
            target=self._run_event_loop, daemon=True, name='rust-bridge'
        )
        self._event_thread.start()
        logger.info(f'[RustBridge] Started — events: {self.events_path}')

    def stop(self):
        self._running = False
        self._send_cmd({'action': 'forward_all'})
        if self._cmd_sock:
            try: self._cmd_sock.close()
            except Exception: pass

    def is_running(self) -> bool:
        return self._running and self._event_thread and self._event_thread.is_alive()

    # ── Intercept control (called from UI) ────────────────────────────────────

    def set_intercept(self, enabled: bool):
        self.intercept = enabled
        self._send_cmd({'action': 'intercept_on' if enabled else 'intercept_off'})

    def set_intercept_scope(self, hosts: list):
        """Only intercept requests from these hosts. Empty list = intercept all."""
        self._send_cmd({'action': 'set_intercept_scope', 'hosts': hosts})

    def forward_flow(self, flow_id: str):
        self._send_cmd({'action': 'forward', 'flow_id': flow_id})
        self._decrement_pending()

    def drop_flow(self, flow_id: str):
        self._send_cmd({'action': 'drop', 'flow_id': flow_id})
        self._decrement_pending()

    def forward_modified(self, flow_id: str, headers: list, body: str):
        self._send_cmd({
            'action':  'forward_modified',
            'flow_id': flow_id,
            'headers': headers,
            'body':    body,
        })
        self._decrement_pending()

    def forward_all(self):
        self._send_cmd({'action': 'forward_all'})
        self._pending_count = 0

    # Compatibility with old ProxyCore interface
    def intercept_forward(self):
        if hasattr(self, '_last_intercepted_id'):
            self.forward_flow(self._last_intercepted_id)

    def intercept_drop(self):
        if hasattr(self, '_last_intercepted_id'):
            self.drop_flow(self._last_intercepted_id)

    def pending_count(self) -> int:
        return getattr(self, '_pending_count', 0)

    # ── Command sender ────────────────────────────────────────────────────────

    def _send_cmd(self, cmd: dict):
        """Send JSON command to Rust via Unix socket."""
        try:
            with self._cmd_lock:
                if self._cmd_sock is None:
                    self._cmd_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self._cmd_sock.connect(self.socket_path)
                data = json.dumps(cmd) + '\n'
                self._cmd_sock.sendall(data.encode())
        except Exception as e:
            logger.debug(f'[RustBridge] cmd send error: {e}')
            self._cmd_sock = None  # reconnect next time

    # ── Event receiver ────────────────────────────────────────────────────────

    def _run_event_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._async_event_receiver())
        except Exception:
            pass
        finally:
            loop.close()

    async def _async_event_receiver(self):
        """Connect to Rust events socket and read newline-delimited JSON."""
        while self._running:
            try:
                reader, _ = await asyncio.open_unix_connection(self.events_path)
                logger.debug('[RustBridge] Connected to events socket')
                buf = b''
                while self._running:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while b'\n' in buf:
                        line, buf = buf.split(b'\n', 1)
                        line = line.strip()
                        if line:
                            try:
                                self._dispatch(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f'[RustBridge] event recv error: {e}')
                await asyncio.sleep(0.5)

    def _dispatch(self, event: dict):
        etype = event.get('event')

        if etype == 'request' and self.on_request:
            flow = self._to_request(event)
            threading.Thread(target=self.on_request, args=(flow,), daemon=True).start()

        elif etype == 'response' and self.on_response:
            flow = self._to_response(event)
            threading.Thread(target=self.on_response, args=(flow,), daemon=True).start()

        elif etype == 'intercepted':
            self._last_intercepted_id = event.get('id', '')
            self._pending_count = getattr(self, '_pending_count', 0) + 1
            if self.on_intercepted:
                threading.Thread(
                    target=self.on_intercepted, args=(event,), daemon=True
                ).start()

        elif etype == 'websocket' and self.on_websocket:
            threading.Thread(target=self.on_websocket, args=(event,), daemon=True).start()

    def _decrement_pending(self):
        self._pending_count = max(0, getattr(self, '_pending_count', 1) - 1)

    # ── Flow dict converters ──────────────────────────────────────────────────

    def _to_request(self, e: dict) -> dict:
        return {
            'id':        e.get('id', ''),
            'timestamp': e.get('timestamp', ''),
            'method':    e.get('method', ''),
            'url':       e.get('url', ''),
            'host':      e.get('host', ''),
            'path':      e.get('path', '/'),
            'headers':   e.get('headers', {}),
            'body':      e.get('body', ''),
            'params':    self._parse_params(e.get('url', ''), e.get('body', '')),
            'is_https':  e.get('is_https', False),
            'http_ver':  e.get('http_ver', 'HTTP/1.1'),
            'stage':     'request',
        }

    def _to_response(self, e: dict) -> dict:
        return {
            'id':            e.get('request_id', ''),
            'timestamp':     e.get('timestamp', ''),
            'status_code':   e.get('status_code', 0),
            'resp_headers':  e.get('headers', {}),
            'resp_body':     e.get('body', ''),
            'resp_length':   e.get('body_length', 0),
            'content_type':  e.get('content_type', ''),
            'response_time': e.get('response_time', 0),
            'stage':         'response',
        }

    def _parse_params(self, url: str, body: str) -> dict:
        from urllib.parse import urlparse, parse_qs
        params = {}
        try:
            qs = urlparse(url).query
            if qs:
                for k, v in parse_qs(qs).items():
                    params[k] = v[0] if v else ''
        except Exception:
            pass
        if body and '=' in body and not body.strip().startswith('{'):
            for part in body.split('&'):
                if '=' in part:
                    k, _, v = part.partition('=')
                    params[k.strip()] = v.strip()
        return params
