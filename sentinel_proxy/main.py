#!/usr/bin/env python3
"""
SentinelProxy v2.0 — Rust Core + Python UI
==========================================
Rust  : HTTP/HTTPS proxy engine (tokio + hyper + rustls)
Python: ML analysis, UI, DB, reporting
"""
import sys
import os
import subprocess
import warnings
import urllib3
import time
import threading
import signal
import socket
import logging
from pathlib import Path

warnings.filterwarnings('ignore')
urllib3.disable_warnings()
sys.path.insert(0, '/home/kali/osints')

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

PROXY_HOST  = '127.0.0.1'
PROXY_PORT  = 8082
SOCK_PATH   = '/tmp/sentinel_proxy_v2.sock'
RUST_BIN    = Path(__file__).parent / 'rust_core' / 'target' / 'release' / 'sentinel_proxy_core'

_rust_proc  = None


def kill_port(port: int):
    """Kill any stale process on port."""
    try:
        r = subprocess.run(['lsof', '-t', f'-i:{port}'],
                           capture_output=True, text=True)
        for pid in r.stdout.strip().split():
            if pid and pid != str(os.getpid()):
                subprocess.run(['kill', '-9', pid], capture_output=True)
        if r.stdout.strip():
            time.sleep(0.5)
    except Exception:
        pass


def port_ready(host: str, port: int, timeout: float = 0.3) -> bool:
    """Check if port is accepting connections."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def start_rust_core() -> subprocess.Popen:
    """Start Rust proxy binary — kill stale, wait for ready."""
    if not RUST_BIN.exists():
        print(f'[ERROR] Rust binary not found: {RUST_BIN}')
        print('Build: cd sentinel_proxy/rust_core && cargo build --release')
        sys.exit(1)

    kill_port(PROXY_PORT)

    proc = subprocess.Popen(
        [str(RUST_BIN), PROXY_HOST, str(PROXY_PORT), SOCK_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Log Rust output
    def _log():
        for line in proc.stdout:
            line = line.strip()
            if line:
                logger.info(f'[Rust] {line}')
    threading.Thread(target=_log, daemon=True, name='rust-log').start()

    # Wait up to 5s for port to be ready
    for i in range(25):
        if port_ready(PROXY_HOST, PROXY_PORT):
            print(f'[+] Rust core ready on {PROXY_HOST}:{PROXY_PORT}')
            return proc
        if proc.poll() is not None:
            print(f'[ERROR] Rust core exited early (code {proc.returncode})')
            sys.exit(1)
        time.sleep(0.2)

    print(f'[WARN] Rust core may not be ready yet — continuing anyway')
    return proc


def cleanup(signum=None, frame=None):
    global _rust_proc
    if _rust_proc:
        _rust_proc.terminate()
        try:
            _rust_proc.wait(timeout=3)
        except Exception:
            _rust_proc.kill()
    # Clean up sockets
    for p in [SOCK_PATH, SOCK_PATH + '.events']:
        try:
            Path(p).unlink()
        except Exception:
            pass
    sys.exit(0)


signal.signal(signal.SIGINT,  cleanup)
signal.signal(signal.SIGTERM, cleanup)


if __name__ == '__main__':
    print('[*] Starting SentinelProxy v2.0 (Rust Core)...')

    # 1. Start Rust core
    _rust_proc = start_rust_core()

    # 2. Start IPC bridge
    from sentinel_proxy.core.rust_bridge import RustCoreBridge
    bridge = RustCoreBridge(SOCK_PATH)
    bridge.start()
    time.sleep(0.5)  # give bridge time to connect
    print(f'[+] IPC bridge ready')

    # 3. Launch UI
    from sentinel_proxy.ui.app import SentinelProxyApp
    app = SentinelProxyApp(rust_bridge=bridge)

    # Wire bridge callbacks NOW (before UI is fully built)
    bridge.on_request    = app._on_proxy_request
    bridge.on_response   = app._on_proxy_response
    bridge.on_websocket  = app._on_proxy_websocket
    bridge.on_intercepted = app._on_intercept_held

    def _mark_running():
        """Mark proxy as running in UI — retry until widgets exist."""
        if not hasattr(app, 'entry_port'):
            app.root.after(200, _mark_running)
            return
        app.proxy_running = True
        app.proxy = bridge
        try:
            app._proxy_btn_text.set('■  STOP PROXY')
            app.btn_proxy.configure(style='Red.TButton')
            app.lbl_proxy_status.config(
                text=f'● ONLINE :{PROXY_PORT}  [Rust]',
                fg='#39ff6e'
            )
            app._set_status(
                f'Rust proxy on {PROXY_HOST}:{PROXY_PORT}  ·  '
                f'Set browser proxy to {PROXY_HOST}:{PROXY_PORT}'
            )
        except Exception:
            pass

    app.root.after(800, _mark_running)
    app.root.mainloop()
    cleanup()
