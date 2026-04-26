"""
Rust Fuzzer Bridge — calls sentinel_fuzzer binary for parallel fuzzing.
Replaces Python ThreadPoolExecutor in Intruder tab with Rust rayon.
~50x faster than Python implementation.
"""
import json
import subprocess
import threading
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

import sys
from pathlib import Path

if getattr(sys, 'frozen', False):
    FUZZER_BIN = Path(sys.executable).resolve().parent / 'sentinel_fuzzer'
else:
    FUZZER_BIN = Path(__file__).parents[1] / 'rust_fuzzer' / 'target' / 'release' / 'sentinel_fuzzer'


class RustFuzzerBridge:
    """
    Wraps sentinel_fuzzer binary.
    Streams JSONL results line by line via callback.
    """

    def __init__(self):
        self._proc    = None
        self._running = False

    def is_available(self) -> bool:
        return FUZZER_BIN.exists()

    def start(
        self,
        url:        str,
        param:      str,
        payloads:   list,
        mode:       str       = 'sniper',
        param2:     str       = '',
        payloads2:  list      = None,
        threads:    int       = 20,
        delay_ms:   int       = 0,
        grep:       str       = '',
        post_body:  str       = '',
        headers:    dict      = None,
        method:     str       = 'GET',
        on_result:  callable  = None,
        on_done:    callable  = None,
    ):
        """Start fuzzing in background thread. on_result called for each result."""
        if not self.is_available():
            logger.warning('[RustFuzzer] Binary not found, falling back to Python')
            return False

        config = {
            'url':       url,
            'method':    method,
            'param':     param,
            'param2':    param2 or '',
            'mode':      mode,
            'payloads':  payloads,
            'payloads2': payloads2 or [],
            'threads':   threads,
            'delay_ms':  delay_ms,
            'grep':      grep,
            'post_body': post_body,
            'headers':   headers or {},
        }

        self._running = True

        def _run():
            try:
                self._proc = subprocess.Popen(
                    [str(FUZZER_BIN)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # Send config
                self._proc.stdin.write(json.dumps(config))
                self._proc.stdin.close()

                # Stream results
                for line in self._proc.stdout:
                    if not self._running:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                        if on_result:
                            on_result(result)
                    except json.JSONDecodeError:
                        pass

                self._proc.wait()
            except Exception as e:
                logger.error(f'[RustFuzzer] error: {e}')
            finally:
                self._running = False
                if on_done:
                    on_done()

        threading.Thread(target=_run, daemon=True, name='rust-fuzzer').start()
        return True

    def stop(self):
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
