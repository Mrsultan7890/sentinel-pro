#!/usr/bin/env python3
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
Standalone SentinelProxy — no UI, just proxy.
Run this, set browser to 127.0.0.1:8082, browse any site.
Ctrl+C to stop.
"""
import sys
import asyncio
import subprocess
import os

sys.path.insert(0, '/home/kali/osints')

# Kill stale
try:
    r = subprocess.run(['lsof', '-t', '-i:8082'], capture_output=True, text=True)
    for pid in r.stdout.strip().split():
        if pid and pid != str(os.getpid()):
            subprocess.run(['kill', '-9', pid], capture_output=True)
except Exception:
    pass

# Patch mitmproxy before import
import mitmproxy.log as _mlog
def _safe_emit(self_h, record):
    try:
        loop = self_h.master.event_loop
        if loop and loop.is_running() and not loop.is_closed():
            from mitmproxy.log import LogEntry, AddLogHook, LOGGING_LEVELS_TO_LOGENTRY
            entry = LogEntry(
                msg=self_h.format(record),
                level=LOGGING_LEVELS_TO_LOGENTRY.get(record.levelno, 'error'),
            )
            loop.call_soon_threadsafe(self_h.master.addons.trigger, AddLogHook(entry))
    except Exception:
        pass
_mlog.MitmLogHandler.emit = _safe_emit

from mitmproxy.addons import errorcheck as _ec
async def _no_exit(self):
    await asyncio.sleep(0)
    if self.logger.has_errored:
        for r in self.logger.has_errored:
            print(f'[WARN] {r.getMessage()}')
_ec.ErrorCheck.shutdown_if_errored = _no_exit

from mitmproxy import http as mhttp
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

req_count = [0]

class SentinelAddon:
    def request(self, flow: mhttp.HTTPFlow):
        req_count[0] += 1
        print(f'[{req_count[0]}] REQ  {flow.request.method} {flow.request.pretty_url}', flush=True)

    def response(self, flow: mhttp.HTTPFlow):
        print(f'[{req_count[0]}] RESP {flow.response.status_code} {flow.request.pretty_url}', flush=True)

async def main():
    opts = Options(listen_host='127.0.0.1', listen_port=8082, ssl_insecure=True)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(SentinelAddon())
    print('=' * 50)
    print('SentinelProxy running on 127.0.0.1:8082')
    print('Set Firefox proxy: 127.0.0.1:8082')
    print('Ctrl+C to stop')
    print('=' * 50)
    try:
        await master.run()
    except KeyboardInterrupt:
        pass
    finally:
        master.shutdown()
        print(f'\nStopped. Total requests: {req_count[0]}')

asyncio.run(main())
