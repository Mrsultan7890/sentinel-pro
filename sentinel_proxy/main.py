#!/usr/bin/env python3
"""
SentinelProxy v1.0 — Autonomous Web Security Proxy
====================================================
Burp Suite alternative with AI-powered analysis.

Architecture:
  mitmproxy (Rust-speed proxy core)
  + Tkinter (native desktop UI)
  + SentinelNet (request classification)
  + Groq LLM (deep analysis)
  + SQLite (request history)

Author: @who_is_the_black_hat
"""

import sys
import os
sys.path.insert(0, '/home/kali/osints')

from sentinel_proxy.ui.app import SentinelProxyApp

if __name__ == '__main__':
    app = SentinelProxyApp()
    app.run()
