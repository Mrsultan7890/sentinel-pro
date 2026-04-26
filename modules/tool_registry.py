"""
SentinelNet Tool Registry
=========================
Agent ke liye sab tools ek jagah.
Har tool: name, description, execute(args) → result dict

Author: @who_is_the_black_hat
"""

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolResult:
    def __init__(self, tool: str, success: bool, output: str, data: dict = None):
        self.tool    = tool
        self.success = success
        self.output  = output          # human-readable observation
        self.data    = data or {}      # structured data for agent reasoning

    def __str__(self):
        status = "OK" if self.success else "ERROR"
        return f"[{self.tool}:{status}] {self.output[:300]}"


class ToolRegistry:
    """
    All tools the agent can call.
    sentinel instance inject karo — existing scanners reuse hote hain.
    """

    def __init__(self, sentinel=None, console=None):
        self._sentinel = sentinel
        self._print    = console or print
        self._tools    = {}
        self._register_all()

    # ── Registration ──────────────────────────────────────────────────────────

    def _register_all(self):
        tools = [
            # Security scanners
            ('recon',           'Passive recon: WHOIS, DNS, subdomains, Wayback, dorks, cloud assets',
             self._recon),
            ('bugbounty',       'Full vuln scan: SSL, headers, ports, SQLi/XSS/SSRF, CORS, JWT, LFI, XXE',
             self._bugbounty),
            ('breach',          'Check email/username in breach databases (HIBP, Dehashed, HudsonRock)',
             self._breach),
            ('email_osint',     'Email OSINT: MX validation, social profiles, breach check',
             self._email_osint),
            ('phone_osint',     'Phone OSINT: carrier, country, line type, social hints',
             self._phone_osint),
            ('person_osint',    'Person OSINT: username variations, 10+ social platforms, relation graph',
             self._person_osint),

            # System tools
            ('shell',           'Execute a bash command on the local Linux system',
             self._shell),
            ('file_read',       'Read contents of a file',
             self._file_read),
            ('file_write',      'Write content to a file',
             self._file_write),
            ('web_fetch',       'Fetch a URL and return text content',
             self._web_fetch),

            # Sentinel system
            ('tor_on',          'Enable Tor routing for anonymity',
             self._tor_on),
            ('tor_off',         'Disable Tor routing',
             self._tor_off),
            ('tor_newip',       'Rotate Tor exit node (new IP)',
             self._tor_newip),
            ('notify',          'Send Telegram alert message',
             self._notify),
            ('db_query',        'Query scan history from database for a target',
             self._db_query),
            ('save_evidence',   'Save data to evidence vault',
             self._save_evidence),
            ('generate_report', 'Generate HTML/PDF report for last scan',
             self._generate_report),
        ]
        for name, desc, fn in tools:
            self._tools[name] = {'description': desc, 'fn': fn}

    # ── Public API ────────────────────────────────────────────────────────────

    def list_tools(self) -> list:
        return [{'name': k, 'description': v['description']} for k, v in self._tools.items()]

    def execute(self, tool_name: str, args: dict) -> ToolResult:
        if tool_name not in self._tools:
            return ToolResult(tool_name, False, f"Unknown tool: {tool_name}")
        try:
            return self._tools[tool_name]['fn'](args)
        except Exception as e:
            logger.exception(f"Tool {tool_name} error")
            return ToolResult(tool_name, False, f"Tool error: {e}")

    def tool_descriptions(self) -> str:
        lines = []
        for t in self.list_tools():
            lines.append(f"  {t['name']:<20} — {t['description']}")
        return '\n'.join(lines)

    # ── Security Scanner Tools ────────────────────────────────────────────────

    def _recon(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('recon', False, 'target required')
        if self._sentinel:
            self._sentinel._handle_recon(f'recon {target}')
            data = self._sentinel.session_data.get('recon', {})
        else:
            data = {'error': 'no sentinel instance'}
        subs  = data.get('subdomains', {}).get('total_found', 0)
        cloud = data.get('cloud_assets', {}).get('total', 0)
        gh    = data.get('github_dorks', {}).get('total_secrets', 0)
        obs   = (f"Recon complete for {target}: {subs} subdomains, "
                 f"{cloud} cloud assets, {gh} GitHub secrets")
        return ToolResult('recon', True, obs, data)

    def _bugbounty(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('bugbounty', False, 'target required')
        if self._sentinel:
            self._sentinel._handle_bugbounty(f'bugbounty {target}')
            data = self._sentinel.session_data.get('bugbounty', {})
        else:
            data = {'error': 'no sentinel instance'}
        vulns = data.get('vulns', {})
        risk  = vulns.get('risk_level', data.get('risk_level', 'UNKNOWN'))
        total = vulns.get('total_vulns', 0)
        obs   = f"BugBounty complete for {target}: risk={risk}, vulns={total}"
        return ToolResult('bugbounty', True, obs, data)

    def _breach(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('breach', False, 'target required')
        if self._sentinel:
            self._sentinel._handle_breach(f'breach {target}')
            data = self._sentinel.session_data.get('breach', {})
        else:
            data = {'error': 'no sentinel instance'}
        risk  = data.get('risk_level', 'UNKNOWN')
        total = data.get('total_breaches', 0)
        logs  = data.get('total_stealer_logs', 0)
        obs   = f"Breach check for {target}: risk={risk}, breaches={total}, stealer_logs={logs}"
        return ToolResult('breach', True, obs, data)

    def _email_osint(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('email_osint', False, 'target required')
        if self._sentinel:
            self._sentinel._handle_email(f'email {target}')
            data = self._sentinel.session_data.get('email', {})
        else:
            data = {}
        obs = f"Email OSINT for {target}: risk={data.get('risk_level','?')}"
        return ToolResult('email_osint', True, obs, data)

    def _phone_osint(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('phone_osint', False, 'target required')
        if self._sentinel:
            self._sentinel._handle_phone(f'phone {target}')
            data = self._sentinel.session_data.get('phone', {})
        else:
            data = {}
        obs = f"Phone OSINT for {target}: carrier={data.get('carrier','?')}, country={data.get('country','?')}"
        return ToolResult('phone_osint', True, obs, data)

    def _person_osint(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('person_osint', False, 'target required')
        if self._sentinel:
            self._sentinel._handle_person(f'person {target}')
            data = self._sentinel.session_data.get('person', {})
        else:
            data = {}
        profiles = len(data.get('social_profiles', []))
        obs = f"Person OSINT for {target}: {profiles} profiles found, risk={data.get('risk_level','?')}"
        return ToolResult('person_osint', True, obs, data)

    # ── System Tools ──────────────────────────────────────────────────────────

    def _shell(self, args: dict) -> ToolResult:
        """
        Execute bash command on local Linux system.
        args: {command: str, timeout: int (optional, default 30), cwd: str (optional)}
        """
        cmd     = args.get('command', '')
        timeout = int(args.get('timeout', 30))
        cwd     = args.get('cwd', str(Path.home()))

        if not cmd:
            return ToolResult('shell', False, 'command required')

        # Safety: block obviously destructive commands
        _BLOCKED = ['rm -rf /', 'mkfs', ':(){:|:&};:', 'dd if=/dev/zero of=/dev/']
        for blocked in _BLOCKED:
            if blocked in cmd:
                return ToolResult('shell', False, f'Blocked dangerous command: {blocked}')

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, cwd=cwd
            )
            output = (result.stdout + result.stderr).strip()
            success = result.returncode == 0
            obs = output[:2000] if output else f'(exit code {result.returncode})'
            return ToolResult('shell', success, obs,
                              {'returncode': result.returncode,
                               'stdout': result.stdout[:2000],
                               'stderr': result.stderr[:500]})
        except subprocess.TimeoutExpired:
            return ToolResult('shell', False, f'Command timed out after {timeout}s')
        except Exception as e:
            return ToolResult('shell', False, str(e))

    def _file_read(self, args: dict) -> ToolResult:
        path    = args.get('path', '')
        max_len = int(args.get('max_len', 8000))
        if not path:
            return ToolResult('file_read', False, 'path required')
        try:
            content = Path(path).read_text(errors='replace')[:max_len]
            return ToolResult('file_read', True, content,
                              {'path': path, 'size': len(content)})
        except FileNotFoundError:
            return ToolResult('file_read', False, f'File not found: {path}')
        except Exception as e:
            return ToolResult('file_read', False, str(e))

    def _file_write(self, args: dict) -> ToolResult:
        path    = args.get('path', '')
        content = args.get('content', '')
        mode    = args.get('mode', 'w')   # 'w' overwrite, 'a' append
        if not path:
            return ToolResult('file_write', False, 'path required')
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, mode) as f:
                f.write(content)
            return ToolResult('file_write', True,
                              f'Written {len(content)} chars to {path}',
                              {'path': path, 'bytes': len(content)})
        except Exception as e:
            return ToolResult('file_write', False, str(e))

    def _web_fetch(self, args: dict) -> ToolResult:
        url     = args.get('url', '')
        timeout = int(args.get('timeout', 15))
        if not url:
            return ToolResult('web_fetch', False, 'url required')
        try:
            import requests
            import config
            proxies = config.get_proxies()
            r = requests.get(url, timeout=timeout, proxies=proxies,
                             headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            text = r.text[:5000]
            return ToolResult('web_fetch', True,
                              f'HTTP {r.status_code} — {len(r.text)} chars',
                              {'status_code': r.status_code, 'content': text,
                               'url': url})
        except Exception as e:
            return ToolResult('web_fetch', False, str(e))

    # ── Sentinel System Tools ─────────────────────────────────────────────────

    def _tor_on(self, args: dict) -> ToolResult:
        try:
            import subprocess as sp, time as t, config
            sp.run(['sudo', 'systemctl', 'start', 'tor'],
                   capture_output=True, timeout=20)
            t.sleep(3)
            from modules.utils import tor_session
            sess = tor_session()
            r    = sess.get('https://httpbin.org/ip', timeout=15)
            ip   = r.json().get('origin', '?')
            config.tor_on()
            return ToolResult('tor_on', True, f'Tor enabled — Exit IP: {ip}',
                              {'exit_ip': ip})
        except Exception as e:
            return ToolResult('tor_on', False, str(e))

    def _tor_off(self, args: dict) -> ToolResult:
        import config
        config.tor_off()
        return ToolResult('tor_off', True, 'Tor disabled — direct connection')

    def _tor_newip(self, args: dict) -> ToolResult:
        result = self._shell({'command': 'echo SIGNAL NEWNYM | nc 127.0.0.1 9051', 'timeout': 10})
        return ToolResult('tor_newip', result.success, 'New Tor circuit requested')

    def _notify(self, args: dict) -> ToolResult:
        message = args.get('message', '')
        if not message:
            return ToolResult('notify', False, 'message required')
        try:
            from modules.notifications import TelegramNotifier
            import config
            ok = TelegramNotifier(config.TELEGRAM_BOT_TOKEN,
                                  config.TELEGRAM_CHAT_ID).send(message)
            return ToolResult('notify', ok,
                              'Telegram alert sent' if ok else 'Telegram send failed')
        except Exception as e:
            return ToolResult('notify', False, str(e))

    def _db_query(self, args: dict) -> ToolResult:
        target = args.get('target', '')
        if not target:
            return ToolResult('db_query', False, 'target required')
        try:
            from modules.database import SentinelDB as DB
            history  = DB.get_target_history(target)
            findings = DB.get_findings(target)
            ioc      = DB.check_ioc(target)
            obs = (f"DB: {len(history)} scans, {len(findings)} findings"
                   + (f", IOC: {ioc['threat']}" if ioc['found'] else ''))
            return ToolResult('db_query', True, obs,
                              {'history': history, 'findings': findings, 'ioc': ioc})
        except Exception as e:
            return ToolResult('db_query', False, str(e))

    def _save_evidence(self, args: dict) -> ToolResult:
        label = args.get('label', 'agent_evidence')
        data  = args.get('data', {})
        try:
            if self._sentinel:
                self._sentinel.evidence.add_evidence(label, data)
            return ToolResult('save_evidence', True, f'Evidence saved: {label}')
        except Exception as e:
            return ToolResult('save_evidence', False, str(e))

    def _generate_report(self, args: dict) -> ToolResult:
        try:
            if self._sentinel:
                paths = self._sentinel.session_data.get('last_paths', {})
                pdf   = self._sentinel.pdf.export_scan(paths)
                return ToolResult('generate_report', True,
                                  f'Report: {pdf or paths.get("html","N/A")}',
                                  {'paths': paths, 'pdf': pdf})
            return ToolResult('generate_report', False, 'No sentinel instance')
        except Exception as e:
            return ToolResult('generate_report', False, str(e))
