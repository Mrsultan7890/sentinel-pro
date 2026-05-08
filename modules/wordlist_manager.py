"""
Wordlist Manager — Central wordlist resolution
===============================================
Priority:
  1. Tool ke saath bundled wordlists (sentinel_proxy/payloads/)
  2. Kali Linux system wordlists (/usr/share/seclists, /usr/share/wordlists)
  3. Hardcoded fallback (always works — no deps)

Agar system wordlist missing ho toh user ko clearly batata hai
kaise install kare — tool crash nahi karta.

Author: @who_is_the_black_hat
"""

import logging
from pathlib import Path
from functools import lru_cache

import config

logger = logging.getLogger(__name__)

# ── Known system wordlist locations ──────────────────────────────────────────

SECLISTS_ROOTS = [
    Path('/usr/share/seclists'),
    Path('/usr/share/SecLists'),
    Path('/opt/seclists'),
    Path('/opt/SecLists'),
]

WORDLISTS_ROOTS = [
    Path('/usr/share/wordlists'),
    Path('/usr/local/share/wordlists'),
]

# ── Wordlist map ──────────────────────────────────────────────────────────────
# format: name → [(path_relative_to_root, root_type), ...]
# root_type: 'seclists' | 'wordlists'

WORDLIST_MAP = {
    # Directory brute-force
    'dirbust_fast': [
        ('Discovery/Web-Content/common.txt',              'seclists'),
        ('dirb/common.txt',                               'wordlists'),
    ],
    'dirbust_normal': [
        ('Discovery/Web-Content/common.txt',              'seclists'),
        ('dirb/common.txt',                               'wordlists'),
    ],
    'dirbust_deep': [
        ('Discovery/Web-Content/big.txt',                 'seclists'),
        ('Discovery/Web-Content/raft-large-directories.txt', 'seclists'),
        ('dirb/big.txt',                                  'wordlists'),
    ],
    # Subdomain brute-force
    'subdomains': [
        ('Discovery/DNS/subdomains-top1million-5000.txt', 'seclists'),
        ('Discovery/DNS/bitquark-subdomains-top100000.txt', 'seclists'),
    ],
    # Parameter fuzzing
    'params': [
        ('Discovery/Web-Content/burp-parameter-names.txt','seclists'),
        ('Discovery/Web-Content/api/objects.txt',         'seclists'),
    ],
    # Password / brute-force
    'passwords': [
        ('Passwords/Common-Credentials/10-million-password-list-top-1000.txt', 'seclists'),
        ('rockyou.txt',                                   'wordlists'),
    ],
    # Usernames
    'usernames': [
        ('Usernames/top-usernames-shortlist.txt',         'seclists'),
        ('Usernames/Names/names.txt',                     'seclists'),
    ],
    # SQLi
    'sqli': [
        ('Fuzzing/SQLi/Generic-SQLi.txt',                 'seclists'),
    ],
    # XSS
    'xss': [
        ('Fuzzing/XSS/XSS-Jhaddix.txt',                  'seclists'),
    ],
    # LFI
    'lfi': [
        ('Fuzzing/LFI/LFI-Jhaddix.txt',                  'seclists'),
    ],
}

# Install instructions per package
INSTALL_CMDS = {
    'seclists':  'sudo apt install seclists',
    'wordlists': 'sudo apt install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz',
}


@lru_cache(maxsize=32)
def find_wordlist(name: str) -> tuple:
    """
    Wordlist dhundho.

    Returns:
        (path_str, source) — source: 'bundled' | 'seclists' | 'wordlists' | 'fallback'
        path_str is None agar koi nahi mila
    """
    if not name or not isinstance(name, str):
        logger.error('Invalid wordlist name')
        return (None, 'invalid')
    
    try:
        # 1. Bundled payloads (sentinel_proxy/payloads/)
        bundled = config.get_base_dir() / 'sentinel_proxy' / 'payloads' / f'{name}.txt'
        if bundled.exists() and bundled.is_file():
            return (str(bundled), 'bundled')

        # 2. System wordlists
        for rel_path, root_type in WORDLIST_MAP.get(name, []):
            roots = SECLISTS_ROOTS if root_type == 'seclists' else WORDLISTS_ROOTS
            for root in roots:
                full = root / rel_path
                if full.exists() and full.is_file():
                    return (str(full), root_type)

        return (None, 'missing')
    except Exception as e:
        logger.error(f'find_wordlist error: {e}')
        return (None, 'error')


def get_wordlist(name: str, fallback: list = None) -> list:
    """
    Wordlist load karo.
    Agar missing ho toh fallback list return karo aur user ko batao.

    Returns: list of strings
    """
    if not name or not isinstance(name, str):
        logger.error('Invalid wordlist name')
        return fallback or []
    
    if fallback is not None and not isinstance(fallback, list):
        fallback = []
    
    path, source = find_wordlist(name)

    if path:
        try:
            p = Path(path)
            # Size check - max 100MB
            if p.stat().st_size > 100 * 1024 * 1024:
                logger.warning(f'Wordlist too large: {path} ({p.stat().st_size / 1024 / 1024:.1f}MB)')
                return fallback or []
            
            lines = p.read_text(errors='ignore').splitlines()
            result = [l.strip() for l in lines if l.strip() and not l.startswith('#')]
            
            # Max entries limit
            if len(result) > 1000000:  # 1M entries max
                logger.warning(f'Wordlist too large: {len(result)} entries, truncating to 1M')
                result = result[:1000000]
            
            logger.debug(f"[Wordlist] {name}: {len(result)} entries from {source} ({path})")
            return result
        except (OSError, IOError, PermissionError) as e:
            logger.warning(f"[Wordlist] Failed to read {path}: {e}")
        except Exception as e:
            logger.error(f"[Wordlist] Unexpected error reading {path}: {e}")

    # Missing — log warning with install instructions
    _warn_missing(name)
    return fallback or []


def _warn_missing(name: str):
    """User ko clearly batao kya install karna hai."""
    if not name or not isinstance(name, str):
        return
    
    try:
        needed = set()
        for _, root_type in WORDLIST_MAP.get(name, []):
            needed.add(root_type)

        for pkg in needed:
            cmd = INSTALL_CMDS.get(pkg, f'sudo apt install {pkg}')
            logger.warning(
                f"[Wordlist] '{name}' not found. Install with: {cmd}"
            )
    except Exception as e:
        logger.debug(f'_warn_missing error: {e}')


def check_wordlists() -> dict:
    """
    Sab wordlists ka status check karo.
    CLI 'status' command mein use hota hai.

    Returns: {name: {'found': bool, 'path': str, 'source': str, 'install': str}}
    """
    results = {}
    try:
        for name in WORDLIST_MAP:
            try:
                path, source = find_wordlist(name)
                needed_pkgs = list({rt for _, rt in WORDLIST_MAP[name]})
                install_cmd = ' | '.join(INSTALL_CMDS.get(p, '') for p in needed_pkgs if p in INSTALL_CMDS)
                results[name] = {
                    'found':   path is not None,
                    'path':    path or '',
                    'source':  source,
                    'install': install_cmd if not path else '',
                }
            except Exception as e:
                logger.debug(f'check_wordlists error for {name}: {e}')
                results[name] = {
                    'found': False,
                    'path': '',
                    'source': 'error',
                    'install': '',
                }
    except Exception as e:
        logger.error(f'check_wordlists error: {e}')
    return results


def wordlist_status_table() -> str:
    """Rich-formatted status string for CLI display."""
    results = check_wordlists()
    found   = sum(1 for r in results.values() if r['found'])
    total   = len(results)

    lines = [f"\n[bold cyan]Wordlist Status ({found}/{total} available)[/bold cyan]\n"]

    for name, info in results.items():
        if info['found']:
            src = f"[dim]{info['source']}[/dim]"
            lines.append(f"  [green]✓[/green] {name:<20} {src}")
        else:
            cmd = info['install']
            lines.append(f"  [yellow]✗[/yellow] {name:<20} [dim]missing — {cmd}[/dim]")

    if found < total:
        lines.append(
            f"\n[dim]Install missing: sudo apt install seclists wordlists[/dim]"
        )
    return '\n'.join(lines)
