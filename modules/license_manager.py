"""
Sentinel Pro — License Manager
================================
Offline license system — no server needed.
HMAC-SHA256 based key verification.

Author: @who_is_the_black_hat
"""

import hashlib
import hmac
import base64
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Secret — PyArmor se obfuscate hone ke baad hidden rahega ─────────────────
_SECRET = b"s3nt1n3l_pr0_@wh0_1s_th3_bl4ck_h4t_2024_x9z"

# ── License file location ─────────────────────────────────────────────────────
LICENSE_FILE = Path.home() / '.sentinel_pro' / 'license.key'

# ── Plans ─────────────────────────────────────────────────────────────────────
PLANS = {
    'basic':      'Basic  — OSINT + Recon + Breach',
    'pro':        'Pro    — + BugBounty + SentinelProxy',
    'elite':      'Elite  — Everything + Lifetime',
}


# ── Key Generation (seller side) ─────────────────────────────────────────────

def generate_license(email: str, plan: str, expiry: str = 'lifetime') -> str:
    """
    License key generate karo.

    Args:
        email  : buyer email
        plan   : basic / pro / elite
        expiry : YYYY-MM-DD ya 'lifetime'

    Returns:
        License key string
    """
    if plan not in PLANS:
        raise ValueError(f"Invalid plan: {plan}. Choose: {list(PLANS.keys())}")

    data = {
        'e': email,
        'p': plan,
        'x': expiry,
        'i': datetime.now().strftime('%Y-%m-%d'),
    }
    payload   = json.dumps(data, separators=(',', ':'), sort_keys=True)
    sig       = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:12].upper()
    encoded   = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')

    # Format: SENT3-<encoded>-<sig>
    return f"SENT3-{encoded}-{sig}"


# ── Key Verification (tool side) ─────────────────────────────────────────────

def verify_license(key: str) -> dict:
    """
    License key verify karo.

    Returns:
        {valid, plan, expiry, email, issued, reason}
    """
    try:
        key = key.strip()
        if not key.startswith('SENT3-'):
            return {'valid': False, 'reason': 'Invalid key format'}

        parts = key.split('-')
        if len(parts) != 3:
            return {'valid': False, 'reason': 'Invalid key structure'}

        _, encoded, sig = parts

        # Padding restore karo
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding

        payload = base64.urlsafe_b64decode(encoded).decode()
        data    = json.loads(payload)

        # Signature verify karo
        expected = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:12].upper()
        if not hmac.compare_digest(sig, expected):
            return {'valid': False, 'reason': 'Invalid key — tampered'}

        # Expiry check karo
        expiry = data.get('x', 'lifetime')
        if expiry != 'lifetime':
            try:
                exp_date = datetime.strptime(expiry, '%Y-%m-%d')
                if datetime.now() > exp_date:
                    return {'valid': False, 'reason': f'License expired on {expiry}'}
            except ValueError:
                return {'valid': False, 'reason': 'Invalid expiry date'}

        return {
            'valid':  True,
            'plan':   data.get('p', 'unknown'),
            'expiry': expiry,
            'email':  data.get('e', ''),
            'issued': data.get('i', ''),
            'reason': 'OK',
        }

    except Exception as e:
        logger.debug(f"License verify error: {e}")
        return {'valid': False, 'reason': 'Corrupt or invalid key'}


# ── Save / Load ───────────────────────────────────────────────────────────────

def save_license(key: str, data: dict) -> bool:
    """License file mein save karo."""
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LICENSE_FILE.write_text(json.dumps({
            'key': key,
            **data
        }, indent=2))
        LICENSE_FILE.chmod(0o600)
        return True
    except Exception as e:
        logger.error(f"License save error: {e}")
        return False


def load_license() -> dict:
    """Saved license load karo."""
    try:
        if LICENSE_FILE.exists():
            return json.loads(LICENSE_FILE.read_text())
    except Exception:
        pass
    return {}


def check_license() -> dict:
    """
    Startup pe call karo — saved license check karo.
    Returns same as verify_license()
    """
    saved = load_license()
    if not saved or 'key' not in saved:
        return {'valid': False, 'reason': 'No license found'}
    return verify_license(saved['key'])


def activate(key: str) -> dict:
    """
    Key activate karo — verify + save.
    Returns: {success, message, data}
    """
    result = verify_license(key)
    if not result['valid']:
        return {'success': False, 'message': result['reason']}

    if save_license(key, result):
        plan_name = PLANS.get(result['plan'], result['plan'])
        return {
            'success': True,
            'message': f"License activated!\n  Plan   : {plan_name}\n  Email  : {result['email']}\n  Expiry : {result['expiry']}",
            'data':    result,
        }
    return {'success': False, 'message': 'Failed to save license'}
