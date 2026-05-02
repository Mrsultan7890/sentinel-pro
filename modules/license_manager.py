"""
Sentinel Pro — License Manager
================================
Offline license system — no server needed.
HMAC-SHA256 based key verification + machine binding.

Author: @who_is_the_black_hat
"""

import hashlib
import hmac
import base64
import json
import logging
import uuid
import platform
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Secret — derived at runtime, not stored as plain text ────────────────────
def _get_secret() -> bytes:
    """Secret ko runtime pe derive karo — plain text mein store nahi."""
    parts = [
        b"s3nt1n3l",
        b"_pr0_",
        b"@wh0_1s_",
        b"th3_bl4ck",
        b"_h4t_2024",
        b"_x9z",
    ]
    return b"".join(parts)

# ── License file location ─────────────────────────────────────────────────────
LICENSE_FILE = Path.home() / '.sentinel_pro' / 'license.key'

# ── Plans ─────────────────────────────────────────────────────────────────────
PLANS = {
    'basic':  'Basic  — 1 Month   — Full Access',
    'pro':    'Pro    — 3 Months  — Full Access',
    'elite':  'Elite  — 1 Year    — Full Access',
}


# ── Machine ID ────────────────────────────────────────────────────────────────
def _get_machine_id() -> str:
    """Machine ka unique ID generate karo."""
    try:
        # Linux: /etc/machine-id
        mid = Path('/etc/machine-id')
        if mid.exists():
            return mid.read_text().strip()[:16]
    except Exception:
        pass
    try:
        # Fallback: MAC address
        mac = uuid.getnode()
        return hashlib.md5(str(mac).encode()).hexdigest()[:16]
    except Exception:
        return 'unknown'


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
        _SECRET  = _get_secret()
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
    """License file mein save karo — machine ID bind karo."""
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        machine_id = _get_machine_id()
        LICENSE_FILE.write_text(json.dumps({
            'key': key,
            'mid': machine_id,
            **data
        }, indent=2))
        LICENSE_FILE.chmod(0o600)
        return True
    except Exception as e:
        logger.error(f"License save error: {e}")
        return False


def load_license() -> dict:
    """Saved license load karo + machine ID verify karo."""
    try:
        if LICENSE_FILE.exists():
            saved = json.loads(LICENSE_FILE.read_text())
            # Machine ID check
            saved_mid   = saved.get('mid', '')
            current_mid = _get_machine_id()
            if saved_mid and saved_mid != current_mid:
                logger.warning("License machine mismatch")
                return {}
            return saved
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
