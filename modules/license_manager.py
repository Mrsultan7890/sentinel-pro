"""
Sentinel Pro — License Manager v2.0
=====================================
Server-side validation via Sentinel License Server.
2-factor: half_key (Telegram) + machine binding (activate).

Author: @who_is_the_black_hat
"""

import hashlib
import json
import logging
import uuid
import httpx
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# HTTP logs suppress karo
import logging as _logging
_logging.getLogger("httpx").setLevel(_logging.WARNING)

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_URL   = "https://sentinel-server-a7i9.onrender.com"
LICENSE_FILE = Path.home() / '.sentinel_pro' / 'license.key'

PLANS = {
    'trial':   'Trial   — 1 Day    — Limited Features',
    'starter': 'Starter — 1 Month  — Full Access',
    'pro':     'Pro     — 3 Months — Full Access',
    'elite':   'Elite   — 1 Year   — Full Access',
}

TRIAL_BLOCKED = ['sentinel_proxy', 'sentinel_intel']

# ── Machine ID ────────────────────────────────────────────────────────────────
def _get_machine_id() -> str:
    try:
        mid = Path('/etc/machine-id')
        if mid.exists():
            return mid.read_text().strip()[:16]
    except Exception:
        pass
    try:
        mac = uuid.getnode()
        return hashlib.md5(str(mac).encode()).hexdigest()[:16]
    except Exception:
        return 'unknown'

def _machine_hash() -> str:
    return hashlib.sha256(_get_machine_id().encode()).hexdigest()[:32]

# ── Save / Load ───────────────────────────────────────────────────────────────
def _save(data: dict) -> bool:
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LICENSE_FILE.write_text(json.dumps(data, indent=2))
        LICENSE_FILE.chmod(0o600)
        return True
    except Exception as e:
        logger.error(f"License save error: {e}")
        return False

def _load() -> dict:
    try:
        if LICENSE_FILE.exists():
            return json.loads(LICENSE_FILE.read_text())
    except Exception:
        pass
    return {}

# ── Server calls ──────────────────────────────────────────────────────────────
def _post(endpoint: str, payload: dict) -> dict:
    try:
        r = httpx.post(f"{SERVER_URL}{endpoint}", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        detail = e.response.json().get("detail", str(e))
        return {"error": detail, "status_code": e.response.status_code}
    except Exception as e:
        return {"error": f"Server unreachable: {e}"}

# ── Activate ──────────────────────────────────────────────────────────────────
def activate(half_key: str) -> dict:
    half_key = half_key.strip()
    if not half_key.startswith("SNTNL-") or not half_key.endswith("-PENDING"):
        return {'success': False, 'message': 'Invalid key format. Bot se mila SNTNL-...-PENDING key daalo.'}

    mhash = _machine_hash()
    result = _post("/activate", {"half_key": half_key, "machine_hash": mhash})

    if "error" in result:
        return {'success': False, 'message': result["error"]}

    final_key   = result["final_key"]
    plan        = result["plan"]
    expires_at  = result["expires_at"][:10]
    telegram_id = result.get("telegram_id", "")

    _save({
        "final_key":    final_key,
        "plan":         plan,
        "expires_at":   expires_at,
        "machine_hash": mhash,
    })

    # Telegram notification — fire and forget
    if telegram_id:
        _post("/notify", {
            "telegram_id": telegram_id,
            "plan":        plan,
            "expires_at":  expires_at,
        })

    plan_name = PLANS.get(plan, plan)
    return {
        'success': True,
        'message': f"License activated!\n  Plan   : {plan_name}\n  Expiry : {expires_at}",
        'data': result,
    }

# ── Check (startup) ───────────────────────────────────────────────────────────
def check_license() -> dict:
    saved = _load()
    if not saved or 'final_key' not in saved:
        return {'valid': False, 'reason': 'No license found. Bot se key lo aur activate karo.'}

    mhash = _machine_hash()
    if saved.get('machine_hash') != mhash:
        return {'valid': False, 'reason': 'Machine mismatch — license is machine ke liye nahi hai.'}

    result = _post("/validate", {"final_key": saved["final_key"], "machine_hash": mhash})

    if "error" in result:
        # Server se HTTP error aaya (403 expired, 401 invalid) — cache use mat karo
        if result.get('status_code') in (401, 403):
            return {'valid': False, 'reason': result['error']}
        # Network unreachable — cached use karo agar expire nahi hua
        exp = saved.get('expires_at', '')
        if exp and datetime.utcnow().date() <= datetime.fromisoformat(exp).date():
            logger.warning("Server unreachable — using cached license")
            return {
                'valid':      True,
                'plan':       saved['plan'],
                'expires_at': exp,
                'features':   ['all'] if saved['plan'] != 'trial' else None,
                'cached':     True,
            }
        return {'valid': False, 'reason': result["error"]}

    saved['plan']       = result['plan']
    saved['expires_at'] = result['expires_at'][:10]
    _save(saved)

    return {
        'valid':      True,
        'plan':       result['plan'],
        'expires_at': result['expires_at'][:10],
        'features':   result['features'],
    }

# ── Feature check ─────────────────────────────────────────────────────────────
def is_feature_allowed(feature: str, license_data: dict) -> bool:
    if not license_data.get('valid'):
        return False
    plan = license_data.get('plan', '')
    if plan == 'trial' and feature in TRIAL_BLOCKED:
        return False
    return True
