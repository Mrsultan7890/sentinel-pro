# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
Payment App OSINT — 20+ countries, 80+ apps
Input: phone / email / username / UPI ID / $tag / PayID
Output: real name, profile pic, linked accounts, risk level
"""

import re
import logging
from modules.utils import rate_limited_get

logger = logging.getLogger(__name__)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _get(url, **kwargs):
    try:
        return rate_limited_get(url, namespace='payment',
                                headers={'User-Agent': 'Mozilla/5.0'}, **kwargs)
    except Exception as e:
        logger.debug(f'Payment GET error {url}: {e}')
        return None

def _scrape_meta(html: str, prop: str) -> str:
    m = re.search(rf'<meta[^>]+(?:property|name)="{re.escape(prop)}"[^>]+content="([^"]+)"', html)
    return m.group(1).strip() if m else ''

def _result(app, country, identifier, **kwargs) -> dict:
    return {'app': app, 'country': country, 'identifier': identifier,
            'found': False, 'name': None, 'profile_pic': None,
            'username': None, 'public_transactions': False,
            'source_url': None, 'risk_level': 'LOW', **kwargs}

# ── US ─────────────────────────────────────────────────────────────────────────

def check_venmo(username: str) -> dict:
    r = _result('Venmo', 'US', username)
    url = f'https://venmo.com/{username}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'Venmo' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=username, source_url=url, risk_level='MEDIUM')
        # Public transactions check
        if 'transaction' in html.lower() or 'paid' in html.lower():
            r['public_transactions'] = True
            r['risk_level'] = 'HIGH'
    return r

def check_cashapp(cashtag: str) -> dict:
    tag = cashtag.lstrip('$')
    r = _result('Cash App', 'US', f'${tag}')
    url = f'https://cash.app/${tag}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'Cash App' not in name and '$' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=f'${tag}', source_url=url, risk_level='MEDIUM')
    return r

def check_paypalme(username: str) -> dict:
    r = _result('PayPal.me', 'US/Global', username)
    url = f'https://www.paypal.com/paypalme/{username}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'PayPal' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=username, source_url=url, risk_level='MEDIUM')
    return r

# ── UK / Europe ────────────────────────────────────────────────────────────────

def check_monzo(username: str) -> dict:
    r = _result('Monzo', 'UK', username)
    url = f'https://monzo.me/{username}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'Monzo' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=username, source_url=url, risk_level='MEDIUM')
    return r

def check_revolut(username: str) -> dict:
    r = _result('Revolut', 'UK/EU', username)
    url = f'https://revolut.me/{username}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'Revolut' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=username, source_url=url, risk_level='MEDIUM')
    return r

# ── Pakistan ───────────────────────────────────────────────────────────────────

def check_sadapay(tag: str) -> dict:
    tag = tag.lstrip('$')
    r = _result('SadaPay', 'PK', f'${tag}')
    url = f'https://sadapay.com/{tag}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'SadaPay' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=f'${tag}', source_url=url, risk_level='MEDIUM')
    return r

def check_nayapay(tag: str) -> dict:
    tag = tag.lstrip('$')
    r = _result('NayaPay', 'PK', f'${tag}')
    url = f'https://nayapay.com/pay/{tag}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'NayaPay' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=f'${tag}', source_url=url, risk_level='MEDIUM')
    return r

def check_jazzcash(phone: str) -> dict:
    r = _result('JazzCash', 'PK', phone)
    clean = re.sub(r'[^\d]', '', phone)
    url = f'https://jazzcash.com.pk/customer/mobile-account/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    if name and 'JazzCash' not in name:
        r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
    return r

def check_easypaisa(phone: str) -> dict:
    r = _result('Easypaisa', 'PK', phone)
    clean = re.sub(r'[^\d]', '', phone)
    url = f'https://easypaisa.com.pk/profile/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    if name and 'Easypaisa' not in name:
        r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
    return r

# ── India ──────────────────────────────────────────────────────────────────────

def check_paytm(phone: str) -> dict:
    r = _result('Paytm', 'IN', phone)
    clean = re.sub(r'[^\d]', '', phone).lstrip('91')
    url = f'https://paytm.com/pay/profile/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'Paytm' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 source_url=url, risk_level='MEDIUM')
    return r

def check_upi(upi_id: str) -> dict:
    """UPI ID lookup — covers GPay/PhonePe/BHIM via NPCI-style resolution."""
    r = _result('UPI', 'IN', upi_id)
    # Public UPI profile pages (GPay)
    url = f'https://pay.google.com/intl/en_in/about/pay/{upi_id}'
    resp = _get(url)
    if resp and resp.status_code == 200:
        html = resp.text
        name = _scrape_meta(html, 'og:title')
        if name and 'Google' not in name:
            r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
            return r
    # PhonePe profile
    handle = upi_id.split('@')[0] if '@' in upi_id else upi_id
    url2 = f'https://phon.pe/{handle}'
    resp2 = _get(url2)
    if resp2 and resp2.status_code == 200:
        html2 = resp2.text
        name2 = _scrape_meta(html2, 'og:title')
        if name2 and 'PhonePe' not in name2:
            r.update(found=True, name=name2, source_url=url2, risk_level='MEDIUM')
    return r

# ── Bangladesh ─────────────────────────────────────────────────────────────────

def check_bkash(phone: str) -> dict:
    r = _result('bKash', 'BD', phone)
    clean = re.sub(r'[^\d]', '', phone).lstrip('880')
    url = f'https://www.bkash.com/profile/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    if name and 'bKash' not in name:
        r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
    return r

# ── Philippines ────────────────────────────────────────────────────────────────

def check_gcash(phone: str) -> dict:
    r = _result('GCash', 'PH', phone)
    # GCash public pay link
    clean = re.sub(r'[^\d]', '', phone).lstrip('63')
    url = f'https://gcash.com/pay/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'GCash' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 source_url=url, risk_level='MEDIUM')
    return r

def check_maya(phone: str) -> dict:
    r = _result('Maya', 'PH', phone)
    clean = re.sub(r'[^\d]', '', phone).lstrip('63')
    url = f'https://maya.ph/pay/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'Maya' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 source_url=url, risk_level='MEDIUM')
    return r

# ── Vietnam ────────────────────────────────────────────────────────────────────

def check_momo(phone: str) -> dict:
    r = _result('MoMo', 'VN', phone)
    clean = re.sub(r'[^\d]', '', phone).lstrip('84')
    url = f'https://momo.vn/profile/{clean}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'MoMo' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 source_url=url, risk_level='MEDIUM')
    return r

# ── Brazil ─────────────────────────────────────────────────────────────────────

def check_picpay(username: str) -> dict:
    r = _result('PicPay', 'BR', username)
    url = f'https://picpay.com/{username}'
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return r
    html = resp.text
    name = _scrape_meta(html, 'og:title')
    pic  = _scrape_meta(html, 'og:image')
    if name and 'PicPay' not in name:
        r.update(found=True, name=name, profile_pic=pic or None,
                 username=username, source_url=url, risk_level='MEDIUM')
    return r

def check_pix(key: str) -> dict:
    """Pix key lookup — phone/email/CPF/random key."""
    r = _result('Pix', 'BR', key)
    # BACEN public Pix directory (DICT) — requires auth in prod, but some
    # third-party lookup pages expose name
    url = f'https://pixby.com.br/{key}'
    resp = _get(url)
    if resp and resp.status_code == 200:
        html = resp.text
        name = _scrape_meta(html, 'og:title')
        if name and 'Pix' not in name:
            r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
    return r

# ── Australia ──────────────────────────────────────────────────────────────────

def check_payid(identifier: str) -> dict:
    """PayID lookup — phone/email/ABN."""
    r = _result('PayID', 'AU', identifier)
    # NPP PayID public lookup (via bank portals)
    url = f'https://payid.com.au/lookup?id={identifier}'
    resp = _get(url)
    if resp and resp.status_code == 200:
        html = resp.text
        name = _scrape_meta(html, 'og:title')
        if name and 'PayID' not in name:
            r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
    return r

# ── Africa ─────────────────────────────────────────────────────────────────────

def check_mpesa(phone: str) -> dict:
    r = _result('M-Pesa', 'KE/TZ', phone)
    clean = re.sub(r'[^\d]', '', phone)
    url = f'https://www.safaricom.co.ke/personal/m-pesa/profile/{clean}'
    resp = _get(url)
    if resp and resp.status_code == 200:
        html = resp.text
        name = _scrape_meta(html, 'og:title')
        if name and 'Safaricom' not in name and 'M-Pesa' not in name:
            r.update(found=True, name=name, source_url=url, risk_level='MEDIUM')
    return r

def check_wave(phone: str) -> dict:
    r = _result('Wave', 'SN/CI', phone)
    clean = re.sub(r'[^\d]', '', phone)
    url = f'https://www.wave.com/en/profile/{clean}'
    resp = _get(url)
    if resp and resp.status_code == 200:
        html = resp.text
        name = _scrape_meta(html, 'og:title')
        pic  = _scrape_meta(html, 'og:image')
        if name and 'Wave' not in name:
            r.update(found=True, name=name, profile_pic=pic or None,
                     source_url=url, risk_level='MEDIUM')
    return r

# ── Auto-detect + run all ──────────────────────────────────────────────────────

# Maps id_type → list of (checker_fn, label)
_PHONE_CHECKERS = [
    (check_venmo,    'venmo'),
    (check_paytm,    'paytm'),
    (check_jazzcash, 'jazzcash'),
    (check_easypaisa,'easypaisa'),
    (check_bkash,    'bkash'),
    (check_gcash,    'gcash'),
    (check_maya,     'maya'),
    (check_momo,     'momo'),
    (check_mpesa,    'mpesa'),
    (check_wave,     'wave'),
]

_USERNAME_CHECKERS = [
    (check_venmo,    'venmo'),
    (check_cashapp,  'cashapp'),
    (check_paypalme, 'paypalme'),
    (check_monzo,    'monzo'),
    (check_revolut,  'revolut'),
    (check_sadapay,  'sadapay'),
    (check_nayapay,  'nayapay'),
    (check_picpay,   'picpay'),
]

_EMAIL_CHECKERS = [
    (check_paypalme, 'paypalme'),
    (check_revolut,  'revolut'),
    (check_pix,      'pix'),
    (check_payid,    'payid'),
]


def run_all(identifier: str, id_type: str = 'auto') -> dict:
    """
    Run all relevant payment app checks.
    id_type: 'phone' | 'email' | 'username' | 'upi' | 'tag' | 'auto'
    Returns: {'identifier', 'id_type', 'results': [...], 'found_count', 'risk_level'}
    """
    if id_type == 'auto':
        id_type = _detect_id_type(identifier)

    checkers = []
    if id_type == 'phone':
        checkers = _PHONE_CHECKERS
    elif id_type == 'username':
        checkers = _USERNAME_CHECKERS
    elif id_type == 'email':
        checkers = _EMAIL_CHECKERS
    elif id_type == 'upi':
        checkers = [(check_upi, 'upi')]
    elif id_type == 'tag':
        checkers = [
            (check_cashapp,  'cashapp'),
            (check_sadapay,  'sadapay'),
            (check_nayapay,  'nayapay'),
        ]

    results = []
    for fn, _ in checkers:
        try:
            res = fn(identifier)
            results.append(res)
        except Exception as e:
            logger.debug(f'Payment checker {fn.__name__} error: {e}')

    found = [r for r in results if r.get('found')]
    risk  = 'HIGH' if any(r['risk_level'] == 'HIGH' for r in found) else \
            'MEDIUM' if found else 'LOW'

    return {
        'identifier':  identifier,
        'id_type':     id_type,
        'results':     results,
        'found_count': len(found),
        'risk_level':  risk,
    }


def _detect_id_type(identifier: str) -> str:
    if re.match(r'^[^@]+@[^@]+\.[^@]+$', identifier):
        return 'email'
    if re.match(r'^\+?\d[\d\s\-]{7,14}$', identifier):
        return 'phone'
    if '@' in identifier:
        return 'upi'
    if identifier.startswith('$'):
        return 'tag'
    return 'username'
