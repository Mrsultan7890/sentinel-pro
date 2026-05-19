"""
Notification Agent — Multi-Channel Alerts
==========================================
- Desktop notifications (notify-send)
- Telegram alerts (already hai, unified karo)
- Sound alerts
- System tray updates
- Email alerts (optional)

Author: @who_is_the_black_hat
"""

import logging
import subprocess
import time
from pathlib import Path

import config

logger = logging.getLogger(__name__)

SOUNDS_DIR = config.BASE_DIR / 'sounds'

# Severity → icon + sound
SEV_CONFIG = {
    'CRITICAL': {'icon': 'dialog-error',    'urgency': 'critical', 'sound': 'critical.wav'},
    'HIGH':     {'icon': 'dialog-warning',  'urgency': 'critical', 'sound': 'high.wav'},
    'MEDIUM':   {'icon': 'dialog-information', 'urgency': 'normal', 'sound': 'medium.wav'},
    'LOW':      {'icon': 'dialog-information', 'urgency': 'low',    'sound': None},
    'INFO':     {'icon': 'dialog-information', 'urgency': 'low',    'sound': None},
}


class NotificationAgent:
    NAME = 'notification_agent'

    def __init__(self):
        self._telegram   = self._init_telegram()
        self._notify_ok  = self._check_notify_send()
        self._sound_ok   = self._check_sound()
        self._history    = []

    def _init_telegram(self):
        try:
            from modules.notifications import TelegramNotifier
            n = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
            return n if n.enabled else None
        except Exception:
            return None

    def _check_notify_send(self) -> bool:
        r = subprocess.run(['which', 'notify-send'], capture_output=True)
        return r.returncode == 0

    def _check_sound(self) -> bool:
        for player in ('paplay', 'aplay', 'mpg123', 'ffplay'):
            r = subprocess.run(['which', player], capture_output=True)
            if r.returncode == 0:
                self._sound_player = player
                return True
        return False

    # ── Main Alert ────────────────────────────────────────────────────────────

    def alert(self, title: str, message: str, severity: str = 'INFO',
              channels: list = None) -> dict:
        """
        Multi-channel alert bhejo.
        channels: ['desktop', 'telegram', 'sound'] — None = all
        """
        channels = channels or ['desktop', 'telegram', 'sound']
        results  = {}
        cfg      = SEV_CONFIG.get(severity.upper(), SEV_CONFIG['INFO'])

        if 'desktop' in channels:
            results['desktop'] = self.desktop(title, message, severity)

        if 'telegram' in channels:
            results['telegram'] = self.telegram(title, message, severity)

        if 'sound' in channels and cfg['sound']:
            results['sound'] = self.sound(severity)

        # History
        self._history.append({
            'time':     time.strftime('%H:%M:%S'),
            'title':    title,
            'message':  message[:100],
            'severity': severity,
            'channels': list(results.keys()),
        })
        self._history = self._history[-50:]

        return results

    # ── Desktop Notification ──────────────────────────────────────────────────

    def desktop(self, title: str, message: str, severity: str = 'INFO',
                timeout: int = 5000) -> bool:
        """notify-send se desktop notification bhejo."""
        if not self._notify_ok:
            return False
        cfg = SEV_CONFIG.get(severity.upper(), SEV_CONFIG['INFO'])
        try:
            subprocess.run([
                'notify-send',
                '--urgency', cfg['urgency'],
                '--icon',    cfg['icon'],
                '--expire-time', str(timeout),
                f'🛡️ Sentinel — {title}',
                message[:4000],
            ], capture_output=True, timeout=5)
            return True
        except Exception as e:
            logger.debug(f"[NotificationAgent] desktop error: {e}")
            return False

    # ── Telegram ──────────────────────────────────────────────────────────────

    def telegram(self, title: str, message: str, severity: str = 'INFO') -> bool:
        """Telegram alert bhejo."""
        if not self._telegram:
            return False
        icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}
        icon  = icons.get(severity.upper(), 'ℹ️')
        text  = (
            f"{icon} *{title}*\n"
            f"{message}\n\n"
            f"_Sentinel Pro — {time.strftime('%H:%M:%S')}_"
        )
        try:
            return self._telegram.send(text)
        except Exception as e:
            logger.debug(f"[NotificationAgent] telegram error: {e}")
            return False

    # ── Sound ─────────────────────────────────────────────────────────────────

    def sound(self, severity: str = 'INFO') -> bool:
        """Sound alert bajao."""
        if not self._sound_ok:
            return False
        cfg       = SEV_CONFIG.get(severity.upper(), SEV_CONFIG['INFO'])
        sound_file = None
        
        # Check if sounds directory and file exist
        if cfg['sound'] and SOUNDS_DIR.exists():
            sound_file = SOUNDS_DIR / cfg['sound']
            if not sound_file.exists():
                sound_file = None
                logger.debug(f"[NotificationAgent] Sound file not found: {sound_file}")

        if sound_file and sound_file.exists():
            try:
                subprocess.Popen(
                    [self._sound_player, str(sound_file)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                return True
            except Exception as e:
                logger.debug(f"[NotificationAgent] Sound playback failed: {e}")

        # Fallback — system beep
        try:
            subprocess.run(['paplay', '/usr/share/sounds/freedesktop/stereo/message.oga'],
                           capture_output=True, timeout=3)
            return True
        except Exception as e:
            logger.debug(f"[NotificationAgent] System beep fallback failed: {e}")

        # Terminal bell
        print('\a', end='', flush=True)
        return True

    # ── Scan Notifications ────────────────────────────────────────────────────

    def scan_started(self, target: str, scan_type: str):
        self.alert(
            f'{scan_type.upper()} Started',
            f'Target: {target}',
            severity='INFO',
            channels=['desktop'],
        )

    def scan_complete(self, target: str, risk: str, findings: int):
        self.alert(
            f'Scan Complete — {risk}',
            f'Target: {target}\nFindings: {findings}',
            severity=risk,
            channels=['desktop', 'telegram', 'sound'],
        )

    def critical_finding(self, target: str, title: str, detail: str):
        self.alert(
            f'🚨 CRITICAL: {title}',
            f'Target: {target}\n{detail[:150]}',
            severity='CRITICAL',
            channels=['desktop', 'telegram', 'sound'],
        )

    def new_monitor_finding(self, target: str, findings: list):
        sorted_findings = sorted(
            findings,
            key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.get('severity', 'LOW'), 4)
        )
        top = sorted_findings[0] if sorted_findings else {}

        details = []
        for f in sorted_findings:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(f.get('severity', 'LOW'), '⚪')
            details.append(f"{icon} {f.get('title', 'Unknown')}: {f.get('detail', '')[:80]}")

        message = f"Target: {target}\n\nALL FINDINGS:\n" + "\n".join(details)

        self.alert(
            f'Monitor Alert — {len(findings)} new finding(s)',
            message,
            severity=top.get('severity', 'MEDIUM'),
            channels=['desktop', 'telegram', 'sound'],
        )

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self, last: int = 20) -> list:
        return self._history[-last:]

    def status(self) -> dict:
        return {
            'desktop':  self._notify_ok,
            'telegram': self._telegram is not None,
            'sound':    self._sound_ok,
            'history':  len(self._history),
        }
