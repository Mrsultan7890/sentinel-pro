"""
Report Agent — HTML/PDF report generation + Telegram alerts
Court-grade evidence, executive summary, CVSS scores

Author: @who_is_the_black_hat
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)


class ReportAgent:
    NAME = 'report_agent'

    def __init__(self, memory: Memory, sentinel=None):
        self.memory   = memory
        self.sentinel = sentinel

    def run(self, target: str, all_results: dict) -> dict:
        logger.info(f"[ReportAgent] Generating report for {target}")

        # Memory se findings lo
        findings = self.memory.recall_findings(target)
        history  = self.memory.recall_target(target)

        # Overall risk
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        risk = 'LOW'
        for f in findings:
            if sev_order.get(f['severity'], 4) < sev_order.get(risk, 4):
                risk = f['severity']

        # Telegram alert
        tg_sent = self._send_telegram(target, findings, risk, all_results)

        # Report paths
        paths = {}
        if self.sentinel:
            try:
                paths = self.sentinel.session_data.get('last_paths', {})
                if not paths:
                    # Generate from last scan data
                    scan_type = list(all_results.keys())[0] if all_results else 'scan'
                    paths = self._save_report(target, scan_type, all_results, findings, risk)
            except Exception as e:
                logger.error(f"[ReportAgent] Report generation failed: {e}")
                paths = self._save_report(target, 'scan', all_results, findings, risk)
        else:
            paths = self._save_report(target, 'scan', all_results, findings, risk)

        summary = f"Report generated: risk={risk}, {len(findings)} findings, telegram={'sent' if tg_sent else 'failed'}"
        self.memory.remember_decision(target, self.NAME, 'report', 'Final report', summary)

        return {
            'risk':     risk,
            'findings': findings,
            'paths':    paths,
            'telegram': tg_sent,
            '_agent_summary': summary,
        }

    def _send_telegram(self, target: str, findings: list, risk: str, all_results: dict) -> bool:
        try:
            import config
            from modules.notifications import TelegramNotifier

            notifier = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
            if not notifier.enabled:
                return False

            # Determine scan type for header
            scan_types = list(all_results.keys())
            has_bugbounty = any('bugbounty' in k or 'exploit' in k for k in scan_types)
            has_recon     = any('recon' in k for k in scan_types)

            header = '🚨 BUG BOUNTY ALERT' if has_bugbounty else ('🔍 RECON ALERT' if has_recon else '🛡️ SENTINEL ALERT')

            lines = [
                header,
                f"Target : {target}",
                f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"Risk   : {risk}",
                "",
                "TOP FINDINGS:",
            ]

            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            top = sorted(findings, key=lambda f: sev_order.get(f['severity'], 4))[:6]

            for f in top:
                icon = '🔴' if f['severity'] == 'CRITICAL' else '🟠'
                # Clean title — no brackets, no payloads
                title = f['title'].replace('[', '').replace(']', '').strip()
                detail = f['detail'][:60].split('\n')[0].strip()
                lines.append(f"{icon} {title} — {detail}" if detail else f"{icon} {title}")

            lines.append("")
            lines.append("Sentinel Pro — @who_is_the_black_hat")

            return notifier.send('\n'.join(lines))

        except Exception as e:
            logger.error(f"[ReportAgent] Telegram failed: {e}")
            return False

    def _save_report(self, target: str, scan_type: str, data: dict,
                     findings: list, risk: str) -> dict:
        """Improved report save — Groq summary + MITRE + chart"""
        try:
            from modules.report_builder import SentinelReportBuilder
            builder = SentinelReportBuilder()
            paths   = builder.build(target, scan_type, data, findings, risk)
            logger.info(f"[ReportAgent] Report built: {paths.get('html','')}")
            return paths
        except Exception as e:
            logger.error(f"[ReportAgent] report_builder failed: {e}")
            # Fallback
            ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
            # Sanitize target to prevent path traversal
            import re
            safe = re.sub(r'[^a-zA-Z0-9._-]', '_', target)[:50]
            safe = safe.strip('._')  # Remove leading/trailing dots and underscores
            base = Path(f'/home/kali/osints/reports/brain_{safe}_{ts}')
            report = {
                'target': target, 'scan_type': scan_type,
                'risk': risk, 'timestamp': datetime.now().isoformat(),
                'findings': findings, 'data': data,
            }
            json_path = str(base) + '.json'
            txt_path  = str(base) + '_summary.txt'
            with open(json_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            with open(txt_path, 'w') as f:
                f.write(f"Target: {target}\nRisk: {risk}\n")
                for fn in findings:
                    f.write(f"  [{fn['severity']}] {fn['title']}: {fn.get('detail','')[:100]}\n")
            return {'json': json_path, 'txt': txt_path}
