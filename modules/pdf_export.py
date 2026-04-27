# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
PDF Export — converts Sentinel Pro HTML reports to professional PDFs via WeasyPrint
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PDFExporter:

    def __init__(self):
        try:
            from weasyprint import HTML, CSS
            self._HTML = HTML
            self._CSS  = CSS
            self.available = True
        except ImportError:
            self.available = False
            logger.warning("WeasyPrint not installed — PDF export disabled. Run: pip install weasyprint")

    # ── public ──────────────────────────────────────────────────────────────

    def html_to_pdf(self, html_path: str) -> str | None:
        """Convert an HTML report file to PDF. Returns PDF path or None."""
        if not self.available:
            return None
        html_path = Path(html_path)
        if not html_path.exists():
            logger.error(f"HTML file not found: {html_path}")
            return None
        pdf_path = html_path.with_suffix('.pdf')
        try:
            self._HTML(filename=str(html_path)).write_pdf(
                str(pdf_path),
                stylesheets=[self._CSS(string=self._print_css())]
            )
            logger.info(f"PDF saved: {pdf_path}")
            return str(pdf_path)
        except Exception as e:
            logger.error(f"PDF export failed: {e}")
            return None

    def export_scan(self, paths: dict) -> str | None:
        """Given a report paths dict (with 'html' key), export PDF and return path."""
        html = paths.get('html')
        if not html:
            return None
        return self.html_to_pdf(html)

    # ── private ─────────────────────────────────────────────────────────────

    def _print_css(self) -> str:
        """Extra CSS to make dark-theme HTML print cleanly as PDF."""
        return """
        @page {
            size: A4;
            margin: 15mm 12mm;
        }
        body {
            background: #0d1117 !important;
            color: #c9d1d9 !important;
            font-size: 11px;
        }
        h1 { font-size: 18px; }
        h2 { font-size: 14px; page-break-after: avoid; }
        table { page-break-inside: avoid; }
        .card { page-break-inside: avoid; }
        a { color: #58a6ff !important; }
        """
