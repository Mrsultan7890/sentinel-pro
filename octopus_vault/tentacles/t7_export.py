from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QMessageBox, QFileDialog, QComboBox
)
from pathlib import Path
from datetime import datetime
from core.database import get_connection

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

import json
import csv

EXPORTS_DIR = Path.home() / ".octopus_vault" / "exports"
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ExportWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self.case_title = ""
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        self.title_lbl = QLabel("📤  Export Engine")
        self.title_lbl.setObjectName("section_title")

        info = QLabel("Select a case from Cases tab, then export below.")
        info.setObjectName("subtitle")

        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(300)
        self._load_cases()

        btn_row = QHBoxLayout()
        pdf_btn = QPushButton("Export PDF Report")
        json_btn = QPushButton("Export JSON")
        json_btn.setObjectName("secondary_btn")
        csv_btn = QPushButton("Export CSV")
        csv_btn.setObjectName("secondary_btn")
        pdf_btn.clicked.connect(self._export_pdf)
        json_btn.clicked.connect(self._export_json)
        csv_btn.clicked.connect(self._export_csv)
        btn_row.addWidget(pdf_btn)
        btn_row.addWidget(json_btn)
        btn_row.addWidget(csv_btn)
        btn_row.addStretch()

        layout.addWidget(self.title_lbl)
        layout.addWidget(info)
        layout.addSpacing(16)
        layout.addWidget(QLabel("Select Case:"))
        layout.addWidget(self.case_combo)
        layout.addSpacing(16)
        layout.addLayout(btn_row)
        layout.addStretch()

    def _load_cases(self):
        self.case_combo.clear()
        conn = get_connection()
        cases = conn.execute("SELECT id, title FROM cases ORDER BY title").fetchall()
        conn.close()
        for c in cases:
            self.case_combo.addItem(c["title"], c["id"])

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.case_title = case_title
        for i in range(self.case_combo.count()):
            if self.case_combo.itemData(i) == case_id:
                self.case_combo.setCurrentIndex(i)
                break

    def _get_selected_case(self):
        idx = self.case_combo.currentIndex()
        if idx < 0:
            return None, ""
        return self.case_combo.itemData(idx), self.case_combo.currentText()

    def _collect_data(self, case_id):
        conn = get_connection()
        case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        subjects = conn.execute("SELECT * FROM subjects WHERE case_id=?", (case_id,)).fetchall()
        evidence = conn.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,)).fetchall()
        timeline = conn.execute("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_date", (case_id,)).fetchall()
        notes = conn.execute("SELECT * FROM notes WHERE case_id=?", (case_id,)).fetchall()
        conn.close()
        return dict(case), [dict(s) for s in subjects], [dict(e) for e in evidence], \
               [dict(t) for t in timeline], [dict(n) for n in notes]

    def _export_json(self):
        case_id, title = self._get_selected_case()
        if not case_id:
            QMessageBox.warning(self, "Error", "No case selected.")
            return
        case, subjects, evidence, timeline, notes = self._collect_data(case_id)
        data = {"case": case, "subjects": subjects, "evidence": evidence,
                "timeline": timeline, "notes": notes}
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", str(EXPORTS_DIR / f"{title}.json"), "JSON (*.json)")
        if path:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            QMessageBox.information(self, "Done", f"Exported to {path}")

    def _export_csv(self):
        case_id, title = self._get_selected_case()
        if not case_id:
            QMessageBox.warning(self, "Error", "No case selected.")
            return
        _, subjects, evidence, timeline, _ = self._collect_data(case_id)
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", str(EXPORTS_DIR / f"{title}_subjects.csv"), "CSV (*.csv)")
        if path:
            with open(path, "w", newline="") as f:
                if subjects:
                    writer = csv.DictWriter(f, fieldnames=subjects[0].keys())
                    writer.writeheader()
                    writer.writerows(subjects)
            QMessageBox.information(self, "Done", f"Subjects exported to {path}")

    def _export_pdf(self):
        if not REPORTLAB_AVAILABLE:
            QMessageBox.warning(self, "Missing Library", "Install reportlab: pip install reportlab")
            return
        case_id, title = self._get_selected_case()
        if not case_id:
            QMessageBox.warning(self, "Error", "No case selected.")
            return
        case, subjects, evidence, timeline, notes = self._collect_data(case_id)
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF", str(EXPORTS_DIR / f"{title}.pdf"), "PDF (*.pdf)")
        if not path:
            return

        doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("title", fontSize=20, textColor=colors.HexColor("#E94560"),
                                     spaceAfter=6, fontName="Helvetica-Bold")
        h2_style = ParagraphStyle("h2", fontSize=14, textColor=colors.HexColor("#00B4D8"),
                                  spaceBefore=12, spaceAfter=4, fontName="Helvetica-Bold")
        body_style = styles["Normal"]

        story.append(Paragraph("🐙 OCTOPUS-VAULT — Investigation Report", title_style))
        story.append(Paragraph(f"Case: {case['title']}", h2_style))
        story.append(Paragraph(f"Status: {case['status']}  |  Created: {str(case['created_at'])[:10]}", body_style))
        if case.get("description"):
            story.append(Paragraph(case["description"], body_style))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#E94560")))

        if subjects:
            story.append(Paragraph("Subjects", h2_style))
            for s in subjects:
                story.append(Paragraph(f"<b>{s['name']}</b>", body_style))
                for field in ["aliases", "emails", "phones", "usernames", "addresses"]:
                    if s.get(field):
                        story.append(Paragraph(f"  {field.capitalize()}: {s[field]}", body_style))
                story.append(Spacer(1, 6))

        if evidence:
            story.append(Paragraph("Evidence", h2_style))
            tdata = [["Type", "Title", "Source", "Date"]]
            for e in evidence:
                tdata.append([e["type"], e["title"] or "", e["source"] or "", str(e["created_at"])[:10]])
            t = Table(tdata, colWidths=[3*cm, 7*cm, 4*cm, 3*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E94560")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#16213E"), colors.HexColor("#1A1A2E")]),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#EAEAEA")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#0F3460")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

        if timeline:
            story.append(Paragraph("Timeline", h2_style))
            for ev in timeline:
                story.append(Paragraph(f"<b>{ev['event_date']}</b> — {ev['title']}", body_style))
                if ev.get("description"):
                    story.append(Paragraph(f"  {ev['description']}", body_style))

        if notes:
            story.append(Paragraph("Notes", h2_style))
            for n in notes:
                story.append(Paragraph(f"<b>{n['title'] or 'Untitled'}</b>", body_style))
                story.append(Paragraph(n["content"] or "", body_style))
                story.append(Spacer(1, 6))

        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", body_style))

        doc.build(story)
        QMessageBox.information(self, "Done", f"PDF exported to {path}")
