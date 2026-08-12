from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QDialog, QFormLayout, QLineEdit, QTextEdit,
    QComboBox, QLabel, QMessageBox, QHeaderView, QFileDialog, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtCore import QUrl
import shutil, subprocess, sys
from pathlib import Path
from core.database import get_connection

EVIDENCE_DIR = Path.home() / ".octopus_vault" / "evidence_files"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

EVIDENCE_TYPES = ["URL", "Screenshot", "Document", "Note",
                  "IP Address", "Email", "Username", "Phone", "Other"]


class EvidenceDialog(QDialog):
    def __init__(self, parent=None, evidence=None, subjects=None):
        super().__init__(parent)
        self.subjects = subjects or []
        self.file_path = ""
        self.setWindowTitle("ADD EVIDENCE" if not evidence else "EDIT EVIDENCE")
        self.setMinimumWidth(500)
        self._build_ui()
        if evidence:
            self._populate(evidence)

    def _build_ui(self):
        layout = QFormLayout(self)
        self.type_input = QComboBox()
        self.type_input.addItems(EVIDENCE_TYPES)
        self.title_input = QLineEdit()
        self.content_input = QTextEdit()
        self.content_input.setMaximumHeight(100)
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("e.g. Twitter, LinkedIn, Shodan")
        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("comma separated")
        self.subject_combo = QComboBox()
        self.subject_combo.addItem("-- None --", None)
        for s in self.subjects:
            self.subject_combo.addItem(s["name"], s["id"])

        file_row = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")
        attach_btn = QPushButton("ATTACH FILE")
        attach_btn.setObjectName("secondary_btn")
        attach_btn.clicked.connect(self._attach_file)
        file_row.addWidget(self.file_label)
        file_row.addWidget(attach_btn)

        layout.addRow("TYPE", self.type_input)
        layout.addRow("TITLE", self.title_input)
        layout.addRow("CONTENT / VALUE", self.content_input)
        layout.addRow("SOURCE", self.source_input)
        layout.addRow("TAGS", self.tags_input)
        layout.addRow("SUBJECT", self.subject_combo)
        layout.addRow("FILE", file_row)

        btns = QHBoxLayout()
        save_btn = QPushButton("SAVE")
        cancel_btn = QPushButton("CANCEL")
        cancel_btn.setObjectName("secondary_btn")
        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        layout.addRow(btns)

    def _attach_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.file_path = path
            self.file_label.setText(Path(path).name)

    def _populate(self, e):
        idx = self.type_input.findText(e["type"])
        if idx >= 0:
            self.type_input.setCurrentIndex(idx)
        self.title_input.setText(e["title"] or "")
        self.content_input.setText(e["content"] or "")
        self.source_input.setText(e["source"] or "")
        self.tags_input.setText(e["tags"] or "")
        if e["file_path"]:
            self.file_label.setText(Path(e["file_path"]).name)
            self.file_path = e["file_path"]
        # restore linked subject
        if e["subject_id"]:
            for i in range(self.subject_combo.count()):
                if self.subject_combo.itemData(i) == e["subject_id"]:
                    self.subject_combo.setCurrentIndex(i)
                    break

    def get_data(self):
        saved_path = ""
        if self.file_path:
            dest = EVIDENCE_DIR / Path(self.file_path).name
            if Path(self.file_path) != dest:
                shutil.copy2(self.file_path, dest)
            saved_path = str(dest)
        return {
            "type":       self.type_input.currentText(),
            "title":      self.title_input.text().strip(),
            "content":    self.content_input.toPlainText().strip(),
            "source":     self.source_input.text().strip(),
            "tags":       self.tags_input.text().strip(),
            "subject_id": self.subject_combo.currentData(),
            "file_path":  saved_path
        }


class EvidenceWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        self.title_lbl = QLabel("> EVIDENCE LOCKER")
        self.title_lbl.setObjectName("section_title")

        top_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setObjectName("search_bar")
        self.search_input.setPlaceholderText("[ SEARCH EVIDENCE... ]")
        self.search_input.textChanged.connect(self._filter_evidence)
        top_row.addWidget(self.search_input)

        btn_row = QHBoxLayout()
        new_btn    = QPushButton("[+] ADD EVIDENCE")
        edit_btn   = QPushButton("EDIT")
        edit_btn.setObjectName("secondary_btn")
        delete_btn = QPushButton("DELETE")
        delete_btn.setObjectName("danger_btn")
        open_btn   = QPushButton("OPEN FILE")
        open_btn.setObjectName("secondary_btn")
        new_btn.clicked.connect(self._new_evidence)
        edit_btn.clicked.connect(self._edit_evidence)
        delete_btn.clicked.connect(self._delete_evidence)
        open_btn.clicked.connect(self._open_file)
        btn_row.addWidget(new_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addWidget(open_btn)
        btn_row.addStretch()

        # ── Two panel: table + preview ──
        body = QHBoxLayout()
        body.setSpacing(12)

        # Left: table
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "TYPE", "TITLE", "SOURCE", "DATE"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.currentItemChanged.connect(self._show_preview)
        left_layout.addWidget(self.table)

        # Right: preview panel
        right = QFrame()
        right.setObjectName("dash_card")
        right.setFixedWidth(280)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(8)

        prev_hdr = QLabel("> PREVIEW")
        prev_hdr.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 10px;")

        self.prev_type  = QLabel("")
        self.prev_type.setStyleSheet("color: #00FF41; font-family: 'Courier New'; font-size: 11px; font-weight: bold;")
        self.prev_title = QLabel("")
        self.prev_title.setStyleSheet("color: #008F11; font-family: 'Courier New'; font-size: 11px;")
        self.prev_title.setWordWrap(True)
        self.prev_source = QLabel("")
        self.prev_source.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 10px;")

        div = QLabel("─" * 30)
        div.setStyleSheet("color: #003300; font-family: 'Courier New'; font-size: 9px;")

        self.prev_content = QTextEdit()
        self.prev_content.setReadOnly(True)
        self.prev_content.setStyleSheet(
            "background: #0A0A0A; border: none; color: #00FF41;"
            "font-family: 'Courier New'; font-size: 11px;"
        )

        self.prev_file = QLabel("")
        self.prev_file.setStyleSheet("color: #0088FF; font-family: 'Courier New'; font-size: 10px;")
        self.prev_file.setWordWrap(True)

        self.prev_tags = QLabel("")
        self.prev_tags.setStyleSheet("color: #AA00FF; font-family: 'Courier New'; font-size: 10px;")
        self.prev_tags.setWordWrap(True)

        copy_btn = QPushButton("COPY CONTENT")
        copy_btn.setObjectName("secondary_btn")
        copy_btn.clicked.connect(self._copy_content)

        right_layout.addWidget(prev_hdr)
        right_layout.addWidget(self.prev_type)
        right_layout.addWidget(self.prev_title)
        right_layout.addWidget(self.prev_source)
        right_layout.addWidget(div)
        right_layout.addWidget(self.prev_content, stretch=1)
        right_layout.addWidget(self.prev_file)
        right_layout.addWidget(self.prev_tags)
        right_layout.addWidget(copy_btn)

        body.addWidget(left, stretch=1)
        body.addWidget(right)

        root.addWidget(self.title_lbl)
        root.addLayout(top_row)
        root.addLayout(btn_row)
        root.addLayout(body, stretch=1)

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> EVIDENCE  //  {case_title.upper()}")
        self.load_evidence()

    def load_evidence(self, filter_text=""):
        if not self.case_id:
            return
        conn = get_connection()
        if filter_text:
            rows = conn.execute(
                """SELECT * FROM evidence WHERE case_id=?
                   AND (title LIKE ? OR content LIKE ? OR source LIKE ? OR type LIKE ?)
                   ORDER BY created_at DESC""",
                (self.case_id, f"%{filter_text}%", f"%{filter_text}%",
                 f"%{filter_text}%", f"%{filter_text}%")
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY created_at DESC", (self.case_id,)
            ).fetchall()
        conn.close()
        self.table.setRowCount(0)
        for i, e in enumerate(rows):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(f"#{e['id']:04d}"))
            self.table.setItem(i, 1, QTableWidgetItem(e["type"]))
            self.table.setItem(i, 2, QTableWidgetItem(e["title"] or (e["content"] or "")[:40]))
            self.table.setItem(i, 3, QTableWidgetItem(e["source"] or ""))
            self.table.setItem(i, 4, QTableWidgetItem(str(e["created_at"])[:10]))

    def _filter_evidence(self, text):
        self.load_evidence(text)

    def _show_preview(self, current, _):
        if not current:
            self._current_evidence = None
            return
        row = current.row()
        raw_id = self.table.item(row, 0)
        if not raw_id:
            return
        eid = int(raw_id.text().replace("#", ""))
        conn = get_connection()
        e = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        conn.close()
        if not e:
            self._current_evidence = None
            return
        self.prev_type.setText(f"[ {e['type']} ]")
        self.prev_title.setText(e["title"] or "")
        self.prev_source.setText(f"SRC: {e['source']}" if e["source"] else "")
        self.prev_content.setText(e["content"] or "")
        self.prev_file.setText(f"FILE: {Path(e['file_path']).name}" if e["file_path"] else "")
        self.prev_tags.setText(f"TAGS: {e['tags']}" if e["tags"] else "")
        self._current_evidence = dict(e)

    def _copy_content(self):
        from PyQt6.QtWidgets import QApplication
        e = getattr(self, "_current_evidence", None)
        if e:
            QApplication.clipboard().setText(e.get("content", ""))

    def _open_file(self):
        e = getattr(self, "_current_evidence", None)
        if not e or not e.get("file_path"):
            QMessageBox.information(self, "Info", "No file attached to this evidence.")
            return
        path = e["file_path"]
        if not Path(path).exists():
            QMessageBox.warning(self, "Error", "File not found.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _get_subjects(self):
        if not self.case_id:
            return []
        conn = get_connection()
        subjects = conn.execute("SELECT id, name FROM subjects WHERE case_id=?", (self.case_id,)).fetchall()
        conn.close()
        return subjects

    def _new_evidence(self):
        if not self.case_id:
            QMessageBox.information(self, "Info", "Select a case first.")
            return
        dlg = EvidenceDialog(self, subjects=self._get_subjects())
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute(
                "INSERT INTO evidence (case_id,subject_id,type,title,content,source,file_path,tags) VALUES (?,?,?,?,?,?,?,?)",
                (self.case_id, d["subject_id"], d["type"], d["title"],
                 d["content"], d["source"], d["file_path"], d["tags"])
            )
            conn.commit()
            conn.close()
            self.load_evidence()

    def _edit_evidence(self):
        row = self.table.currentRow()
        if row < 0:
            return
        eid = int(self.table.item(row, 0).text().replace("#", ""))
        conn = get_connection()
        e = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        conn.close()
        dlg = EvidenceDialog(self, evidence=e, subjects=self._get_subjects())
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute(
                "UPDATE evidence SET type=?,title=?,content=?,source=?,tags=?,subject_id=?,file_path=? WHERE id=?",
                (d["type"], d["title"], d["content"], d["source"], d["tags"], d["subject_id"], d["file_path"], eid)
            )
            conn.commit()
            conn.close()
            self.load_evidence()

    def _delete_evidence(self):
        row = self.table.currentRow()
        if row < 0:
            return
        eid = int(self.table.item(row, 0).text().replace("#", ""))
        reply = QMessageBox.question(self, "Delete", "Delete this evidence?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            conn.execute("DELETE FROM evidence WHERE id=?", (eid,))
            conn.commit()
            conn.close()
            self.load_evidence()
