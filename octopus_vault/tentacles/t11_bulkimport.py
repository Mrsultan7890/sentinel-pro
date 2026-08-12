import csv
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QComboBox
)
from PyQt6.QtGui import QColor
from core.database import get_connection

EXPECTED_COLS = ["name", "aliases", "emails", "phones", "usernames", "addresses", "notes"]


class BulkImportWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self._rows = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self.title_lbl = QLabel("> BULK IMPORT")
        self.title_lbl.setObjectName("section_title")

        info = QLabel(
            "// CSV format: name, aliases, emails, phones, usernames, addresses, notes\n"
            "// Only 'name' column is required. Others are optional."
        )
        info.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 10px;")

        ctrl_row = QHBoxLayout()
        self.case_combo = QComboBox()
        self._load_cases()
        load_btn = QPushButton("[ LOAD CSV FILE ]")
        load_btn.setObjectName("secondary_btn")
        self.import_btn = QPushButton("[ IMPORT ALL ]")
        self.import_btn.setEnabled(False)
        load_btn.clicked.connect(self._load_csv)
        self.import_btn.clicked.connect(self._do_import)
        ctrl_row.addWidget(QLabel("TARGET CASE:"))
        ctrl_row.addWidget(self.case_combo)
        ctrl_row.addSpacing(16)
        ctrl_row.addWidget(load_btn)
        ctrl_row.addWidget(self.import_btn)
        ctrl_row.addStretch()

        self.status_lbl = QLabel("// LOAD A CSV FILE TO PREVIEW")
        self.status_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([c.upper() for c in EXPECTED_COLS])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.title_lbl)
        layout.addWidget(info)
        layout.addLayout(ctrl_row)
        layout.addWidget(self.status_lbl)
        layout.addWidget(self.table)

    def _load_cases(self):
        conn = get_connection()
        cases = conn.execute("SELECT id, title FROM cases ORDER BY title").fetchall()
        conn.close()
        self.case_combo.clear()
        for c in cases:
            self.case_combo.addItem(c["title"], c["id"])

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> BULK IMPORT  //  {case_title.upper()}")
        self._load_cases()
        for i in range(self.case_combo.count()):
            if self.case_combo.itemData(i) == case_id:
                self.case_combo.setCurrentIndex(i)
                break

    def _load_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        self._rows = []
        self.table.setRowCount(0)
        errors = 0
        try:
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = row.get("name", "").strip()
                    if not name:
                        errors += 1
                        continue
                    self._rows.append({
                        "name":      name,
                        "aliases":   row.get("aliases", "").strip(),
                        "emails":    row.get("emails", "").strip(),
                        "phones":    row.get("phones", "").strip(),
                        "usernames": row.get("usernames", "").strip(),
                        "addresses": row.get("addresses", "").strip(),
                        "notes":     row.get("notes", "").strip(),
                    })
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to read CSV:\n{e}")
            return

        for i, r in enumerate(self._rows):
            self.table.insertRow(i)
            for j, col in enumerate(EXPECTED_COLS):
                item = QTableWidgetItem(r[col])
                if col == "name":
                    item.setForeground(QColor("#00FF41"))
                self.table.setItem(i, j, item)

        msg = f"// LOADED {len(self._rows)} ROWS"
        if errors:
            msg += f"  |  {errors} SKIPPED (no name)"
        self.status_lbl.setText(msg)
        self.import_btn.setEnabled(bool(self._rows))

    def _do_import(self):
        case_id = self.case_combo.currentData()
        if not case_id:
            QMessageBox.warning(self, "Error", "Select a target case.")
            return
        if not self._rows:
            return
        conn = get_connection()
        count = 0
        for r in self._rows:
            conn.execute(
                "INSERT INTO subjects (case_id,name,aliases,emails,phones,usernames,addresses,notes) VALUES (?,?,?,?,?,?,?,?)",
                (case_id, r["name"], r["aliases"], r["emails"],
                 r["phones"], r["usernames"], r["addresses"], r["notes"])
            )
            count += 1
        conn.commit()
        conn.close()
        self.status_lbl.setStyleSheet("color: #00FF41; font-family: 'Courier New'; font-size: 11px;")
        self.status_lbl.setText(f"// IMPORT COMPLETE — {count} SUBJECTS ADDED")
        self._rows = []
        self.table.setRowCount(0)
        self.import_btn.setEnabled(False)
