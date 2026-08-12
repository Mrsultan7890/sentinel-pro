from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox
)
from PyQt6.QtGui import QColor
from core.database import get_connection


class DuplicateDetectorWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self.title_lbl = QLabel("> DUPLICATE DETECTOR")
        self.title_lbl.setObjectName("section_title")

        info = QLabel("// Scans subjects for shared emails, usernames, phones across cases")
        info.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 10px;")

        ctrl_row = QHBoxLayout()
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(["THIS CASE ONLY", "ALL CASES"])
        scan_btn = QPushButton("[ SCAN FOR DUPLICATES ]")
        scan_btn.clicked.connect(self._scan)
        ctrl_row.addWidget(QLabel("SCOPE:"))
        ctrl_row.addWidget(self.scope_combo)
        ctrl_row.addSpacing(16)
        ctrl_row.addWidget(scan_btn)
        ctrl_row.addStretch()

        self.result_lbl = QLabel("")
        self.result_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["FIELD", "VALUE", "SUBJECT 1", "SUBJECT 2", "CASE"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.title_lbl)
        layout.addWidget(info)
        layout.addLayout(ctrl_row)
        layout.addWidget(self.result_lbl)
        layout.addWidget(self.table)

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> DUPLICATE DETECTOR  //  {case_title.upper()}")

    def _scan(self):
        scope_all = self.scope_combo.currentText() == "ALL CASES"
        conn = get_connection()

        if scope_all:
            subjects = conn.execute(
                "SELECT s.*, c.title as case_title FROM subjects s JOIN cases c ON s.case_id=c.id"
            ).fetchall()
        else:
            if not self.case_id:
                self.result_lbl.setText("// SELECT A CASE FIRST")
                conn.close()
                return
            subjects = conn.execute(
                "SELECT s.*, c.title as case_title FROM subjects s JOIN cases c ON s.case_id=c.id WHERE s.case_id=?",
                (self.case_id,)
            ).fetchall()
        conn.close()

        duplicates = []
        fields = ["emails", "usernames", "phones"]

        for field in fields:
            value_map = {}
            for s in subjects:
                for val in (s[field] or "").split(","):
                    v = val.strip().lower()
                    if v:
                        value_map.setdefault(v, []).append(s)

            for val, matches in value_map.items():
                if len(matches) > 1:
                    for i in range(len(matches)):
                        for j in range(i + 1, len(matches)):
                            duplicates.append({
                                "field": field.upper(),
                                "value": val,
                                "subject1": matches[i]["name"],
                                "subject2": matches[j]["name"],
                                "case": matches[i]["case_title"]
                                        if matches[i]["case_title"] == matches[j]["case_title"]
                                        else f"{matches[i]['case_title']} / {matches[j]['case_title']}"
                            })

        self.table.setRowCount(0)
        for i, d in enumerate(duplicates):
            self.table.insertRow(i)
            field_item = QTableWidgetItem(d["field"])
            field_item.setForeground(QColor("#FF3333"))
            self.table.setItem(i, 0, field_item)
            self.table.setItem(i, 1, QTableWidgetItem(d["value"]))
            self.table.setItem(i, 2, QTableWidgetItem(d["subject1"]))
            self.table.setItem(i, 3, QTableWidgetItem(d["subject2"]))
            self.table.setItem(i, 4, QTableWidgetItem(d["case"]))

        count = len(duplicates)
        if count == 0:
            self.result_lbl.setStyleSheet("color: #00FF41; font-family: 'Courier New'; font-size: 11px;")
            self.result_lbl.setText("// SCAN COMPLETE — NO DUPLICATES FOUND")
        else:
            self.result_lbl.setStyleSheet("color: #FF3333; font-family: 'Courier New'; font-size: 11px;")
            self.result_lbl.setText(f"// WARNING: {count} DUPLICATE(S) DETECTED")
