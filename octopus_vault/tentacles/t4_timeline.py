from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QDialog, QFormLayout, QLineEdit, QTextEdit,
    QLabel, QMessageBox, QHeaderView, QDateEdit
)
from PyQt6.QtCore import Qt, QDate
from core.database import get_connection

class TimelineDialog(QDialog):
    def __init__(self, parent=None, event=None):
        super().__init__(parent)
        self.setWindowTitle("Add Event" if not event else "Edit Event")
        self.setMinimumWidth(420)
        self._build_ui()
        if event:
            self._populate(event)

    def _build_ui(self):
        layout = QFormLayout(self)
        self.title_input = QLineEdit()
        self.desc_input = QTextEdit()
        self.desc_input.setMaximumHeight(80)
        self.date_input = QDateEdit()
        self.date_input.setCalendarPopup(True)
        self.date_input.setDate(QDate.currentDate())

        layout.addRow("Event Title *", self.title_input)
        layout.addRow("Description", self.desc_input)
        layout.addRow("Date", self.date_input)

        btns = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary_btn")
        save_btn.clicked.connect(self._save)
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        layout.addRow(btns)

    def _populate(self, e):
        self.title_input.setText(e["title"])
        self.desc_input.setText(e["description"] or "")
        if e["event_date"]:
            self.date_input.setDate(QDate.fromString(e["event_date"], "yyyy-MM-dd"))

    def _save(self):
        if not self.title_input.text().strip():
            QMessageBox.warning(self, "Error", "Title is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "title": self.title_input.text().strip(),
            "description": self.desc_input.toPlainText().strip(),
            "event_date": self.date_input.date().toString("yyyy-MM-dd")
        }


class TimelineWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        self.title_lbl = QLabel("> TIMELINE")
        self.title_lbl.setObjectName("section_title")

        btn_row = QHBoxLayout()
        new_btn = QPushButton("[+] ADD EVENT")
        edit_btn = QPushButton("EDIT")
        edit_btn.setObjectName("secondary_btn")
        delete_btn = QPushButton("DELETE")
        delete_btn.setObjectName("danger_btn")
        new_btn.clicked.connect(self._new_event)
        edit_btn.clicked.connect(self._edit_event)
        delete_btn.clicked.connect(self._delete_event)
        btn_row.addWidget(new_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addStretch()

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "DATE", "EVENT", "DESCRIPTION"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.title_lbl)
        layout.addLayout(btn_row)
        layout.addWidget(self.table)

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> TIMELINE  //  {case_title.upper()}")
        self.load_events()

    def load_events(self):
        if not self.case_id:
            return
        conn = get_connection()
        rows = conn.execute("SELECT * FROM timeline_events WHERE case_id=? ORDER BY event_date ASC",
                            (self.case_id,)).fetchall()
        conn.close()
        self.table.setRowCount(0)
        for i, e in enumerate(rows):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(str(e["id"])))
            self.table.setItem(i, 1, QTableWidgetItem(e["event_date"] or ""))
            self.table.setItem(i, 2, QTableWidgetItem(e["title"]))
            self.table.setItem(i, 3, QTableWidgetItem(e["description"] or ""))

    def _new_event(self):
        if not self.case_id:
            QMessageBox.information(self, "Info", "Select a case first.")
            return
        dlg = TimelineDialog(self)
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute("INSERT INTO timeline_events (case_id,title,description,event_date) VALUES (?,?,?,?)",
                         (self.case_id, d["title"], d["description"], d["event_date"]))
            conn.commit()
            conn.close()
            self.load_events()

    def _edit_event(self):
        row = self.table.currentRow()
        if row < 0:
            return
        eid = int(self.table.item(row, 0).text())
        conn = get_connection()
        e = conn.execute("SELECT * FROM timeline_events WHERE id=?", (eid,)).fetchone()
        conn.close()
        dlg = TimelineDialog(self, e)
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute("UPDATE timeline_events SET title=?,description=?,event_date=? WHERE id=?",
                         (d["title"], d["description"], d["event_date"], eid))
            conn.commit()
            conn.close()
            self.load_events()

    def _delete_event(self):
        row = self.table.currentRow()
        if row < 0:
            return
        eid = int(self.table.item(row, 0).text())
        reply = QMessageBox.question(self, "Delete", "Delete this event?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            conn.execute("DELETE FROM timeline_events WHERE id=?", (eid,))
            conn.commit()
            conn.close()
            self.load_events()
