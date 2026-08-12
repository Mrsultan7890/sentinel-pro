from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QDialog, QFormLayout, QLineEdit, QTextEdit,
    QLabel, QMessageBox, QHeaderView
)
from PyQt6.QtCore import Qt
from core.database import get_connection

class SubjectDialog(QDialog):
    def __init__(self, parent=None, subject=None):
        super().__init__(parent)
        self.setWindowTitle("New Subject" if not subject else "Edit Subject")
        self.setMinimumWidth(450)
        self._build_ui()
        if subject:
            self._populate(subject)

    def _build_ui(self):
        layout = QFormLayout(self)
        self.name = QLineEdit()
        self.aliases = QLineEdit()
        self.aliases.setPlaceholderText("comma separated")
        self.emails = QLineEdit()
        self.emails.setPlaceholderText("comma separated")
        self.phones = QLineEdit()
        self.phones.setPlaceholderText("comma separated")
        self.usernames = QLineEdit()
        self.usernames.setPlaceholderText("comma separated")
        self.addresses = QTextEdit()
        self.addresses.setMaximumHeight(60)
        self.notes = QTextEdit()
        self.notes.setMaximumHeight(80)

        layout.addRow("Name *", self.name)
        layout.addRow("Aliases", self.aliases)
        layout.addRow("Emails", self.emails)
        layout.addRow("Phones", self.phones)
        layout.addRow("Usernames", self.usernames)
        layout.addRow("Addresses", self.addresses)
        layout.addRow("Notes", self.notes)

        btns = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary_btn")
        save_btn.clicked.connect(self._save)
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        layout.addRow(btns)

    def _populate(self, s):
        self.name.setText(s["name"])
        self.aliases.setText(s["aliases"] or "")
        self.emails.setText(s["emails"] or "")
        self.phones.setText(s["phones"] or "")
        self.usernames.setText(s["usernames"] or "")
        self.addresses.setText(s["addresses"] or "")
        self.notes.setText(s["notes"] or "")

    def _save(self):
        if not self.name.text().strip():
            QMessageBox.warning(self, "Error", "Name is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "name": self.name.text().strip(),
            "aliases": self.aliases.text().strip(),
            "emails": self.emails.text().strip(),
            "phones": self.phones.text().strip(),
            "usernames": self.usernames.text().strip(),
            "addresses": self.addresses.toPlainText().strip(),
            "notes": self.notes.toPlainText().strip()
        }


class SubjectsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        self.title_lbl = QLabel("> SUBJECT PROFILES")
        self.title_lbl.setObjectName("section_title")

        btn_row = QHBoxLayout()
        self.new_btn = QPushButton("[+] ADD SUBJECT")
        edit_btn = QPushButton("EDIT")
        edit_btn.setObjectName("secondary_btn")
        delete_btn = QPushButton("DELETE")
        delete_btn.setObjectName("danger_btn")
        self.new_btn.clicked.connect(self._new_subject)
        edit_btn.clicked.connect(self._edit_subject)
        delete_btn.clicked.connect(self._delete_subject)
        btn_row.addWidget(self.new_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addStretch()

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "NAME", "EMAILS", "USERNAMES", "PHONES"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.title_lbl)
        layout.addLayout(btn_row)
        layout.addWidget(self.table)

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> SUBJECTS  //  {case_title.upper()}")
        self.load_subjects()

    def load_subjects(self):
        if not self.case_id:
            return
        conn = get_connection()
        rows = conn.execute("SELECT * FROM subjects WHERE case_id=? ORDER BY name", (self.case_id,)).fetchall()
        conn.close()
        self.table.setRowCount(0)
        for i, s in enumerate(rows):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(f"#{s['id']:04d}"))
            self.table.setItem(i, 1, QTableWidgetItem(s["name"]))
            self.table.setItem(i, 2, QTableWidgetItem(s["emails"] or ""))
            self.table.setItem(i, 3, QTableWidgetItem(s["usernames"] or ""))
            self.table.setItem(i, 4, QTableWidgetItem(s["phones"] or ""))

    def _new_subject(self):
        if not self.case_id:
            QMessageBox.information(self, "Info", "Select a case first.")
            return
        dlg = SubjectDialog(self)
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute("""INSERT INTO subjects (case_id,name,aliases,emails,phones,usernames,addresses,notes)
                            VALUES (?,?,?,?,?,?,?,?)""",
                         (self.case_id, d["name"], d["aliases"], d["emails"],
                          d["phones"], d["usernames"], d["addresses"], d["notes"]))
            conn.commit()
            conn.close()
            self.load_subjects()

    def _edit_subject(self):
        row = self.table.currentRow()
        if row < 0:
            return
        sid = int(self.table.item(row, 0).text().replace("#", ""))
        conn = get_connection()
        s = conn.execute("SELECT * FROM subjects WHERE id=?", (sid,)).fetchone()
        conn.close()
        dlg = SubjectDialog(self, s)
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute("""UPDATE subjects SET name=?,aliases=?,emails=?,phones=?,usernames=?,addresses=?,notes=?
                            WHERE id=?""",
                         (d["name"], d["aliases"], d["emails"], d["phones"],
                          d["usernames"], d["addresses"], d["notes"], sid))
            conn.commit()
            conn.close()
            self.load_subjects()

    def _delete_subject(self):
        row = self.table.currentRow()
        if row < 0:
            return
        sid = int(self.table.item(row, 0).text().replace("#", ""))
        name = self.table.item(row, 1).text()
        reply = QMessageBox.question(self, "Delete", f"Delete subject '{name}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            conn.execute("DELETE FROM subjects WHERE id=?", (sid,))
            conn.commit()
            conn.close()
            self.load_subjects()
