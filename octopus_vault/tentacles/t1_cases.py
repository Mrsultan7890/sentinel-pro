from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QDialog, QFormLayout, QLineEdit, QTextEdit,
    QComboBox, QLabel, QMessageBox, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from core.database import get_connection
from core.models import Case

class CaseDialog(QDialog):
    def __init__(self, parent=None, case=None):
        super().__init__(parent)
        self.case = case
        self.setWindowTitle("New Case" if not case else "Edit Case")
        self.setMinimumWidth(400)
        self._build_ui()
        if case:
            self._populate(case)

    def _build_ui(self):
        layout = QFormLayout(self)
        self.title_input = QLineEdit()
        self.desc_input = QTextEdit()
        self.desc_input.setMaximumHeight(80)
        self.status_input = QComboBox()
        self.status_input.addItems(["Active", "Pending", "Closed"])

        layout.addRow("Title *", self.title_input)
        layout.addRow("Description", self.desc_input)
        layout.addRow("Status", self.status_input)

        btns = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary_btn")
        save_btn.clicked.connect(self._save)
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        layout.addRow(btns)

    def _populate(self, case):
        self.title_input.setText(case["title"])
        self.desc_input.setText(case["description"] or "")
        idx = self.status_input.findText(case["status"])
        if idx >= 0:
            self.status_input.setCurrentIndex(idx)

    def _save(self):
        if not self.title_input.text().strip():
            QMessageBox.warning(self, "Error", "Title is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "title": self.title_input.text().strip(),
            "description": self.desc_input.toPlainText().strip(),
            "status": self.status_input.currentText()
        }


class CasesWidget(QWidget):
    case_selected = pyqtSignal(int, str)

    def __init__(self):
        super().__init__()
        self._build_ui()
        self.load_cases()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("> CASE MANAGER")
        title.setObjectName("section_title")

        # Search + buttons row
        top_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setObjectName("search_bar")
        self.search_input.setPlaceholderText("[ SEARCH CASES... ]")
        self.search_input.textChanged.connect(self._filter_cases)
        top_row.addWidget(self.search_input)

        btn_row = QHBoxLayout()
        new_btn = QPushButton("[+] NEW CASE")
        edit_btn = QPushButton("EDIT")
        edit_btn.setObjectName("secondary_btn")
        delete_btn = QPushButton("DELETE")
        delete_btn.setObjectName("danger_btn")
        new_btn.clicked.connect(self._new_case)
        edit_btn.clicked.connect(self._edit_case)
        delete_btn.clicked.connect(self._delete_case)
        btn_row.addWidget(new_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addStretch()

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "TITLE", "STATUS", "CREATED"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(self._open_case)

        layout.addWidget(title)
        layout.addLayout(top_row)
        layout.addLayout(btn_row)
        layout.addWidget(self.table)

    def load_cases(self, filter_text=""):
        conn = get_connection()
        if filter_text:
            cases = conn.execute(
                "SELECT * FROM cases WHERE title LIKE ? OR description LIKE ? ORDER BY updated_at DESC",
                (f"%{filter_text}%", f"%{filter_text}%")
            ).fetchall()
        else:
            cases = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
        conn.close()
        self.table.setRowCount(0)
        for row, case in enumerate(cases):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f"#{case['id']:04d}"))
            self.table.setItem(row, 1, QTableWidgetItem(case["title"]))
            status_item = QTableWidgetItem(case["status"])
            if case["status"] == "Active":
                status_item.setForeground(QColor("#00FF41"))
            elif case["status"] == "Closed":
                status_item.setForeground(QColor("#005500"))
            else:
                status_item.setForeground(QColor("#FFAA00"))
            self.table.setItem(row, 2, status_item)
            self.table.setItem(row, 3, QTableWidgetItem(str(case["created_at"])[:10]))

    def _filter_cases(self, text):
        self.load_cases(text)

    def _new_case(self):
        dlg = CaseDialog(self)
        if dlg.exec():
            data = dlg.get_data()
            conn = get_connection()
            conn.execute("INSERT INTO cases (title, description, status) VALUES (?,?,?)",
                         (data["title"], data["description"], data["status"]))
            conn.commit()
            conn.close()
            self.load_cases()

    def _edit_case(self):
        row = self.table.currentRow()
        if row < 0:
            return
        case_id = int(self.table.item(row, 0).text())
        conn = get_connection()
        case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        conn.close()
        dlg = CaseDialog(self, case)
        if dlg.exec():
            data = dlg.get_data()
            conn = get_connection()
            conn.execute("UPDATE cases SET title=?, description=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (data["title"], data["description"], data["status"], case_id))
            conn.commit()
            conn.close()
            self.load_cases()

    def _delete_case(self):
        row = self.table.currentRow()
        if row < 0:
            return
        case_id = int(self.table.item(row, 0).text())
        title = self.table.item(row, 1).text()
        reply = QMessageBox.question(self, "Delete Case",
                                     f"Delete '{title}' and all its data?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
            conn.commit()
            conn.close()
            self.load_cases()

    def _open_case(self):
        row = self.table.currentRow()
        if row < 0:
            return
        case_id = int(self.table.item(row, 0).text())
        title = self.table.item(row, 1).text()
        self.case_selected.emit(case_id, title)
