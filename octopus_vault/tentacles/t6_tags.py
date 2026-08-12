from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QDialog, QFormLayout, QLineEdit,
    QLabel, QMessageBox, QColorDialog, QHeaderView
)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt
from core.database import get_connection

class TagDialog(QDialog):
    def __init__(self, parent=None, tag=None):
        super().__init__(parent)
        self.color = tag["color"] if tag else "#E94560"
        self.setWindowTitle("New Tag" if not tag else "Edit Tag")
        self.setMinimumWidth(320)
        self._build_ui()
        if tag:
            self.name_input.setText(tag["name"])

    def _build_ui(self):
        layout = QFormLayout(self)
        self.name_input = QLineEdit()

        color_row = QHBoxLayout()
        self.color_preview = QLabel("  ")
        self.color_preview.setFixedSize(32, 24)
        self._update_color_preview()
        pick_btn = QPushButton("Pick Color")
        pick_btn.setObjectName("secondary_btn")
        pick_btn.clicked.connect(self._pick_color)
        color_row.addWidget(self.color_preview)
        color_row.addWidget(pick_btn)
        color_row.addStretch()

        layout.addRow("Tag Name *", self.name_input)
        layout.addRow("Color", color_row)

        btns = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary_btn")
        save_btn.clicked.connect(self._save)
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        layout.addRow(btns)

    def _update_color_preview(self):
        self.color_preview.setStyleSheet(f"background-color: {self.color}; border-radius: 4px;")

    def _pick_color(self):
        color = QColorDialog.getColor(QColor(self.color), self)
        if color.isValid():
            self.color = color.name()
            self._update_color_preview()

    def _save(self):
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Error", "Tag name is required.")
            return
        self.accept()

    def get_data(self):
        return {"name": self.name_input.text().strip(), "color": self.color}


class TagsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()
        self.load_tags()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("> TAG SYSTEM")
        title.setObjectName("section_title")

        btn_row = QHBoxLayout()
        new_btn = QPushButton("[+] NEW TAG")
        edit_btn = QPushButton("EDIT")
        edit_btn.setObjectName("secondary_btn")
        delete_btn = QPushButton("DELETE")
        delete_btn.setObjectName("danger_btn")
        new_btn.clicked.connect(self._new_tag)
        edit_btn.clicked.connect(self._edit_tag)
        delete_btn.clicked.connect(self._delete_tag)
        btn_row.addWidget(new_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addStretch()

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["ID", "Tag Name", "Color"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        layout.addWidget(title)
        layout.addLayout(btn_row)
        layout.addWidget(self.table)

    def load_tags(self):
        conn = get_connection()
        rows = conn.execute("SELECT * FROM tags ORDER BY name").fetchall()
        conn.close()
        self.table.setRowCount(0)
        for i, t in enumerate(rows):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(str(t["id"])))
            self.table.setItem(i, 1, QTableWidgetItem(t["name"]))
            color_item = QTableWidgetItem(t["color"])
            color_item.setBackground(QColor(t["color"]))
            self.table.setItem(i, 2, color_item)

    def _new_tag(self):
        dlg = TagDialog(self)
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            try:
                conn.execute("INSERT INTO tags (name, color) VALUES (?,?)", (d["name"], d["color"]))
                conn.commit()
            except Exception:
                QMessageBox.warning(self, "Error", "Tag name already exists.")
            conn.close()
            self.load_tags()

    def _edit_tag(self):
        row = self.table.currentRow()
        if row < 0:
            return
        tid = int(self.table.item(row, 0).text())
        conn = get_connection()
        t = conn.execute("SELECT * FROM tags WHERE id=?", (tid,)).fetchone()
        conn.close()
        dlg = TagDialog(self, t)
        if dlg.exec():
            d = dlg.get_data()
            conn = get_connection()
            conn.execute("UPDATE tags SET name=?, color=? WHERE id=?", (d["name"], d["color"], tid))
            conn.commit()
            conn.close()
            self.load_tags()

    def _delete_tag(self):
        row = self.table.currentRow()
        if row < 0:
            return
        tid = int(self.table.item(row, 0).text())
        reply = QMessageBox.question(self, "Delete", "Delete this tag?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            conn.execute("DELETE FROM tags WHERE id=?", (tid,))
            conn.commit()
            conn.close()
            self.load_tags()
