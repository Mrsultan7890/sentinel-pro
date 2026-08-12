from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget,
    QListWidgetItem, QLineEdit, QTextEdit, QLabel, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from core.database import get_connection


class NotesWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.case_id = None
        self.current_note_id = None
        self._autosave_timer = QTimer()
        self._autosave_timer.setInterval(30000)  # 30 seconds
        self._autosave_timer.timeout.connect(self._autosave)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # ── Header ──
        self.title_lbl = QLabel("> NOTES BOARD")
        self.title_lbl.setObjectName("section_title")

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        new_btn = QPushButton("[+] NEW NOTE")
        self.save_btn = QPushButton("SAVE")
        self.save_btn.setObjectName("secondary_btn")
        delete_btn = QPushButton("DELETE")
        delete_btn.setObjectName("danger_btn")
        new_btn.clicked.connect(self._new_note)
        self.save_btn.clicked.connect(self._save_note)
        delete_btn.clicked.connect(self._delete_note)
        self._autosave_timer.start()
        btn_row.addWidget(new_btn)
        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addStretch()

        # ── Two panel body ──
        body = QHBoxLayout()
        body.setSpacing(12)

        # Left panel — note list
        left = QFrame()
        left.setObjectName("dash_card")
        left.setFixedWidth(200)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        list_header = QLabel("  > NOTE LIST")
        list_header.setStyleSheet(
            "color: #005500; font-family: 'Courier New'; font-size: 10px;"
            "padding: 6px 8px; border-bottom: 1px solid #003300;"
        )

        self.note_list = QListWidget()
        self.note_list.setFrameShape(QFrame.Shape.NoFrame)
        self.note_list.currentItemChanged.connect(self._load_note_content)

        left_layout.addWidget(list_header)
        left_layout.addWidget(self.note_list)

        # Right panel — editor
        right = QFrame()
        right.setObjectName("dash_card")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(8)

        title_label = QLabel("> TITLE")
        title_label.setStyleSheet(
            "color: #005500; font-family: 'Courier New'; font-size: 10px;"
        )
        self.note_title = QLineEdit()
        self.note_title.setPlaceholderText("[ NOTE TITLE ]")

        content_label = QLabel("> CONTENT")
        content_label.setStyleSheet(
            "color: #005500; font-family: 'Courier New'; font-size: 10px;"
        )
        self.note_content = QTextEdit()
        self.note_content.setPlaceholderText("// Write investigation notes here...")

        right_layout.addWidget(title_label)
        right_layout.addWidget(self.note_title)
        right_layout.addWidget(content_label)
        right_layout.addWidget(self.note_content)

        body.addWidget(left)
        body.addWidget(right, stretch=1)

        root.addWidget(self.title_lbl)
        root.addLayout(btn_row)
        root.addLayout(body, stretch=1)

    def set_case(self, case_id: int, case_title: str):
        self.case_id = case_id
        self.title_lbl.setText(f"> NOTES  //  {case_title.upper()}")
        self.load_notes()

    def load_notes(self):
        if not self.case_id:
            return
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM notes WHERE case_id=? ORDER BY updated_at DESC", (self.case_id,)
        ).fetchall()
        conn.close()
        self.note_list.clear()
        for n in rows:
            item = QListWidgetItem(n["title"] or "Untitled")
            item.setData(Qt.ItemDataRole.UserRole, n["id"])
            self.note_list.addItem(item)

    def _load_note_content(self, item):
        if not item:
            return
        note_id = item.data(Qt.ItemDataRole.UserRole)
        self.current_note_id = note_id
        conn = get_connection()
        n = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
        conn.close()
        self.note_title.blockSignals(True)
        self.note_content.blockSignals(True)
        self.note_title.setText(n["title"] or "")
        self.note_content.setText(n["content"] or "")
        self.note_title.blockSignals(False)
        self.note_content.blockSignals(False)
        self._autosave_timer.start()

    def _new_note(self):
        if not self.case_id:
            QMessageBox.information(self, "Info", "Select a case first.")
            return
        conn = get_connection()
        cursor = conn.execute(
            "INSERT INTO notes (case_id, title, content) VALUES (?,?,?)",
            (self.case_id, "New Note", "")
        )
        note_id = cursor.lastrowid
        conn.commit()
        conn.close()
        self.load_notes()
        for i in range(self.note_list.count()):
            if self.note_list.item(i).data(Qt.ItemDataRole.UserRole) == note_id:
                self.note_list.setCurrentRow(i)
                break

    def _save_note(self):
        if not self.current_note_id:
            return
        title = self.note_title.text().strip() or "Untitled"
        content = self.note_content.toPlainText()
        conn = get_connection()
        conn.execute(
            "UPDATE notes SET title=?, content=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (title, content, self.current_note_id)
        )
        conn.commit()
        conn.close()
        self.load_notes()

    def _autosave(self):
        if self.current_note_id:
            self._save_note()

    def _delete_note(self):
        if not self.current_note_id:
            return
        reply = QMessageBox.question(self, "Delete", "Delete this note?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            conn = get_connection()
            conn.execute("DELETE FROM notes WHERE id=?", (self.current_note_id,))
            conn.commit()
            conn.close()
            self.current_note_id = None
            self.note_title.clear()
            self.note_content.clear()
            self.load_notes()
