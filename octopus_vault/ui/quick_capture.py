from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTextEdit, QComboBox, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut
from core.database import get_connection


class QuickCaptureDialog(QDialog):
    def __init__(self, parent=None, active_case_id=None):
        super().__init__(parent)
        self.setWindowTitle("// QUICK CAPTURE")
        self.setMinimumWidth(500)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint)
        self._build_ui(active_case_id)
        self._paste_clipboard()

    def _build_ui(self, active_case_id):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("> QUICK CAPTURE  //  CTRL+SHIFT+C")
        title.setObjectName("section_title")

        # Case selector
        case_row = QHBoxLayout()
        case_lbl = QLabel("CASE:")
        case_lbl.setFixedWidth(80)
        case_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")
        self.case_combo = QComboBox()
        self._load_cases(active_case_id)
        case_row.addWidget(case_lbl)
        case_row.addWidget(self.case_combo)

        # Type selector
        type_row = QHBoxLayout()
        type_lbl = QLabel("TYPE:")
        type_lbl.setFixedWidth(80)
        type_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["URL", "IP Address", "Email", "Username", "Phone",
                                   "Screenshot", "Document", "Note", "Other"])
        type_row.addWidget(type_lbl)
        type_row.addWidget(self.type_combo)

        # Title
        title_row = QHBoxLayout()
        title_lbl = QLabel("TITLE:")
        title_lbl.setFixedWidth(80)
        title_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("[ OPTIONAL TITLE ]")
        title_row.addWidget(title_lbl)
        title_row.addWidget(self.title_input)

        # Content
        content_lbl = QLabel("> CONTENT:")
        content_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")
        self.content_input = QTextEdit()
        self.content_input.setMaximumHeight(120)
        self.content_input.setPlaceholderText("// Paste or type content here...")

        # Source
        source_row = QHBoxLayout()
        source_lbl = QLabel("SOURCE:")
        source_lbl.setFixedWidth(80)
        source_lbl.setStyleSheet("color: #005500; font-family: 'Courier New'; font-size: 11px;")
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("[ e.g. Twitter, Shodan, Manual ]")
        source_row.addWidget(source_lbl)
        source_row.addWidget(self.source_input)

        # Buttons
        btn_row = QHBoxLayout()
        save_btn = QPushButton("[ENTER] CAPTURE")
        cancel_btn = QPushButton("CANCEL")
        cancel_btn.setObjectName("secondary_btn")
        save_btn.clicked.connect(self._save)
        cancel_btn.clicked.connect(self.reject)

        # Enter shortcut
        enter_sc = QShortcut(QKeySequence("Return"), self)
        enter_sc.activated.connect(self._save)

        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)

        layout.addWidget(title)
        layout.addLayout(case_row)
        layout.addLayout(type_row)
        layout.addLayout(title_row)
        layout.addWidget(content_lbl)
        layout.addWidget(self.content_input)
        layout.addLayout(source_row)
        layout.addLayout(btn_row)

    def _load_cases(self, active_case_id):
        conn = get_connection()
        cases = conn.execute("SELECT id, title FROM cases WHERE status='Active' ORDER BY updated_at DESC").fetchall()
        conn.close()
        self.case_combo.clear()
        selected_idx = 0
        for i, c in enumerate(cases):
            self.case_combo.addItem(c["title"], c["id"])
            if c["id"] == active_case_id:
                selected_idx = i
        if cases:
            self.case_combo.setCurrentIndex(selected_idx)

    def _paste_clipboard(self):
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip()
        if text:
            self.content_input.setText(text)
            # Auto-detect type
            if text.startswith("http"):
                self.type_combo.setCurrentText("URL")
            elif "@" in text and "." in text:
                self.type_combo.setCurrentText("Email")
            elif text.replace(".", "").replace(":", "").isdigit():
                self.type_combo.setCurrentText("IP Address")

    def _save(self):
        case_id = self.case_combo.currentData()
        if not case_id:
            return
        content = self.content_input.toPlainText().strip()
        if not content:
            return
        conn = get_connection()
        conn.execute(
            "INSERT INTO evidence (case_id, type, title, content, source) VALUES (?,?,?,?,?)",
            (case_id, self.type_combo.currentText(),
             self.title_input.text().strip(), content,
             self.source_input.text().strip())
        )
        conn.commit()
        conn.close()
        self.accept()
