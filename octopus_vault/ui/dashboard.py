from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from datetime import datetime
from core.database import get_connection


class StatCard(QFrame):
    def __init__(self, number, label):
        super().__init__()
        self.setObjectName("dash_card")
        self.setFixedHeight(90)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        num = QLabel(str(number))
        num.setObjectName("dash_number")
        num.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel(label.upper())
        lbl.setObjectName("dash_card_title")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(num)
        layout.addWidget(lbl)


class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # ASCII banner
        banner = QLabel(
            "  ██████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗\n"
            " ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝\n"
            " ██║   ██║██║        ██║   ██║   ██║██████╔╝██║   ██║███████╗\n"
            " ██║   ██║██║        ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║\n"
            " ╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║\n"
            "  ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝\n"
            "                         V A U L T  //  OSINT Case Manager"
        )
        banner.setStyleSheet(
            "color: #00FF41; font-family: 'Courier New', monospace; "
            "font-size: 10px; letter-spacing: 0px; line-height: 1.4;"
        )
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Clock
        self.clock_label = QLabel()
        self.clock_label.setStyleSheet(
            "color: #005500; font-family: 'Courier New', monospace; font-size: 11px;"
        )
        self.clock_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._update_clock()
        timer = QTimer(self)
        timer.timeout.connect(self._update_clock)
        timer.start(1000)

        # Divider
        div = QLabel("─" * 90)
        div.setStyleSheet("color: #003300; font-family: 'Courier New', monospace; font-size: 10px;")
        div.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Stats row
        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(12)
        self._stat_cards = {}
        for key, label in [("cases", "Cases"), ("subjects", "Subjects"),
                            ("evidence", "Evidence"), ("notes", "Notes")]:
            card = StatCard(0, label)
            self._stat_cards[key] = card
            self.stats_row.addWidget(card)

        # Recent cases
        recent_title = QLabel("> RECENT INVESTIGATIONS")
        recent_title.setObjectName("dash_recent_title")

        self.recent_table = QTableWidget(0, 4)
        self.recent_table.setHorizontalHeaderLabels(["CASE ID", "TITLE", "STATUS", "LAST UPDATED"])
        self.recent_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.recent_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.recent_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.recent_table.setMaximumHeight(200)
        self.recent_table.setAlternatingRowColors(True)

        # Recent evidence
        ev_title = QLabel("> RECENT EVIDENCE COLLECTED")
        ev_title.setObjectName("dash_recent_title")

        self.ev_table = QTableWidget(0, 4)
        self.ev_table.setHorizontalHeaderLabels(["TYPE", "TITLE", "SOURCE", "DATE"])
        self.ev_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.ev_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ev_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ev_table.setMaximumHeight(180)
        self.ev_table.setAlternatingRowColors(True)

        layout.addWidget(banner)
        layout.addWidget(self.clock_label)
        layout.addWidget(div)
        layout.addLayout(self.stats_row)
        layout.addWidget(recent_title)
        layout.addWidget(self.recent_table)
        layout.addWidget(ev_title)
        layout.addWidget(self.ev_table)
        layout.addStretch()

        self.refresh()

    def _update_clock(self):
        now = datetime.now().strftime("[ %Y-%m-%d  %H:%M:%S ]  //  SYSTEM ONLINE")
        self.clock_label.setText(now)

    def refresh(self):
        conn = get_connection()
        cases_count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        subjects_count = conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0]
        evidence_count = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        notes_count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]

        recent_cases = conn.execute(
            "SELECT * FROM cases ORDER BY updated_at DESC LIMIT 8"
        ).fetchall()

        recent_ev = conn.execute(
            "SELECT * FROM evidence ORDER BY created_at DESC LIMIT 6"
        ).fetchall()
        conn.close()

        # Update stat cards
        for key, val in [("cases", cases_count), ("subjects", subjects_count),
                         ("evidence", evidence_count), ("notes", notes_count)]:
            card = self._stat_cards[key]
            card.layout().itemAt(0).widget().setText(str(val))

        # Recent cases table
        self.recent_table.setRowCount(0)
        for i, c in enumerate(recent_cases):
            self.recent_table.insertRow(i)
            self.recent_table.setItem(i, 0, QTableWidgetItem(f"#{c['id']:04d}"))
            self.recent_table.setItem(i, 1, QTableWidgetItem(c["title"]))
            status_item = QTableWidgetItem(c["status"])
            if c["status"] == "Active":
                status_item.setForeground(QColor("#00FF41"))
            elif c["status"] == "Closed":
                status_item.setForeground(QColor("#005500"))
            else:
                status_item.setForeground(QColor("#FFAA00"))
            self.recent_table.setItem(i, 2, status_item)
            self.recent_table.setItem(i, 3, QTableWidgetItem(str(c["updated_at"])[:16]))

        # Recent evidence table
        self.ev_table.setRowCount(0)
        for i, e in enumerate(recent_ev):
            self.ev_table.insertRow(i)
            self.ev_table.setItem(i, 0, QTableWidgetItem(e["type"]))
            self.ev_table.setItem(i, 1, QTableWidgetItem(e["title"] or e["content"][:40] if e["content"] else ""))
            self.ev_table.setItem(i, 2, QTableWidgetItem(e["source"] or ""))
            self.ev_table.setItem(i, 3, QTableWidgetItem(str(e["created_at"])[:16]))
