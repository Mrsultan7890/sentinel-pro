from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFrame, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QShortcut, QKeySequence, QIcon, QPixmap
from pathlib import Path

from ui.dashboard import DashboardWidget
from tentacles.t1_cases import CasesWidget
from tentacles.t2_subjects import SubjectsWidget
from tentacles.t3_evidence import EvidenceWidget
from tentacles.t4_timeline import TimelineWidget
from tentacles.t5_notes import NotesWidget
from tentacles.t6_tags import TagsWidget
from tentacles.t7_export import ExportWidget
from tentacles.t8_vault import VaultWidget
from tentacles.t9_linkgraph import LinkGraphWidget
from tentacles.t10_duplicates import DuplicateDetectorWidget
from tentacles.t11_bulkimport import BulkImportWidget

TENTACLES = [
    ("~$", "DASHBOARD",  0),
    ("T1", "CASES",      1),
    ("T2", "SUBJECTS",   2),
    ("T3", "EVIDENCE",   3),
    ("T4", "TIMELINE",   4),
    ("T5", "NOTES",      5),
    ("T6", "TAGS",       6),
    ("T7", "EXPORT",     7),
    ("T8", "VAULT",      8),
    ("T9", "LINK GRAPH", 9),
    ("TA", "DUPLICATES", 10),
    ("TB", "BULK IMPORT",11),
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OCTOPUS-VAULT")
        self.setMinimumSize(1200, 750)
        self.active_case_id = None
        self.active_case_title = ""
        self._build_ui()
        self._setup_shortcuts()

    def _build_ui(self):
        # ── App Icon ──
        icon_path = Path(__file__).parent.parent / "assets" / "icons" / "octopus.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──
        header = QWidget()
        header.setObjectName("header")
        header.setFixedHeight(52)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(14, 0, 14, 0)
        h_layout.setSpacing(0)

        # Left: icon + title + tagline
        icon_lbl = QLabel()
        icon_path_png = Path(__file__).parent.parent / "assets" / "icons" / "octopus_256.png"
        if icon_path_png.exists():
            pix = QPixmap(str(icon_path_png)).scaled(30, 30, Qt.AspectRatioMode.KeepAspectRatio,
                                                      Qt.TransformationMode.SmoothTransformation)
            icon_lbl.setPixmap(pix)
        else:
            icon_lbl.setText("🐙")
            icon_lbl.setStyleSheet("font-size: 22px;")

        title_block = QVBoxLayout()
        title_block.setContentsMargins(8, 0, 0, 0)
        title_block.setSpacing(0)
        logo = QLabel("OCTOPUS-VAULT")
        logo.setObjectName("app_title")
        tagline = QLabel("OSINT INVESTIGATION SUITE")
        tagline.setObjectName("header_tagline")
        title_block.addWidget(logo)
        title_block.addWidget(tagline)

        # Separator
        sep = QLabel("|")
        sep.setObjectName("header_sep")

        # Case pill
        self.case_label = QLabel("NO ACTIVE CASE")
        self.case_label.setObjectName("header_case_pill")

        # Right side
        shortcuts = QLabel("^N New  ^F Search  ^⇧C Capture  ^D Dash")
        shortcuts.setObjectName("header_shortcut_bar")

        status_pill = QWidget()
        status_pill.setObjectName("header_status_pill")
        sp_layout = QHBoxLayout(status_pill)
        sp_layout.setContentsMargins(8, 0, 8, 0)
        sp_layout.setSpacing(6)
        dot = QLabel("●")
        dot.setObjectName("header_status_dot")
        status_txt = QLabel("VAULT ONLINE")
        status_txt.setObjectName("header_status_text")
        sp_layout.addWidget(dot)
        sp_layout.addWidget(status_txt)

        h_layout.addWidget(icon_lbl)
        h_layout.addLayout(title_block)
        h_layout.addWidget(sep)
        h_layout.addWidget(self.case_label)
        h_layout.addStretch()
        h_layout.addWidget(shortcuts)
        h_layout.addSpacing(16)
        h_layout.addWidget(status_pill)

        root.addWidget(header)

        # ── Body ──
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # Sidebar
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(175)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        logo_lbl = QLabel("  🐙 OCTOPUS")
        logo_lbl.setObjectName("sidebar_logo")
        ver_lbl = QLabel("  v2.0 // OSINT VAULT")
        ver_lbl.setObjectName("sidebar_version")
        sidebar_layout.addWidget(logo_lbl)
        sidebar_layout.addWidget(ver_lbl)

        div = QFrame()
        div.setObjectName("sidebar_divider")
        div.setFixedHeight(1)
        sidebar_layout.addWidget(div)
        sidebar_layout.addSpacing(6)

        self.nav_buttons = []
        for prefix, name, idx in TENTACLES:
            btn = QPushButton(f"  [{prefix}]  {name}")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=idx: self._switch_tab(i))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # Quick capture button at bottom of sidebar
        qc_btn = QPushButton("  [⚡] QUICK CAPTURE")
        qc_btn.setStyleSheet(
            "background: transparent; color: #FFAA00; border: none;"
            "border-top: 1px solid #003300; padding: 10px 14px;"
            "text-align: left; font-family: 'Courier New'; font-size: 12px;"
        )
        qc_btn.clicked.connect(self._quick_capture)
        sidebar_layout.addWidget(qc_btn)

        # Stack
        self.stack = QStackedWidget()

        self.dashboard_widget   = DashboardWidget()
        self.cases_widget       = CasesWidget()
        self.subjects_widget    = SubjectsWidget()
        self.evidence_widget    = EvidenceWidget()
        self.timeline_widget    = TimelineWidget()
        self.notes_widget       = NotesWidget()
        self.tags_widget        = TagsWidget()
        self.export_widget      = ExportWidget()
        self.vault_widget       = VaultWidget()
        self.linkgraph_widget   = LinkGraphWidget()
        self.duplicates_widget  = DuplicateDetectorWidget()
        self.bulkimport_widget  = BulkImportWidget()

        for w in [self.dashboard_widget, self.cases_widget, self.subjects_widget,
                  self.evidence_widget, self.timeline_widget, self.notes_widget,
                  self.tags_widget, self.export_widget, self.vault_widget,
                  self.linkgraph_widget, self.duplicates_widget, self.bulkimport_widget]:
            self.stack.addWidget(w)

        self.cases_widget.case_selected.connect(self._on_case_selected)

        body.addWidget(sidebar)
        body.addWidget(self.stack)

        body_widget = QWidget()
        body_widget.setLayout(body)
        root.addWidget(body_widget)

        self._switch_tab(0)

    def _setup_shortcuts(self):
        # Ctrl+N — new item in current tab
        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self._shortcut_new)
        # Ctrl+S — save (notes)
        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self._shortcut_save)
        # Ctrl+F — focus search
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self._shortcut_search)
        # Ctrl+Shift+C — quick capture
        QShortcut(QKeySequence("Ctrl+Shift+C"), self).activated.connect(self._quick_capture)
        # Ctrl+D — go to dashboard
        QShortcut(QKeySequence("Ctrl+D"), self).activated.connect(lambda: self._switch_tab(0))
        # Ctrl+Alt+S — hidden investigation board
        QShortcut(QKeySequence("Ctrl+Alt+S"), self).activated.connect(self._open_board)
        # Ctrl+1..9 — switch tabs
        for i in range(1, 10):
            QShortcut(QKeySequence(f"Ctrl+{i}"), self).activated.connect(
                lambda checked=False, idx=i: self._switch_tab(idx)
            )

    def _shortcut_new(self):
        idx = self.stack.currentIndex()
        actions = {
            1: lambda: self.cases_widget._new_case(),
            2: lambda: self.subjects_widget._new_subject(),
            3: lambda: self.evidence_widget._new_evidence(),
            4: lambda: self.timeline_widget._new_event(),
            5: lambda: self.notes_widget._new_note(),
        }
        if idx in actions:
            actions[idx]()

    def _shortcut_save(self):
        if self.stack.currentIndex() == 5:
            self.notes_widget._save_note()

    def _shortcut_search(self):
        idx = self.stack.currentIndex()
        if idx == 1 and hasattr(self.cases_widget, "search_input"):
            self.cases_widget.search_input.setFocus()
        elif idx == 3 and hasattr(self.evidence_widget, "search_input"):
            self.evidence_widget.search_input.setFocus()

    def _quick_capture(self):
        from ui.quick_capture import QuickCaptureDialog
        dlg = QuickCaptureDialog(self, active_case_id=self.active_case_id)
        if dlg.exec():
            # Refresh evidence if currently on that tab
            if self.stack.currentIndex() == 3:
                self.evidence_widget.load_evidence()
            self.dashboard_widget.refresh()

    def _switch_tab(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
        if index == 0:
            self.dashboard_widget.refresh()

    def _open_board(self):
        from tentacles.t12_board import InvestigationBoardWindow
        case_id    = self.active_case_id
        case_title = self.active_case_title
        self._board_window = InvestigationBoardWindow(
            case_id=case_id, case_title=case_title, parent=None
        )

    def _on_case_selected(self, case_id: int, case_title: str):
        self.active_case_id = case_id
        self.active_case_title = case_title
        self.case_label.setObjectName("header_case_pill_active")
        self.case_label.setText(f"▶  {case_title.upper()}")
        self.case_label.style().unpolish(self.case_label)
        self.case_label.style().polish(self.case_label)

        self.subjects_widget.set_case(case_id, case_title)
        self.evidence_widget.set_case(case_id, case_title)
        self.timeline_widget.set_case(case_id, case_title)
        self.notes_widget.set_case(case_id, case_title)
        self.export_widget.set_case(case_id, case_title)
        self.linkgraph_widget.set_case(case_id, case_title)
        self.duplicates_widget.set_case(case_id, case_title)
        self.bulkimport_widget.set_case(case_id, case_title)

        self._switch_tab(2)
