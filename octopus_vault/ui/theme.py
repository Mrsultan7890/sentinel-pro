DARK_THEME = """
* {
    font-family: 'Courier New', 'Consolas', monospace;
    font-size: 13px;
    color: #00FF41;
}

QMainWindow, QDialog, QWidget {
    background-color: #0A0A0A;
    color: #00FF41;
}

QSplitter::handle {
    background-color: #00FF41;
    width: 1px;
    height: 1px;
}

/* ── SIDEBAR ── */
#sidebar {
    background-color: #0D0D0D;
    border-right: 1px solid #00FF41;
}

#sidebar_logo {
    color: #00FF41;
    font-size: 15px;
    font-weight: bold;
    font-family: 'Courier New', monospace;
    padding: 8px 12px;
    letter-spacing: 1px;
}

#sidebar_version {
    color: #005500;
    font-size: 10px;
    padding: 0px 12px 12px 12px;
    font-family: 'Courier New', monospace;
}

#sidebar QPushButton {
    background-color: transparent;
    color: #008F11;
    border: none;
    border-left: 3px solid transparent;
    padding: 10px 14px;
    text-align: left;
    font-size: 12px;
    font-family: 'Courier New', monospace;
    border-radius: 0px;
}

#sidebar QPushButton:hover {
    background-color: #001a00;
    color: #00FF41;
    border-left: 3px solid #00FF41;
}

#sidebar QPushButton:checked {
    background-color: #002200;
    color: #00FF41;
    border-left: 3px solid #00FF41;
    font-weight: bold;
}

#sidebar_divider {
    background-color: #003300;
    max-height: 1px;
    margin: 4px 12px;
}

/* ── HEADER ── */
#header {
    background-color: #080808;
    border-bottom: 1px solid #003300;
    min-height: 52px;
    max-height: 52px;
}

#header_left {
    background-color: transparent;
}

#app_title {
    color: #00FF41;
    font-size: 15px;
    font-weight: bold;
    font-family: 'Courier New', monospace;
    letter-spacing: 4px;
}

#header_tagline {
    color: #003300;
    font-size: 9px;
    font-family: 'Courier New', monospace;
    letter-spacing: 2px;
}

#header_sep {
    color: #002200;
    font-size: 20px;
    font-family: 'Courier New', monospace;
    padding: 0px 8px;
}

#header_case_pill {
    background-color: #001a00;
    border: 1px solid #003300;
    border-radius: 2px;
    padding: 3px 10px;
    color: #005500;
    font-size: 10px;
    font-family: 'Courier New', monospace;
}

#header_case_pill_active {
    background-color: #002200;
    border: 1px solid #00FF41;
    border-radius: 2px;
    padding: 3px 10px;
    color: #00FF41;
    font-size: 10px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
}

#header_shortcut_bar {
    background-color: transparent;
    color: #002200;
    font-size: 10px;
    font-family: 'Courier New', monospace;
}

#header_status_dot {
    color: #00FF41;
    font-size: 8px;
}

#header_status_text {
    color: #004400;
    font-size: 10px;
    font-family: 'Courier New', monospace;
    letter-spacing: 1px;
}

#header_status_pill {
    background-color: #001a00;
    border: 1px solid #003300;
    border-radius: 2px;
    padding: 3px 10px;
}

/* ── SECTION TITLES ── */
QLabel#section_title {
    color: #00FF41;
    font-size: 13px;
    font-weight: bold;
    font-family: 'Courier New', monospace;
    letter-spacing: 2px;
    padding: 4px 0px;
}

QLabel#subtitle {
    color: #005500;
    font-size: 11px;
    font-family: 'Courier New', monospace;
}

QLabel#field_label {
    color: #008F11;
    font-size: 11px;
    font-family: 'Courier New', monospace;
}

/* ── TABLES ── */
QTableWidget {
    background-color: #0A0A0A;
    border: 1px solid #003300;
    gridline-color: #001a00;
    color: #00FF41;
    selection-background-color: #002200;
    selection-color: #00FF41;
    alternate-background-color: #0D0D0D;
}

QTableWidget::item {
    padding: 5px 8px;
    border: none;
    font-family: 'Courier New', monospace;
    font-size: 12px;
}

QTableWidget::item:hover {
    background-color: #001a00;
    color: #00FF41;
}

QTableWidget::item:selected {
    background-color: #002200;
    color: #00FF41;
    border-left: 2px solid #00FF41;
}

QHeaderView::section {
    background-color: #0D0D0D;
    color: #008F11;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #003300;
    border-right: 1px solid #001a00;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
}

/* ── BUTTONS ── */
QPushButton {
    background-color: #001a00;
    color: #00FF41;
    border: 1px solid #00FF41;
    padding: 6px 14px;
    border-radius: 2px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #002200;
    color: #00FF41;
    border: 1px solid #00FF41;
}

QPushButton:pressed {
    background-color: #003300;
}

QPushButton:disabled {
    background-color: #0A0A0A;
    color: #003300;
    border: 1px solid #003300;
}

QPushButton#secondary_btn {
    background-color: transparent;
    color: #008F11;
    border: 1px solid #003300;
}

QPushButton#secondary_btn:hover {
    background-color: #001a00;
    color: #00FF41;
    border: 1px solid #008F11;
}

QPushButton#danger_btn {
    background-color: transparent;
    color: #FF3333;
    border: 1px solid #660000;
}

QPushButton#danger_btn:hover {
    background-color: #1a0000;
    border: 1px solid #FF3333;
}

QPushButton#action_btn {
    background-color: #002200;
    color: #00FF41;
    border: 1px solid #00FF41;
    padding: 8px 20px;
}

/* ── INPUTS ── */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #0D0D0D;
    border: 1px solid #003300;
    border-radius: 2px;
    color: #00FF41;
    padding: 6px 8px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #003300;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #00FF41;
    background-color: #0D0D0D;
}

QLineEdit::placeholder {
    color: #003300;
}

QComboBox {
    background-color: #0D0D0D;
    border: 1px solid #003300;
    border-radius: 2px;
    color: #00FF41;
    padding: 6px 8px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
}

QComboBox:focus {
    border: 1px solid #00FF41;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    color: #00FF41;
}

QComboBox QAbstractItemView {
    background-color: #0D0D0D;
    border: 1px solid #003300;
    color: #00FF41;
    selection-background-color: #002200;
    font-family: 'Courier New', monospace;
}

QDateEdit {
    background-color: #0D0D0D;
    border: 1px solid #003300;
    color: #00FF41;
    padding: 6px 8px;
    font-family: 'Courier New', monospace;
}

QDateEdit:focus {
    border: 1px solid #00FF41;
}

/* ── SCROLLBARS ── */
QScrollBar:vertical {
    background-color: #0A0A0A;
    width: 6px;
    border: none;
}

QScrollBar::handle:vertical {
    background-color: #003300;
    border-radius: 3px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #00FF41;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #0A0A0A;
    height: 6px;
    border: none;
}

QScrollBar::handle:horizontal {
    background-color: #003300;
    border-radius: 3px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #00FF41;
}

/* ── TABS ── */
QTabWidget::pane {
    border: 1px solid #003300;
    background-color: #0A0A0A;
}

QTabBar::tab {
    background-color: #0D0D0D;
    color: #005500;
    padding: 7px 16px;
    border: none;
    border-right: 1px solid #001a00;
    font-family: 'Courier New', monospace;
    font-size: 11px;
}

QTabBar::tab:selected {
    background-color: #001a00;
    color: #00FF41;
    border-bottom: 2px solid #00FF41;
}

QTabBar::tab:hover {
    background-color: #001a00;
    color: #00FF41;
}

/* ── LIST WIDGET ── */
QListWidget {
    background-color: #0A0A0A;
    border: 1px solid #003300;
    color: #008F11;
    font-family: 'Courier New', monospace;
    font-size: 12px;
}

QListWidget::item {
    padding: 6px 10px;
    border-bottom: 1px solid #001a00;
}

QListWidget::item:hover {
    background-color: #001a00;
    color: #00FF41;
}

QListWidget::item:selected {
    background-color: #002200;
    color: #00FF41;
    border-left: 2px solid #00FF41;
}

/* ── DIALOGS ── */
QDialog {
    background-color: #0A0A0A;
    border: 1px solid #003300;
}

QFormLayout QLabel {
    color: #008F11;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    min-width: 100px;
}

/* ── MESSAGE BOX ── */
QMessageBox {
    background-color: #0D0D0D;
    color: #00FF41;
    font-family: 'Courier New', monospace;
}

QMessageBox QPushButton {
    min-width: 80px;
}

/* ── TOOLTIP ── */
QToolTip {
    background-color: #0D0D0D;
    color: #00FF41;
    border: 1px solid #003300;
    padding: 4px 8px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
}

/* ── DASHBOARD CARDS ── */
#dash_card {
    background-color: #0D0D0D;
    border: 1px solid #003300;
    border-radius: 2px;
}

#dash_card:hover {
    border: 1px solid #00FF41;
}

#dash_number {
    color: #00FF41;
    font-size: 32px;
    font-weight: bold;
    font-family: 'Courier New', monospace;
}

#dash_card_title {
    color: #005500;
    font-size: 11px;
    font-family: 'Courier New', monospace;
    letter-spacing: 2px;
}

#dash_recent_title {
    color: #008F11;
    font-size: 11px;
    font-family: 'Courier New', monospace;
    letter-spacing: 1px;
    padding: 4px 0px;
}

/* ── SEARCH BAR ── */
#search_bar {
    background-color: #0D0D0D;
    border: 1px solid #003300;
    border-radius: 2px;
    color: #00FF41;
    padding: 6px 10px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
}

#search_bar:focus {
    border: 1px solid #00FF41;
}

/* ── STATUS BADGES ── */
#badge_active {
    background-color: #002200;
    color: #00FF41;
    border: 1px solid #00FF41;
    border-radius: 2px;
    padding: 1px 6px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
}

#badge_closed {
    background-color: #0D0D0D;
    color: #005500;
    border: 1px solid #003300;
    border-radius: 2px;
    padding: 1px 6px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
}

#badge_pending {
    background-color: #1a1000;
    color: #FFAA00;
    border: 1px solid #664400;
    border-radius: 2px;
    padding: 1px 6px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
}

/* ── CALENDAR ── */
QCalendarWidget {
    background-color: #0D0D0D;
    color: #00FF41;
    font-family: 'Courier New', monospace;
}

QCalendarWidget QAbstractItemView {
    background-color: #0D0D0D;
    color: #00FF41;
    selection-background-color: #002200;
}
"""
