import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from core.database import init_db
from core.encryption import is_vault_setup
from ui.theme import DARK_THEME

_main_window = None  # Global reference to prevent GC

def launch_main(app):
    global _main_window
    from ui.main_window import MainWindow
    _main_window = MainWindow()
    _main_window.show()

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_THEME)
    app.setFont(QFont("Courier New", 10))

    init_db()

    if not is_vault_setup():
        from tentacles.t8_vault import VaultSetupDialog
        auth = VaultSetupDialog()
        auth.setStyleSheet(DARK_THEME)
        auth.vault_unlocked.connect(lambda: (auth.close(), launch_main(app)))
        auth.show()
    else:
        from tentacles.t8_vault import VaultLoginDialog
        auth = VaultLoginDialog()
        auth.setStyleSheet(DARK_THEME)
        auth.vault_unlocked.connect(lambda: (auth.close(), launch_main(app)))
        auth.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
