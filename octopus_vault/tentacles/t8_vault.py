from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QMessageBox, QFormLayout, QDialog
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon
from pathlib import Path
from core.encryption import setup_vault, verify_password, is_vault_setup


def _set_icon(widget):
    ico = Path(__file__).parent.parent / "assets" / "icons" / "octopus.ico"
    if ico.exists():
        widget.setWindowIcon(QIcon(str(ico)))


class VaultSetupDialog(QWidget):
    vault_unlocked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OCTOPUS-VAULT // SETUP")
        self.setFixedSize(400, 300)
        _set_icon(self)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 32, 40, 32)
        layout.setSpacing(14)

        icon_row = QHBoxLayout()
        icon_lbl = QLabel()
        from pathlib import Path
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtCore import Qt
        ico_path = Path(__file__).parent.parent / "assets" / "icons" / "octopus_256.png"
        if ico_path.exists():
            pix = QPixmap(str(ico_path)).scaled(48, 48, Qt.AspectRatioMode.KeepAspectRatio,
                                                 Qt.TransformationMode.SmoothTransformation)
            icon_lbl.setPixmap(pix)
        icon_row.addStretch()
        icon_row.addWidget(icon_lbl)
        icon_row.addStretch()

        title = QLabel("OCTOPUS-VAULT")
        title.setObjectName("app_title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("> INITIALIZE VAULT PASSWORD")
        subtitle.setStyleSheet(
            "color: #005500; font-family: 'Courier New'; font-size: 11px; letter-spacing: 1px;"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.pass1 = QLineEdit()
        self.pass1.setPlaceholderText("[ NEW PASSWORD ]")
        self.pass1.setEchoMode(QLineEdit.EchoMode.Password)

        self.pass2 = QLineEdit()
        self.pass2.setPlaceholderText("[ CONFIRM PASSWORD ]")
        self.pass2.setEchoMode(QLineEdit.EchoMode.Password)

        create_btn = QPushButton("[ INITIALIZE VAULT ]")
        create_btn.clicked.connect(self._create)

        layout.addLayout(icon_row)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(8)
        layout.addWidget(self.pass1)
        layout.addWidget(self.pass2)
        layout.addWidget(create_btn)

    def _create(self):
        p1 = self.pass1.text()
        p2 = self.pass2.text()
        if len(p1) < 6:
            QMessageBox.warning(self, "Error", "Password must be at least 6 characters.")
            return
        if p1 != p2:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        setup_vault(p1)
        self.vault_unlocked.emit()


class VaultLoginDialog(QWidget):
    vault_unlocked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OCTOPUS-VAULT // UNLOCK")
        self.setFixedSize(400, 260)
        _set_icon(self)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 32, 40, 32)
        layout.setSpacing(14)

        icon_row = QHBoxLayout()
        icon_lbl = QLabel()
        from pathlib import Path
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtCore import Qt
        ico_path = Path(__file__).parent.parent / "assets" / "icons" / "octopus_256.png"
        if ico_path.exists():
            pix = QPixmap(str(ico_path)).scaled(48, 48, Qt.AspectRatioMode.KeepAspectRatio,
                                                 Qt.TransformationMode.SmoothTransformation)
            icon_lbl.setPixmap(pix)
        icon_row.addStretch()
        icon_row.addWidget(icon_lbl)
        icon_row.addStretch()

        title = QLabel("OCTOPUS-VAULT")
        title.setObjectName("app_title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("> ENTER PASSWORD TO UNLOCK")
        subtitle.setStyleSheet(
            "color: #005500; font-family: 'Courier New'; font-size: 11px; letter-spacing: 1px;"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.password = QLineEdit()
        self.password.setPlaceholderText("[ VAULT PASSWORD ]")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.returnPressed.connect(self._unlock)

        unlock_btn = QPushButton("[ UNLOCK VAULT ]")
        unlock_btn.clicked.connect(self._unlock)

        layout.addLayout(icon_row)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(8)
        layout.addWidget(self.password)
        layout.addWidget(unlock_btn)

    def _unlock(self):
        if verify_password(self.password.text()):
            self.vault_unlocked.emit()
        else:
            QMessageBox.warning(self, "Access Denied", "Incorrect password.")
            self.password.clear()


class VaultWidget(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("🔐  Vault Settings")
        title.setObjectName("section_title")

        info = QLabel("Your data is stored locally at:\n~/.octopus_vault/vault.db")
        info.setObjectName("subtitle")

        change_btn = QPushButton("Change Password")
        change_btn.setObjectName("secondary_btn")
        change_btn.setMaximumWidth(200)
        change_btn.clicked.connect(self._change_password)

        layout.addWidget(title)
        layout.addSpacing(16)
        layout.addWidget(info)
        layout.addSpacing(16)
        layout.addWidget(change_btn)
        layout.addStretch()

    def _change_password(self):
        from PyQt6.QtWidgets import QDialog, QFormLayout
        dlg = QDialog(self)
        dlg.setWindowTitle("Change Password")
        dlg.setMinimumWidth(320)
        form = QFormLayout(dlg)

        old_pass = QLineEdit()
        old_pass.setEchoMode(QLineEdit.EchoMode.Password)
        new_pass = QLineEdit()
        new_pass.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_pass = QLineEdit()
        confirm_pass.setEchoMode(QLineEdit.EchoMode.Password)

        form.addRow("Current Password", old_pass)
        form.addRow("New Password", new_pass)
        form.addRow("Confirm New", confirm_pass)

        btns = QHBoxLayout()
        save_btn = QPushButton("Change")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary_btn")
        cancel_btn.clicked.connect(dlg.reject)
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        form.addRow(btns)

        def do_change():
            if not verify_password(old_pass.text()):
                QMessageBox.warning(dlg, "Error", "Current password is incorrect.")
                return
            if len(new_pass.text()) < 6:
                QMessageBox.warning(dlg, "Error", "New password must be at least 6 characters.")
                return
            if new_pass.text() != confirm_pass.text():
                QMessageBox.warning(dlg, "Error", "Passwords do not match.")
                return
            setup_vault(new_pass.text())
            QMessageBox.information(dlg, "Done", "Password changed successfully.")
            dlg.accept()

        save_btn.clicked.connect(do_change)
        dlg.exec()
