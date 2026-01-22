#!/usr/bin/env python3
"""
SSH Terminal Manager - Entry Point

A secure SSH connection manager with optional Authentik OAuth2 integration.
"""
import sys
import json
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QLabel,
    QPushButton, QLineEdit, QFormLayout, QMessageBox,
    QDialogButtonBox, QCheckBox, QHBoxLayout
)
from PyQt6.QtCore import Qt, QSettings
from PyQt6.QtGui import QFont

from src.storage.database import Database
from src.styles import apply_theme
from src.storage.encryption import EncryptionManager
from src.ssh.manager import ConnectionManager
from src.ui.main_window import MainWindow
from src.resources import IconProvider


class LoginDialog(QDialog):
    """Initial login/setup dialog."""

    def __init__(self, encryption: EncryptionManager, is_first_run: bool, parent=None):
        super().__init__(parent)
        self.encryption = encryption
        self.is_first_run = is_first_run
        self.setWindowTitle("SSH Terminal Manager")
        self.setMinimumWidth(400)
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

        self._setup_ui()

    def _setup_ui(self):
        """Setup dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Title
        title = QLabel("SSH Terminal Manager")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Check if DPAPI credentials exist
        if self.encryption.initialize_from_dpapi():
            # Already initialized with DPAPI - auto login
            info = QLabel("Welcome back!")
            info.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(info)

            continue_btn = QPushButton("Start")
            continue_btn.setMinimumHeight(40)
            continue_btn.clicked.connect(self.accept)
            layout.addWidget(continue_btn)

        elif self.is_first_run:
            # First run - setup master password
            info = QLabel(
                "Welcome! Please set up a master password to encrypt your credentials.\n\n"
                "If you enable Windows Credential Manager, you won't need to\n"
                "enter this password again on this computer."
            )
            info.setWordWrap(True)
            info.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(info)

            self._add_password_form(layout, setup_mode=True)

        else:
            # Returning user without DPAPI - need password
            info = QLabel("Please enter your master password.")
            info.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(info)

            self._add_password_form(layout, setup_mode=False)

    def _add_password_form(self, layout: QVBoxLayout, setup_mode: bool):
        """Add password input form."""
        form = QFormLayout()
        form.setSpacing(10)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(30)
        self.password_input.returnPressed.connect(
            self._setup_password if setup_mode else self._verify_password
        )
        form.addRow("Master Password:", self.password_input)

        if setup_mode:
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input.setMinimumHeight(30)
            form.addRow("Confirm Password:", self.confirm_input)

            self.use_dpapi = QCheckBox("Remember on this computer (Windows Credential Manager)")
            self.use_dpapi.setChecked(True)
            form.addRow("", self.use_dpapi)

        layout.addLayout(form)

        # Buttons
        btn_layout = QHBoxLayout()

        ok_btn = QPushButton("Continue" if setup_mode else "Unlock")
        ok_btn.setMinimumHeight(35)
        ok_btn.clicked.connect(self._setup_password if setup_mode else self._verify_password)
        btn_layout.addWidget(ok_btn)

        cancel_btn = QPushButton("Exit")
        cancel_btn.setMinimumHeight(35)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)

        # Focus password field
        self.password_input.setFocus()

    def _setup_password(self):
        """Setup master password (first run)."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        if not password:
            QMessageBox.warning(self, "Error", "Password cannot be empty")
            return

        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return

        if len(password) < 8:
            QMessageBox.warning(
                self, "Error",
                "Password should be at least 8 characters"
            )
            return

        try:
            self.encryption.use_dpapi = self.use_dpapi.isChecked()
            self.encryption.initialize_with_password(password)

            # Save salt for later verification if not using DPAPI
            if not self.use_dpapi.isChecked():
                salt_path = Path(__file__).parent / "data" / ".salt"
                salt_path.parent.mkdir(parents=True, exist_ok=True)
                self.encryption.save_salt_to_file(salt_path)

            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to initialize: {e}")

    def _verify_password(self):
        """Verify master password (returning user)."""
        password = self.password_input.text()

        if not password:
            QMessageBox.warning(self, "Error", "Password cannot be empty")
            return

        try:
            # Load salt
            salt_path = Path(__file__).parent / "data" / ".salt"
            if salt_path.exists():
                self.encryption.load_salt_from_file(salt_path)
                self.encryption.initialize_with_password(password, self.encryption.get_salt())
                self.accept()
            else:
                QMessageBox.warning(
                    self, "Error",
                    "Credential store not found. Please set up a new password."
                )
        except Exception as e:
            QMessageBox.warning(self, "Error", "Incorrect password")


def check_first_run() -> bool:
    """Check if this is the first run."""
    data_dir = Path(__file__).parent / "data"
    db_path = data_dir / "connections.db"
    salt_path = data_dir / ".salt"

    # First run if no database and no salt file
    return not db_path.exists() and not salt_path.exists()


def main():
    """Main entry point."""
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("SSH Terminal Manager")
    app.setOrganizationName("SSHTerminalManager")

    # Apply dark theme
    apply_theme(app, "dark")

    # Check if first run
    is_first_run = check_first_run()

    # Initialize components
    database = Database()
    encryption = EncryptionManager(use_dpapi=True)

    # Show login dialog
    login_dialog = LoginDialog(encryption, is_first_run)
    if login_dialog.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    # Create connection manager
    connection_manager = ConnectionManager(database, encryption)

    # Clear icon cache to ensure fresh icons
    IconProvider.clear_cache()

    # Create and show main window (no Authentik by default)
    main_window = MainWindow(
        database=database,
        encryption=encryption,
        connection_manager=connection_manager,
        authentik=None  # Authentik is optional, configure in Settings
    )
    main_window.show()

    # Run application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
