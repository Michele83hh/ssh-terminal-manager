"""
SSH key management dialog.
"""
import os
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QPushButton, QLabel, QGroupBox, QFormLayout, QLineEdit,
    QComboBox, QSpinBox, QFileDialog, QMessageBox, QTextEdit,
    QDialogButtonBox, QInputDialog
)
from PyQt6.QtCore import Qt

try:
    from paramiko import RSAKey, Ed25519Key, ECDSAKey
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


class KeyGenerateDialog(QDialog):
    """Dialog for generating new SSH keys."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate SSH Key")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        # Key type
        form = QFormLayout()

        self.key_type = QComboBox()
        self.key_type.addItems(["RSA", "Ed25519", "ECDSA"])
        self.key_type.currentTextChanged.connect(self._on_type_changed)
        form.addRow("Key Type:", self.key_type)

        self.key_bits = QComboBox()
        self.key_bits.addItems(["2048", "3072", "4096"])
        self.key_bits.setCurrentText("4096")
        form.addRow("Key Size:", self.key_bits)

        self.key_name = QLineEdit()
        self.key_name.setPlaceholderText("id_rsa")
        form.addRow("Key Name:", self.key_name)

        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setPlaceholderText("Optional passphrase")
        form.addRow("Passphrase:", self.passphrase)

        self.confirm_passphrase = QLineEdit()
        self.confirm_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Confirm:", self.confirm_passphrase)

        self.comment = QLineEdit()
        self.comment.setPlaceholderText("user@hostname")
        form.addRow("Comment:", self.comment)

        layout.addLayout(form)

        # Save location
        location_layout = QHBoxLayout()
        self.save_path = QLineEdit()
        self.save_path.setText(str(Path.home() / ".ssh"))
        location_layout.addWidget(self.save_path)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_location)
        location_layout.addWidget(browse_btn)

        form.addRow("Save to:", location_layout)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._generate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._on_type_changed("RSA")

    def _on_type_changed(self, key_type: str):
        """Handle key type change."""
        if key_type == "Ed25519":
            self.key_bits.setEnabled(False)
            self.key_name.setPlaceholderText("id_ed25519")
        elif key_type == "ECDSA":
            self.key_bits.clear()
            self.key_bits.addItems(["256", "384", "521"])
            self.key_bits.setEnabled(True)
            self.key_name.setPlaceholderText("id_ecdsa")
        else:  # RSA
            self.key_bits.clear()
            self.key_bits.addItems(["2048", "3072", "4096"])
            self.key_bits.setCurrentText("4096")
            self.key_bits.setEnabled(True)
            self.key_name.setPlaceholderText("id_rsa")

    def _browse_location(self):
        """Browse for save location."""
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Directory",
            str(Path.home() / ".ssh")
        )
        if path:
            self.save_path.setText(path)

    def _generate(self):
        """Generate the SSH key."""
        if not PARAMIKO_AVAILABLE:
            QMessageBox.critical(self, "Error", "paramiko is required for key generation")
            return

        # Validate passphrase
        if self.passphrase.text() != self.confirm_passphrase.text():
            QMessageBox.warning(self, "Error", "Passphrases do not match")
            return

        key_type = self.key_type.currentText()
        key_name = self.key_name.text() or self.key_name.placeholderText()
        passphrase = self.passphrase.text() or None
        comment = self.comment.text()
        save_dir = Path(self.save_path.text())

        if not save_dir.exists():
            save_dir.mkdir(parents=True, exist_ok=True)

        private_path = save_dir / key_name
        public_path = save_dir / f"{key_name}.pub"

        # Check if files exist
        if private_path.exists() or public_path.exists():
            result = QMessageBox.question(
                self,
                "Overwrite?",
                f"Key files already exist at {private_path}. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if result != QMessageBox.StandardButton.Yes:
                return

        try:
            # Generate key
            if key_type == "RSA":
                bits = int(self.key_bits.currentText())
                key = RSAKey.generate(bits)
            elif key_type == "Ed25519":
                key = Ed25519Key.generate()
            else:  # ECDSA
                from paramiko.ecdsakey import ECDSAKey
                bits = int(self.key_bits.currentText())
                key = ECDSAKey.generate(bits=bits)

            # Save private key
            key.write_private_key_file(str(private_path), password=passphrase)

            # Save public key
            public_key = f"{key.get_name()} {key.get_base64()}"
            if comment:
                public_key += f" {comment}"
            public_path.write_text(public_key + "\n")

            # Set permissions (on Unix)
            if os.name != 'nt':
                os.chmod(private_path, 0o600)
                os.chmod(public_path, 0o644)

            QMessageBox.information(
                self,
                "Key Generated",
                f"SSH key pair generated successfully:\n\n"
                f"Private key: {private_path}\n"
                f"Public key: {public_path}"
            )

            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate key: {e}")


class KeyManagerDialog(QDialog):
    """SSH key management dialog."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SSH Key Manager")
        self.setMinimumSize(700, 500)

        self._ssh_dir = Path.home() / ".ssh"
        self._setup_ui()
        self._load_keys()

    def _setup_ui(self):
        """Setup dialog UI."""
        layout = QHBoxLayout(self)

        # Left panel - key list
        left_panel = QVBoxLayout()

        list_label = QLabel("SSH Keys:")
        left_panel.addWidget(list_label)

        self.key_list = QListWidget()
        self.key_list.currentItemChanged.connect(self._on_key_selected)
        left_panel.addWidget(self.key_list)

        # Buttons
        btn_layout = QHBoxLayout()

        generate_btn = QPushButton("Generate")
        generate_btn.clicked.connect(self._generate_key)
        btn_layout.addWidget(generate_btn)

        import_btn = QPushButton("Import")
        import_btn.clicked.connect(self._import_key)
        btn_layout.addWidget(import_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self._delete_key)
        btn_layout.addWidget(delete_btn)

        left_panel.addLayout(btn_layout)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._load_keys)
        left_panel.addWidget(refresh_btn)

        layout.addLayout(left_panel, 1)

        # Right panel - key details
        right_panel = QVBoxLayout()

        details_group = QGroupBox("Key Details")
        details_layout = QFormLayout(details_group)

        self.key_path_label = QLabel("-")
        self.key_path_label.setWordWrap(True)
        details_layout.addRow("Path:", self.key_path_label)

        self.key_type_label = QLabel("-")
        details_layout.addRow("Type:", self.key_type_label)

        self.key_size_label = QLabel("-")
        details_layout.addRow("Size:", self.key_size_label)

        self.key_fingerprint_label = QLabel("-")
        self.key_fingerprint_label.setWordWrap(True)
        self.key_fingerprint_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details_layout.addRow("Fingerprint:", self.key_fingerprint_label)

        right_panel.addWidget(details_group)

        # Public key display
        pubkey_group = QGroupBox("Public Key")
        pubkey_layout = QVBoxLayout(pubkey_group)

        self.pubkey_text = QTextEdit()
        self.pubkey_text.setReadOnly(True)
        self.pubkey_text.setMaximumHeight(100)
        pubkey_layout.addWidget(self.pubkey_text)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self._copy_pubkey)
        pubkey_layout.addWidget(copy_btn)

        right_panel.addWidget(pubkey_group)

        # Actions
        actions_group = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_group)

        change_pass_btn = QPushButton("Change Passphrase")
        change_pass_btn.clicked.connect(self._change_passphrase)
        actions_layout.addWidget(change_pass_btn)

        export_btn = QPushButton("Export Public Key")
        export_btn.clicked.connect(self._export_pubkey)
        actions_layout.addWidget(export_btn)

        right_panel.addWidget(actions_group)
        right_panel.addStretch()

        layout.addLayout(right_panel, 2)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        right_panel.addWidget(close_btn)

    def _load_keys(self):
        """Load SSH keys from .ssh directory."""
        self.key_list.clear()

        if not self._ssh_dir.exists():
            return

        # Look for private keys (files without .pub extension that have matching .pub)
        for path in self._ssh_dir.iterdir():
            if path.is_file() and not path.suffix == '.pub':
                pub_path = path.with_suffix(path.suffix + '.pub') if path.suffix else Path(str(path) + '.pub')
                if pub_path.exists():
                    item = QListWidgetItem(path.name)
                    item.setData(Qt.ItemDataRole.UserRole, str(path))
                    self.key_list.addItem(item)

    def _on_key_selected(self, current: QListWidgetItem, previous: QListWidgetItem):
        """Handle key selection."""
        if not current:
            self.key_path_label.setText("-")
            self.key_type_label.setText("-")
            self.key_size_label.setText("-")
            self.key_fingerprint_label.setText("-")
            self.pubkey_text.clear()
            return

        key_path = Path(current.data(Qt.ItemDataRole.UserRole))
        pub_path = Path(str(key_path) + '.pub')

        self.key_path_label.setText(str(key_path))

        # Try to read public key
        if pub_path.exists():
            try:
                pubkey_content = pub_path.read_text().strip()
                self.pubkey_text.setText(pubkey_content)

                # Parse public key
                parts = pubkey_content.split()
                if len(parts) >= 2:
                    key_type = parts[0]
                    self.key_type_label.setText(key_type)

                    # Get fingerprint
                    if PARAMIKO_AVAILABLE:
                        try:
                            import base64
                            import hashlib
                            key_data = base64.b64decode(parts[1])
                            fingerprint = hashlib.sha256(key_data).hexdigest()
                            formatted = ':'.join(
                                fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)
                            )
                            self.key_fingerprint_label.setText(f"SHA256:{formatted[:47]}...")
                        except Exception:
                            self.key_fingerprint_label.setText("Unable to compute")

            except Exception as e:
                self.pubkey_text.setText(f"Error reading public key: {e}")

        # Try to determine key size
        if PARAMIKO_AVAILABLE:
            try:
                # Try loading without passphrase first
                key = self._load_private_key(key_path)
                if key:
                    self.key_size_label.setText(f"{key.get_bits()} bits")
            except Exception:
                self.key_size_label.setText("Unknown (encrypted)")

    def _load_private_key(self, path: Path, passphrase: str = None):
        """Try to load a private key."""
        if not PARAMIKO_AVAILABLE:
            return None

        key_types = [RSAKey, Ed25519Key, ECDSAKey]

        for key_class in key_types:
            try:
                return key_class.from_private_key_file(str(path), password=passphrase)
            except Exception:
                continue

        return None

    def _generate_key(self):
        """Open key generation dialog."""
        dialog = KeyGenerateDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._load_keys()

    def _import_key(self):
        """Import an existing key."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import SSH Key",
            str(Path.home()),
            "All Files (*)"
        )

        if not file_path:
            return

        src_path = Path(file_path)
        dest_path = self._ssh_dir / src_path.name

        if dest_path.exists():
            result = QMessageBox.question(
                self,
                "Overwrite?",
                f"Key {dest_path.name} already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if result != QMessageBox.StandardButton.Yes:
                return

        try:
            # Copy private key
            dest_path.write_bytes(src_path.read_bytes())

            # Copy public key if exists
            src_pub = Path(str(src_path) + '.pub')
            if src_pub.exists():
                dest_pub = Path(str(dest_path) + '.pub')
                dest_pub.write_bytes(src_pub.read_bytes())

            # Set permissions
            if os.name != 'nt':
                os.chmod(dest_path, 0o600)

            self._load_keys()
            QMessageBox.information(self, "Imported", f"Key imported to {dest_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import key: {e}")

    def _delete_key(self):
        """Delete selected key."""
        current = self.key_list.currentItem()
        if not current:
            return

        key_path = Path(current.data(Qt.ItemDataRole.UserRole))

        result = QMessageBox.question(
            self,
            "Delete Key?",
            f"Are you sure you want to delete {key_path.name}?\n\n"
            "This action cannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result != QMessageBox.StandardButton.Yes:
            return

        try:
            key_path.unlink()

            pub_path = Path(str(key_path) + '.pub')
            if pub_path.exists():
                pub_path.unlink()

            self._load_keys()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete key: {e}")

    def _copy_pubkey(self):
        """Copy public key to clipboard."""
        from PyQt6.QtWidgets import QApplication
        text = self.pubkey_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Public key copied to clipboard")

    def _export_pubkey(self):
        """Export public key to file."""
        current = self.key_list.currentItem()
        if not current:
            return

        text = self.pubkey_text.toPlainText()
        if not text:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Public Key",
            str(Path.home() / "public_key.txt"),
            "Text Files (*.txt);;All Files (*)"
        )

        if file_path:
            try:
                Path(file_path).write_text(text + "\n")
                QMessageBox.information(self, "Exported", f"Public key exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {e}")

    def _change_passphrase(self):
        """Change key passphrase."""
        current = self.key_list.currentItem()
        if not current:
            return

        if not PARAMIKO_AVAILABLE:
            QMessageBox.critical(self, "Error", "paramiko is required")
            return

        key_path = Path(current.data(Qt.ItemDataRole.UserRole))

        # Get current passphrase
        current_pass, ok = QInputDialog.getText(
            self,
            "Current Passphrase",
            "Enter current passphrase (leave empty if none):",
            QLineEdit.EchoMode.Password
        )
        if not ok:
            return

        # Load key
        key = self._load_private_key(key_path, current_pass or None)
        if not key:
            QMessageBox.critical(self, "Error", "Could not load key with provided passphrase")
            return

        # Get new passphrase
        new_pass, ok = QInputDialog.getText(
            self,
            "New Passphrase",
            "Enter new passphrase (leave empty for none):",
            QLineEdit.EchoMode.Password
        )
        if not ok:
            return

        confirm_pass, ok = QInputDialog.getText(
            self,
            "Confirm Passphrase",
            "Confirm new passphrase:",
            QLineEdit.EchoMode.Password
        )
        if not ok:
            return

        if new_pass != confirm_pass:
            QMessageBox.warning(self, "Error", "Passphrases do not match")
            return

        try:
            key.write_private_key_file(str(key_path), password=new_pass or None)
            QMessageBox.information(self, "Success", "Passphrase changed successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change passphrase: {e}")
