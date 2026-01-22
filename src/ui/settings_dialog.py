"""
Settings dialog with Putty-like terminal configuration options.
"""
import json
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QFormLayout, QGroupBox, QLabel, QLineEdit, QSpinBox,
    QComboBox, QCheckBox, QPushButton, QColorDialog,
    QFontComboBox, QDialogButtonBox, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QSettings, pyqtSignal
from PyQt6.QtGui import QColor, QFont


class ColorButton(QPushButton):
    """Button that displays and allows selection of a color."""

    def __init__(self, color: QColor = QColor(255, 255, 255), parent=None):
        super().__init__(parent)
        self._color = color
        self._update_style()
        self.clicked.connect(self._choose_color)

    def _update_style(self):
        """Update button style to show color."""
        self.setStyleSheet(
            f"background-color: {self._color.name()}; "
            f"border: 1px solid #555; "
            f"min-width: 60px; min-height: 25px;"
        )

    def _choose_color(self):
        """Open color picker dialog."""
        color = QColorDialog.getColor(self._color, self, "Select Color")
        if color.isValid():
            self._color = color
            self._update_style()

    def get_color(self) -> QColor:
        return self._color

    def set_color(self, color: QColor):
        self._color = color
        self._update_style()


class SettingsDialog(QDialog):
    """Settings dialog with multiple configuration tabs."""

    # Signal emitted when settings are applied (for live preview)
    settings_applied = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumSize(600, 500)

        self._settings = QSettings("SSHTerminalManager", "SSHTerminalManager")
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self):
        """Setup dialog UI."""
        layout = QVBoxLayout(self)

        # Tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Appearance tab
        tabs.addTab(self._create_appearance_tab(), "Appearance")

        # Terminal tab
        tabs.addTab(self._create_terminal_tab(), "Terminal")

        # Connection tab
        tabs.addTab(self._create_connection_tab(), "Connection")

        # Authentik tab
        tabs.addTab(self._create_authentik_tab(), "Authentik")

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel |
            QDialogButtonBox.StandardButton.Apply |
            QDialogButtonBox.StandardButton.RestoreDefaults
        )
        buttons.accepted.connect(self._save_and_close)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self._save_settings)
        buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(self._restore_defaults)
        layout.addWidget(buttons)

    def _create_appearance_tab(self) -> QWidget:
        """Create appearance settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Font settings
        font_group = QGroupBox("Font")
        font_layout = QFormLayout(font_group)

        self.font_family = QFontComboBox()
        self.font_family.setCurrentFont(QFont("Consolas"))
        font_layout.addRow("Family:", self.font_family)

        self.font_size = QSpinBox()
        self.font_size.setRange(6, 72)
        self.font_size.setValue(11)
        font_layout.addRow("Size:", self.font_size)

        layout.addWidget(font_group)

        # Colors
        colors_group = QGroupBox("Colors")
        colors_layout = QFormLayout(colors_group)

        self.fg_color = ColorButton(QColor(229, 229, 229))
        colors_layout.addRow("Foreground:", self.fg_color)

        self.bg_color = ColorButton(QColor(30, 30, 30))
        colors_layout.addRow("Background:", self.bg_color)

        layout.addWidget(colors_group)

        # Color scheme presets
        scheme_group = QGroupBox("Color Scheme")
        scheme_layout = QHBoxLayout(scheme_group)

        self.color_scheme = QComboBox()
        self.color_scheme.addItems([
            "Default Dark",
            "Solarized Dark",
            "Solarized Light",
            "Monokai",
            "One Dark",
            "Dracula"
        ])
        self.color_scheme.currentTextChanged.connect(self._apply_color_scheme)
        scheme_layout.addWidget(self.color_scheme)

        layout.addWidget(scheme_group)
        layout.addStretch()

        return widget

    def _create_terminal_tab(self) -> QWidget:
        """Create terminal settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Scrollback settings
        scrollback_group = QGroupBox("Scrollback")
        scrollback_layout = QFormLayout(scrollback_group)

        self.scrollback_lines = QSpinBox()
        self.scrollback_lines.setRange(100, 100000)
        self.scrollback_lines.setValue(10000)
        self.scrollback_lines.setSingleStep(1000)
        scrollback_layout.addRow("Lines:", self.scrollback_lines)

        layout.addWidget(scrollback_group)

        # Cursor settings
        cursor_group = QGroupBox("Cursor")
        cursor_layout = QFormLayout(cursor_group)

        self.cursor_style = QComboBox()
        self.cursor_style.addItems(["Block", "Underline", "Bar"])
        cursor_layout.addRow("Style:", self.cursor_style)

        layout.addWidget(cursor_group)

        # Selection
        selection_group = QGroupBox("Selection")
        selection_layout = QFormLayout(selection_group)

        self.paste_on_right_click = QCheckBox("Paste on right-click (like PuTTY)")
        self.paste_on_right_click.setChecked(True)
        selection_layout.addRow(self.paste_on_right_click)

        layout.addWidget(selection_group)
        layout.addStretch()

        return widget

    def _create_connection_tab(self) -> QWidget:
        """Create connection settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Default connection settings
        defaults_group = QGroupBox("Default Connection Settings")
        defaults_layout = QFormLayout(defaults_group)

        self.default_port = QSpinBox()
        self.default_port.setRange(1, 65535)
        self.default_port.setValue(22)
        defaults_layout.addRow("Default port:", self.default_port)

        self.default_timeout = QSpinBox()
        self.default_timeout.setRange(5, 300)
        self.default_timeout.setValue(30)
        self.default_timeout.setSuffix(" sec")
        defaults_layout.addRow("Connection timeout:", self.default_timeout)

        self.default_keepalive = QSpinBox()
        self.default_keepalive.setRange(0, 3600)
        self.default_keepalive.setValue(60)
        self.default_keepalive.setSuffix(" sec")
        defaults_layout.addRow("Keepalive interval:", self.default_keepalive)

        layout.addWidget(defaults_group)

        # Keyboard settings
        keyboard_group = QGroupBox("Keyboard")
        keyboard_layout = QFormLayout(keyboard_group)

        self.backspace_key = QComboBox()
        self.backspace_key.addItems(["Control-H", "Control-?"])
        keyboard_layout.addRow("Default Backspace:", self.backspace_key)

        layout.addWidget(keyboard_group)
        layout.addStretch()

        return widget

    def _create_authentik_tab(self) -> QWidget:
        """Create Authentik configuration tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Authentik settings
        auth_group = QGroupBox("Authentik OAuth2 Configuration")
        auth_layout = QFormLayout(auth_group)

        self.authentik_url = QLineEdit()
        self.authentik_url.setPlaceholderText("https://auth.example.com")
        auth_layout.addRow("Authentik URL:", self.authentik_url)

        self.authentik_client_id = QLineEdit()
        self.authentik_client_id.setPlaceholderText("ssh-terminal-manager")
        auth_layout.addRow("Client ID:", self.authentik_client_id)

        self.authentik_redirect_port = QSpinBox()
        self.authentik_redirect_port.setRange(1024, 65535)
        self.authentik_redirect_port.setValue(8400)
        auth_layout.addRow("Redirect Port:", self.authentik_redirect_port)

        layout.addWidget(auth_group)

        # LDAP settings (optional) - not yet implemented
        ldap_group = QGroupBox("LDAP Credential Provider (Optional)")
        ldap_layout = QFormLayout(ldap_group)

        self.ldap_enabled = QCheckBox("Enable LDAP credential lookup")
        self.ldap_enabled.setEnabled(False)
        self.ldap_enabled.setToolTip("Not yet implemented")
        ldap_layout.addRow(self.ldap_enabled)

        self.ldap_base_dn = QLineEdit()
        self.ldap_base_dn.setPlaceholderText("dc=example,dc=com")
        self.ldap_base_dn.setEnabled(False)
        self.ldap_base_dn.setToolTip("Not yet implemented")
        ldap_layout.addRow("Base DN:", self.ldap_base_dn)

        layout.addWidget(ldap_group)

        # Credential storage
        cred_group = QGroupBox("Credential Storage")
        cred_layout = QFormLayout(cred_group)

        self.use_dpapi = QCheckBox("Use Windows DPAPI for master key storage")
        self.use_dpapi.setChecked(True)
        cred_layout.addRow(self.use_dpapi)

        change_master_btn = QPushButton("Change Master Password...")
        change_master_btn.setEnabled(False)
        change_master_btn.setToolTip("Not yet implemented")
        cred_layout.addRow(change_master_btn)

        layout.addWidget(cred_group)
        layout.addStretch()

        return widget

    def _apply_color_scheme(self, scheme: str):
        """Apply a predefined color scheme."""
        schemes = {
            "Default Dark": {
                "fg": QColor(229, 229, 229),
                "bg": QColor(30, 30, 30),
            },
            "Solarized Dark": {
                "fg": QColor(131, 148, 150),
                "bg": QColor(0, 43, 54),
            },
            "Solarized Light": {
                "fg": QColor(101, 123, 131),
                "bg": QColor(253, 246, 227),
            },
            "Monokai": {
                "fg": QColor(248, 248, 242),
                "bg": QColor(39, 40, 34),
            },
            "One Dark": {
                "fg": QColor(171, 178, 191),
                "bg": QColor(40, 44, 52),
            },
            "Dracula": {
                "fg": QColor(248, 248, 242),
                "bg": QColor(40, 42, 54),
            }
        }

        if scheme in schemes:
            colors = schemes[scheme]
            self.fg_color.set_color(colors["fg"])
            self.bg_color.set_color(colors["bg"])

    def _load_settings(self):
        """Load settings from QSettings."""
        # Appearance
        font_family = self._settings.value("terminal/fontFamily", "Consolas")
        self.font_family.setCurrentFont(QFont(font_family))

        self.font_size.setValue(int(self._settings.value("terminal/fontSize", 11)))

        fg = self._settings.value("terminal/fgColor", "#e5e5e5")
        self.fg_color.set_color(QColor(fg))

        bg = self._settings.value("terminal/bgColor", "#1e1e1e")
        self.bg_color.set_color(QColor(bg))

        # Terminal
        self.scrollback_lines.setValue(
            int(self._settings.value("terminal/scrollbackLines", 10000))
        )

        cursor_style = self._settings.value("terminal/cursorStyle", "Block")
        idx = self.cursor_style.findText(cursor_style)
        if idx >= 0:
            self.cursor_style.setCurrentIndex(idx)

        self.paste_on_right_click.setChecked(
            self._settings.value("terminal/pasteOnRightClick", True, type=bool)
        )

        # Connection
        self.default_port.setValue(
            int(self._settings.value("connection/defaultPort", 22))
        )
        self.default_timeout.setValue(
            int(self._settings.value("connection/defaultTimeout", 30))
        )
        self.default_keepalive.setValue(
            int(self._settings.value("connection/defaultKeepalive", 60))
        )
        backspace_key = self._settings.value("connection/backspaceKey", "Control-H")
        self.backspace_key.setCurrentText(backspace_key)

        # Authentik
        self.authentik_url.setText(
            self._settings.value("authentik/url", "")
        )
        self.authentik_client_id.setText(
            self._settings.value("authentik/clientId", "")
        )
        self.authentik_redirect_port.setValue(
            int(self._settings.value("authentik/redirectPort", 8400))
        )
        self.use_dpapi.setChecked(
            self._settings.value("credentials/useDpapi", True, type=bool)
        )

    def _save_settings(self):
        """Save settings to QSettings and notify listeners."""
        # Appearance
        self._settings.setValue("terminal/fontFamily", self.font_family.currentFont().family())
        self._settings.setValue("terminal/fontSize", self.font_size.value())
        self._settings.setValue("terminal/fgColor", self.fg_color.get_color().name())
        self._settings.setValue("terminal/bgColor", self.bg_color.get_color().name())

        # Terminal
        self._settings.setValue("terminal/scrollbackLines", self.scrollback_lines.value())
        self._settings.setValue("terminal/cursorStyle", self.cursor_style.currentText())
        self._settings.setValue("terminal/pasteOnRightClick", self.paste_on_right_click.isChecked())

        # Connection
        self._settings.setValue("connection/defaultPort", self.default_port.value())
        self._settings.setValue("connection/defaultTimeout", self.default_timeout.value())
        self._settings.setValue("connection/defaultKeepalive", self.default_keepalive.value())
        self._settings.setValue("connection/backspaceKey", self.backspace_key.currentText())

        # Authentik
        self._settings.setValue("authentik/url", self.authentik_url.text())
        self._settings.setValue("authentik/clientId", self.authentik_client_id.text())
        self._settings.setValue("authentik/redirectPort", self.authentik_redirect_port.value())
        self._settings.setValue("credentials/useDpapi", self.use_dpapi.isChecked())

        # Sync to disk immediately
        self._settings.sync()

        # Notify listeners that settings have changed
        self.settings_applied.emit()

    def _save_and_close(self):
        """Save settings and close dialog."""
        self._save_settings()
        self.accept()

    def _restore_defaults(self):
        """Restore all settings to default values."""
        # Appearance defaults
        self.font_family.setCurrentFont(QFont("Consolas"))
        self.font_size.setValue(11)
        self.fg_color.set_color(QColor(229, 229, 229))
        self.bg_color.set_color(QColor(30, 30, 30))
        self.color_scheme.setCurrentText("Default Dark")

        # Terminal defaults
        self.scrollback_lines.setValue(10000)
        self.cursor_style.setCurrentText("Block")
        self.paste_on_right_click.setChecked(True)

        # Connection defaults
        self.default_port.setValue(22)
        self.default_timeout.setValue(30)
        self.default_keepalive.setValue(60)
        self.backspace_key.setCurrentText("Control-H")

        # Authentik defaults (keep empty for security)
        self.authentik_url.setText("")
        self.authentik_client_id.setText("")
        self.authentik_redirect_port.setValue(8400)
        self.use_dpapi.setChecked(True)

    @staticmethod
    def get_terminal_settings() -> dict:
        """Get terminal settings as dictionary."""
        settings = QSettings("SSHTerminalManager", "SSHTerminalManager")
        return {
            'font_family': settings.value("terminal/fontFamily", "Consolas"),
            'font_size': int(settings.value("terminal/fontSize", 11)),
            'fg_color': settings.value("terminal/fgColor", "#e5e5e5"),
            'bg_color': settings.value("terminal/bgColor", "#1e1e1e"),
            'scrollback_lines': int(settings.value("terminal/scrollbackLines", 10000)),
            'cursor_style': settings.value("terminal/cursorStyle", "Block"),
            'paste_on_right_click': settings.value("terminal/pasteOnRightClick", True, type=bool),
        }

    @staticmethod
    def get_connection_settings() -> dict:
        """Get connection settings as dictionary."""
        settings = QSettings("SSHTerminalManager", "SSHTerminalManager")
        return {
            'default_port': int(settings.value("connection/defaultPort", 22)),
            'default_timeout': int(settings.value("connection/defaultTimeout", 30)),
            'default_keepalive': int(settings.value("connection/defaultKeepalive", 60)),
            'backspace_key': settings.value("connection/backspaceKey", "Control-H"),
        }

    @staticmethod
    def get_authentik_settings() -> dict:
        """Get Authentik settings as dictionary."""
        settings = QSettings("SSHTerminalManager", "SSHTerminalManager")
        return {
            'url': settings.value("authentik/url", ""),
            'client_id': settings.value("authentik/clientId", ""),
            'redirect_port': int(settings.value("authentik/redirectPort", 8400)),
        }
