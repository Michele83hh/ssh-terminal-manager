"""
Main application window.
"""
import json
from pathlib import Path
from typing import Optional, Dict

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QToolBar, QStatusBar, QMenuBar, QMenu, QMessageBox,
    QInputDialog, QLineEdit, QDialog, QLabel, QPushButton,
    QFormLayout, QSpinBox, QComboBox, QDialogButtonBox, QTextEdit,
    QStackedWidget
)
from PyQt6.QtCore import Qt, QSettings, pyqtSignal, QSize
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QFont

from .connection_list import ConnectionListWidget
from .terminal_window import TerminalWindow
from .terminal_tabs import TerminalTabWidget, TerminalTab
from .settings_dialog import SettingsDialog
from .key_manager import KeyManagerDialog
from ..ssh.manager import ConnectionManager, ActiveSession
from ..ssh.session import HostKeyStatus
from ..storage.database import Database, Connection
from ..storage.encryption import EncryptionManager
from ..resources import get_icon


class HostKeyVerificationDialog(QDialog):
    """
    Dialog for SSH host key verification.

    Warns user about new or changed host keys to prevent MITM attacks.
    """

    def __init__(
        self,
        parent,
        hostname: str,
        port: int,
        key_type: str,
        fingerprint: str,
        status: HostKeyStatus
    ):
        super().__init__(parent)

        is_changed = status == HostKeyStatus.CHANGED

        if is_changed:
            self.setWindowTitle("WARNING: Host Key Changed!")
        else:
            self.setWindowTitle("New Host Key")

        self.setMinimumWidth(500)
        self.setModal(True)

        layout = QVBoxLayout(self)

        # Warning message
        if is_changed:
            warning = QLabel(
                "<b style='color: red; font-size: 14pt;'>⚠️ WARNING: HOST KEY HAS CHANGED!</b>"
            )
            warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(warning)

            explanation = QLabel(
                "The host key for this server has changed since your last connection.\n"
                "This could indicate:\n"
                "• A man-in-the-middle attack (someone intercepting your connection)\n"
                "• The server was reinstalled or its keys were regenerated\n\n"
                "If you did not expect this change, DO NOT CONNECT!"
            )
            explanation.setWordWrap(True)
            explanation.setStyleSheet("background-color: #fff3cd; padding: 10px; border-radius: 5px;")
            layout.addWidget(explanation)
        else:
            info = QLabel(
                "<b>Connecting to a new host</b>\n\n"
                "The authenticity of this host can't be established.\n"
                "Please verify the fingerprint with your system administrator."
            )
            info.setWordWrap(True)
            layout.addWidget(info)

        # Host information
        info_box = QTextEdit()
        info_box.setReadOnly(True)
        info_box.setMaximumHeight(120)
        info_box.setFont(QFont("Consolas", 10))
        info_box.setPlainText(
            f"Host: {hostname}:{port}\n"
            f"Key Type: {key_type}\n"
            f"Fingerprint:\n{fingerprint}"
        )
        layout.addWidget(info_box)

        # Buttons
        button_layout = QHBoxLayout()

        if is_changed:
            accept_btn = QPushButton("Accept Risk and Connect")
            accept_btn.setStyleSheet("background-color: #dc3545; color: white;")
        else:
            accept_btn = QPushButton("Accept and Connect")
            accept_btn.setStyleSheet("background-color: #28a745; color: white;")

        accept_btn.clicked.connect(self.accept)

        reject_btn = QPushButton("Cancel")
        reject_btn.clicked.connect(self.reject)
        reject_btn.setDefault(True)  # Default to cancel for safety

        button_layout.addWidget(reject_btn)
        button_layout.addWidget(accept_btn)
        layout.addLayout(button_layout)


class QuickConnectDialog(QDialog):
    """Dialog for quick SSH connection without saving."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Quick Connect")
        self.setMinimumWidth(350)

        layout = QFormLayout(self)

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("hostname or IP")
        layout.addRow("Host:", self.host_input)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        layout.addRow("Port:", self.port_input)

        self.username_input = QLineEdit()
        layout.addRow("Username:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Password:", self.password_input)

        self.auth_type = QComboBox()
        self.auth_type.addItems(["Password", "SSH Key"])
        self.auth_type.currentIndexChanged.connect(self._on_auth_type_changed)
        layout.addRow("Auth Type:", self.auth_type)

        self.key_path_input = QLineEdit()
        self.key_path_input.setEnabled(False)
        layout.addRow("Key Path:", self.key_path_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _on_auth_type_changed(self, index: int):
        is_key = index == 1
        self.key_path_input.setEnabled(is_key)
        self.password_input.setEnabled(not is_key)

    def get_connection_data(self) -> tuple:
        """Get connection data from dialog."""
        return (
            self.host_input.text(),
            self.username_input.text(),
            self.password_input.text() if self.auth_type.currentIndex() == 0 else None,
            self.port_input.value(),
            self.key_path_input.text() if self.auth_type.currentIndex() == 1 else None
        )


class ConnectionDialog(QDialog):
    """Dialog for adding/editing connections."""

    def __init__(self, parent=None, connection: Optional[Connection] = None, groups: list = None):
        super().__init__(parent)
        self.connection = connection
        self.groups = groups or ['Default']

        self.setWindowTitle("Edit Connection" if connection else "New Connection")
        self.setMinimumWidth(450)

        # Load default values from global settings
        from .settings_dialog import SettingsDialog
        conn_defaults = SettingsDialog.get_connection_settings()

        layout = QFormLayout(self)

        # Connection settings
        layout.addRow(QLabel("<b>Connection</b>"))

        self.name_input = QLineEdit()
        layout.addRow("Name:", self.name_input)

        self.host_input = QLineEdit()
        layout.addRow("Host:", self.host_input)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(conn_defaults.get('default_port', 22))
        layout.addRow("Port:", self.port_input)

        self.username_input = QLineEdit()
        layout.addRow("Username:", self.username_input)

        self.group_input = QComboBox()
        self.group_input.setEditable(True)
        self.group_input.addItems(self.groups)
        layout.addRow("Group:", self.group_input)

        self.credential_mode = QComboBox()
        self.credential_mode.addItems(["Local (encrypted)", "Authentik/LDAP"])
        layout.addRow("Credentials:", self.credential_mode)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Password:", self.password_input)

        self.key_path_input = QLineEdit()
        layout.addRow("SSH Key:", self.key_path_input)

        self.keepalive_input = QSpinBox()
        self.keepalive_input.setRange(0, 3600)
        self.keepalive_input.setValue(conn_defaults.get('default_keepalive', 60))
        self.keepalive_input.setSuffix(" sec")
        layout.addRow("Keepalive:", self.keepalive_input)

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(5, 300)
        self.timeout_input.setValue(conn_defaults.get('default_timeout', 30))
        self.timeout_input.setSuffix(" sec")
        layout.addRow("Timeout:", self.timeout_input)

        # Terminal settings (per connection)
        layout.addRow(QLabel(""))  # Spacer
        layout.addRow(QLabel("<b>Terminal Settings</b>"))

        self.backspace_key = QComboBox()
        self.backspace_key.addItems(["Default (from global settings)", "Control-H (Cisco, etc.)", "Control-? / DEL (Linux)"])
        layout.addRow("Backspace:", self.backspace_key)

        self.delete_key = QComboBox()
        self.delete_key.addItems(["Same as Backspace (Linux/SSH prompts)", "Ctrl+D forward delete (Cisco/bash)"])
        layout.addRow("Delete:", self.delete_key)

        self.term_type = QComboBox()
        self.term_type.addItems(["xterm-256color", "xterm", "vt100", "linux", "ansi"])
        layout.addRow("Terminal Type:", self.term_type)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        # Populate if editing
        if connection:
            self.name_input.setText(connection.name)
            self.host_input.setText(connection.host)
            self.port_input.setValue(connection.port)
            self.username_input.setText(connection.username)
            self.group_input.setCurrentText(connection.group_name)
            self.credential_mode.setCurrentIndex(
                0 if connection.credential_mode == 'local' else 1
            )
            self.key_path_input.setText(connection.ssh_key_path or "")
            self.keepalive_input.setValue(connection.keepalive_interval)
            self.timeout_input.setValue(connection.timeout)

            # Terminal settings
            term_settings = connection.terminal_settings or {}
            backspace = term_settings.get('backspace_key', 'default')
            if backspace == 'Control-H':
                self.backspace_key.setCurrentIndex(1)
            elif backspace == 'Control-?':
                self.backspace_key.setCurrentIndex(2)
            else:
                self.backspace_key.setCurrentIndex(0)

            delete_key = term_settings.get('delete_key', 'same_as_backspace')
            if delete_key == 'ctrl_d':
                self.delete_key.setCurrentIndex(1)
            else:
                self.delete_key.setCurrentIndex(0)

            term_type = term_settings.get('term_type', 'xterm-256color')
            idx = self.term_type.findText(term_type)
            if idx >= 0:
                self.term_type.setCurrentIndex(idx)

    def get_connection(self) -> Connection:
        """Get connection from dialog data."""
        conn = self.connection or Connection()
        conn.name = self.name_input.text()
        conn.host = self.host_input.text()
        conn.port = self.port_input.value()
        conn.username = self.username_input.text()
        conn.group_name = self.group_input.currentText()
        conn.credential_mode = 'local' if self.credential_mode.currentIndex() == 0 else 'authentik'
        conn.ssh_key_path = self.key_path_input.text() or None
        conn.keepalive_interval = self.keepalive_input.value()
        conn.timeout = self.timeout_input.value()

        # Terminal settings
        backspace_idx = self.backspace_key.currentIndex()
        if backspace_idx == 1:
            backspace_val = 'Control-H'
        elif backspace_idx == 2:
            backspace_val = 'Control-?'
        else:
            backspace_val = 'default'

        delete_val = 'ctrl_d' if self.delete_key.currentIndex() == 1 else 'same_as_backspace'

        conn.terminal_settings = {
            'backspace_key': backspace_val,
            'delete_key': delete_val,
            'term_type': self.term_type.currentText()
        }

        return conn

    def get_password(self) -> Optional[str]:
        """Get password if entered."""
        pwd = self.password_input.text()
        return pwd if pwd else None


class MainWindow(QMainWindow):
    """Main application window."""

    session_started = pyqtSignal(int)
    session_ended = pyqtSignal(int, str)

    def __init__(
        self,
        database: Database,
        encryption: EncryptionManager,
        connection_manager: ConnectionManager,
        authentik=None  # Optional, for future use
    ):
        super().__init__()

        self.database = database
        self.encryption = encryption
        self.connection_manager = connection_manager

        self._terminal_windows: Dict[int, TerminalWindow] = {}
        self._settings = QSettings("SSHTerminalManager", "SSHTerminalManager")

        self._setup_ui()
        self._setup_menus()
        self._setup_toolbar()
        self._setup_connections()
        self._load_settings()

        # Connect manager callbacks
        self.connection_manager.on_session_start = self._on_session_start
        self.connection_manager.on_session_end = self._on_session_end
        self.connection_manager.on_host_key_verify = self._on_host_key_verify

    def _on_host_key_verify(
        self,
        hostname: str,
        port: int,
        key_type: str,
        fingerprint: str,
        status: HostKeyStatus
    ) -> bool:
        """
        Handle SSH host key verification.

        Shows dialog to user for new or changed host keys.
        Returns True to accept, False to reject.
        """
        dialog = HostKeyVerificationDialog(
            self, hostname, port, key_type, fingerprint, status
        )
        return dialog.exec() == QDialog.DialogCode.Accepted

    def _setup_ui(self):
        """Setup main UI layout."""
        self.setWindowTitle("SSH Terminal Manager")
        self.setMinimumSize(1000, 700)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar toggle button (always visible)
        self._sidebar_toggle = QPushButton()
        self._sidebar_toggle.setFixedWidth(20)
        self._sidebar_toggle.setText("◀")  # Unicode chevron
        self._sidebar_toggle.setToolTip("Hide sidebar (Ctrl+B)")
        self._sidebar_toggle.setFlat(True)
        self._sidebar_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._sidebar_toggle.clicked.connect(self._toggle_sidebar)
        self._sidebar_toggle.setStyleSheet("""
            QPushButton {
                background-color: #252526;
                border: none;
                border-right: 1px solid #3c3c3c;
                border-radius: 0;
                padding: 0;
                font-size: 10px;
                color: #808080;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
                color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #2a82da;
            }
        """)
        layout.addWidget(self._sidebar_toggle)

        # Splitter for resizable sidebar
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(3)
        self._splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #3c3c3c;
            }
            QSplitter::handle:hover {
                background-color: #2a82da;
            }
        """)

        # Connection list (sidebar)
        self.connection_list = ConnectionListWidget(self.database)
        self.connection_list.setMinimumWidth(280)
        self._splitter.addWidget(self.connection_list)

        # Track sidebar state
        self._sidebar_visible = True
        self._sidebar_width = 350

        # Main area with stacked widget (welcome screen / terminal tabs)
        self._main_stack = QStackedWidget()

        # Welcome screen (shown when no tabs are open)
        self._welcome_widget = self._create_welcome_widget()
        self._main_stack.addWidget(self._welcome_widget)

        # Terminal tabs
        self._terminal_tabs = TerminalTabWidget()
        self._terminal_tabs.tab_count_changed.connect(self._on_tab_count_changed)
        self._terminal_tabs.all_tabs_closed.connect(self._show_welcome)
        self._main_stack.addWidget(self._terminal_tabs)

        self._splitter.addWidget(self._main_stack)

        # Set initial sizes (sidebar: 350px, main: rest)
        self._splitter.setSizes([350, 650])
        self._splitter.setStretchFactor(0, 0)
        self._splitter.setStretchFactor(1, 1)

        layout.addWidget(self._splitter, 1)

        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        self._update_status()

    def _toggle_sidebar(self):
        """Toggle sidebar visibility."""
        if self._sidebar_visible:
            # Hide sidebar - save current width first
            sizes = self._splitter.sizes()
            if sizes[0] > 0:
                self._sidebar_width = sizes[0]
            self._splitter.setSizes([0, sum(sizes)])
            self._sidebar_toggle.setText("▶")  # Point right when collapsed
            self._sidebar_toggle.setToolTip("Show sidebar (Ctrl+B)")
            self._sidebar_visible = False
        else:
            # Show sidebar
            sizes = self._splitter.sizes()
            total = sum(sizes)
            self._splitter.setSizes([self._sidebar_width, total - self._sidebar_width])
            self._sidebar_toggle.setText("◀")  # Point left when expanded
            self._sidebar_toggle.setToolTip("Hide sidebar (Ctrl+B)")
            self._sidebar_visible = True

    def _create_welcome_widget(self) -> QWidget:
        """Create the welcome screen widget."""
        widget = QWidget()
        widget.setObjectName("welcomeWidget")

        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Terminal icon
        icon_label = QLabel()
        icon = get_icon("terminal", "#2a82da")
        icon_label.setPixmap(icon.pixmap(QSize(64, 64)))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)

        layout.addSpacing(20)

        # Title
        title = QLabel("SSH Terminal Manager")
        title.setObjectName("welcomeTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Select a connection from the list or create a new one")
        subtitle.setObjectName("welcomeSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        layout.addSpacing(30)

        # Quick actions
        btn_layout = QHBoxLayout()
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_layout.setSpacing(16)

        quick_connect_btn = QPushButton(get_icon("connect"), " Quick Connect")
        quick_connect_btn.setObjectName("connectButton")
        quick_connect_btn.clicked.connect(self._quick_connect)
        btn_layout.addWidget(quick_connect_btn)

        new_conn_btn = QPushButton(get_icon("add"), " New Connection")
        new_conn_btn.clicked.connect(self._new_connection)
        btn_layout.addWidget(new_conn_btn)

        layout.addLayout(btn_layout)

        layout.addStretch()

        return widget

    def _show_welcome(self):
        """Show welcome screen."""
        self._main_stack.setCurrentWidget(self._welcome_widget)

    def _show_terminals(self):
        """Show terminal tabs."""
        self._main_stack.setCurrentWidget(self._terminal_tabs)

    def _on_tab_count_changed(self, count: int):
        """Handle tab count change."""
        if count > 0:
            self._show_terminals()
        self._update_status()

    def _setup_menus(self):
        """Setup menu bar with icons."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        new_conn_action = QAction(get_icon("add"), "&New Connection...", self)
        new_conn_action.setShortcut(QKeySequence("Ctrl+Shift+N"))
        new_conn_action.triggered.connect(self._new_connection)
        file_menu.addAction(new_conn_action)

        quick_connect_action = QAction(get_icon("connect"), "&Quick Connect...", self)
        quick_connect_action.setShortcut(QKeySequence("Ctrl+N"))
        quick_connect_action.triggered.connect(self._quick_connect)
        file_menu.addAction(quick_connect_action)

        file_menu.addSeparator()

        import_action = QAction(get_icon("import"), "&Import Connections...", self)
        import_action.triggered.connect(self._import_connections)
        file_menu.addAction(import_action)

        export_action = QAction(get_icon("export"), "&Export Connections...", self)
        export_action.triggered.connect(self._export_connections)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction(get_icon("close"), "E&xit", self)
        exit_action.setShortcut(QKeySequence("Alt+F4"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("&Edit")

        settings_action = QAction(get_icon("settings"), "&Settings...", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self._open_settings)
        edit_menu.addAction(settings_action)

        # Tools menu
        tools_menu = menubar.addMenu("&Tools")

        key_manager_action = QAction(get_icon("key"), "SSH &Key Manager...", self)
        key_manager_action.triggered.connect(self._open_key_manager)
        tools_menu.addAction(key_manager_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        toggle_sidebar_action = QAction(get_icon("sidebar"), "&Toggle Sidebar", self)
        toggle_sidebar_action.setShortcut(QKeySequence("Ctrl+B"))
        toggle_sidebar_action.triggered.connect(self._toggle_sidebar)
        view_menu.addAction(toggle_sidebar_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_toolbar(self):
        """Setup toolbar with icons."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(20, 20))
        self.addToolBar(toolbar)

        # Quick connect
        quick_connect_action = QAction(get_icon("connect"), "Quick Connect", self)
        quick_connect_action.setToolTip("Quick Connect (Ctrl+N)")
        quick_connect_action.triggered.connect(self._quick_connect)
        toolbar.addAction(quick_connect_action)

        # New connection
        new_conn_action = QAction(get_icon("add"), "New Connection", self)
        new_conn_action.setToolTip("New Connection (Ctrl+Shift+N)")
        new_conn_action.triggered.connect(self._new_connection)
        toolbar.addAction(new_conn_action)

        toolbar.addSeparator()

        # Refresh
        refresh_action = QAction(get_icon("refresh"), "Refresh", self)
        refresh_action.setToolTip("Refresh connection list")
        refresh_action.triggered.connect(self.connection_list.refresh)
        toolbar.addAction(refresh_action)

        toolbar.addSeparator()

        # Settings
        settings_action = QAction(get_icon("settings"), "Settings", self)
        settings_action.setToolTip("Settings (Ctrl+,)")
        settings_action.triggered.connect(self._open_settings)
        toolbar.addAction(settings_action)

        # SSH Key Manager
        key_manager_action = QAction(get_icon("key"), "SSH Keys", self)
        key_manager_action.setToolTip("SSH Key Manager")
        key_manager_action.triggered.connect(self._open_key_manager)
        toolbar.addAction(key_manager_action)

    def _setup_connections(self):
        """Connect signals."""
        self.connection_list.connection_activated.connect(self._connect_to)
        self.connection_list.connection_edit_requested.connect(self._edit_connection)
        self.connection_list.connection_delete_requested.connect(self._delete_connection)
        self.connection_list.connection_duplicate_requested.connect(self._duplicate_connection)
        self.connection_list.new_connection_requested.connect(self._new_connection)
        self.connection_list.settings_requested.connect(self._open_settings)

    def _load_settings(self):
        """Load window settings."""
        geometry = self._settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

        state = self._settings.value("windowState")
        if state:
            self.restoreState(state)

    def _save_settings(self):
        """Save window settings."""
        self._settings.setValue("geometry", self.saveGeometry())
        self._settings.setValue("windowState", self.saveState())

    def _update_status(self):
        """Update status bar with detailed connection info."""
        active_sessions = self.connection_manager.get_active_sessions()
        active_count = len(active_sessions)
        conn_count = len(self.database.get_all_connections())
        tab_count = self._terminal_tabs.count() if hasattr(self, '_terminal_tabs') else 0

        # Build status message
        parts = [f"Saved: {conn_count}"]

        if active_count > 0:
            parts.append(f"Active: {active_count}")

        if tab_count > 0:
            parts.append(f"Tabs: {tab_count}")

        status = " | ".join(parts)
        self.statusBar.showMessage(status)

    def _quick_connect(self):
        """Show quick connect dialog."""
        dialog = QuickConnectDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            host, username, password, port, key_path = dialog.get_connection_data()

            if not host or not username:
                QMessageBox.warning(self, "Error", "Host and username are required")
                return

            session_id = self.connection_manager.quick_connect(
                host=host,
                username=username,
                password=password,
                port=port,
                key_path=key_path
            )

            if session_id is None:
                error_msg = self.connection_manager.get_last_error()
                if error_msg:
                    QMessageBox.critical(
                        self,
                        "Connection Failed",
                        f"Could not connect to {host}\n\n{error_msg}"
                    )
                else:
                    QMessageBox.critical(self, "Connection Failed", "Could not establish SSH connection")

    def _new_connection(self):
        """Show new connection dialog."""
        groups = [g.name for g in self.database.get_all_groups()]
        dialog = ConnectionDialog(self, groups=groups)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            connection = dialog.get_connection()
            password = dialog.get_password()

            self.connection_manager.save_connection(connection, password)
            self.connection_list.refresh()
            self._update_status()

    def _edit_connection(self, connection_id: int):
        """Edit existing connection."""
        connection = self.database.get_connection(connection_id)
        if not connection:
            return

        groups = [g.name for g in self.database.get_all_groups()]
        dialog = ConnectionDialog(self, connection=connection, groups=groups)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated = dialog.get_connection()
            password = dialog.get_password()

            self.connection_manager.save_connection(updated, password)
            self.connection_list.refresh()

    def _delete_connection(self, connection_id: int):
        """Delete connection after confirmation."""
        connection = self.database.get_connection(connection_id)
        if not connection:
            return

        result = QMessageBox.question(
            self,
            "Delete Connection",
            f"Are you sure you want to delete '{connection.name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result == QMessageBox.StandardButton.Yes:
            self.connection_manager.delete_connection(connection_id)
            self.connection_list.refresh()
            self._update_status()

    def _duplicate_connection(self, connection_id: int):
        """Duplicate a connection."""
        new_id = self.connection_manager.duplicate_connection(connection_id)
        if new_id:
            self.connection_list.refresh()
            self._update_status()

    def _connect_to(self, connection_id: int):
        """Connect to a saved connection."""
        connection = self.database.get_connection(connection_id)
        if not connection:
            return

        # Check if password is needed
        password = None
        if connection.credential_mode == 'local' and not connection.encrypted_password and not connection.ssh_key_path:
            password, ok = QInputDialog.getText(
                self,
                "Password Required",
                f"Enter password for {connection.username}@{connection.host}:",
                QLineEdit.EchoMode.Password
            )
            if not ok:
                return

        session_id = self.connection_manager.start_session(connection, password)

        if session_id is None:
            error_msg = self.connection_manager.get_last_error()
            if error_msg:
                QMessageBox.critical(
                    self,
                    "Connection Failed",
                    f"Could not connect to {connection.host}\n\n{error_msg}"
                )
            else:
                QMessageBox.critical(
                    self,
                    "Connection Failed",
                    f"Could not connect to {connection.host}"
                )

    def _on_session_start(self, session_id: int, active_session: ActiveSession):
        """Handle new session started."""
        # Create terminal tab
        tab = self._terminal_tabs.add_terminal(
            session_id=session_id,
            session=active_session.session,
            connection=active_session.connection
        )

        tab.closed.connect(lambda: self._on_terminal_closed(session_id))
        self._terminal_windows[session_id] = tab

        self._show_terminals()
        self._update_status()
        self.session_started.emit(session_id)

    def _on_session_end(self, session_id: int, reason: str):
        """Handle session ended."""
        if session_id in self._terminal_windows:
            terminal = self._terminal_windows[session_id]
            terminal.set_disconnected(reason)

        self._update_status()
        self.session_ended.emit(session_id, reason)

    def _on_terminal_closed(self, session_id: int):
        """Handle terminal window closed."""
        if session_id in self._terminal_windows:
            del self._terminal_windows[session_id]

        # Close session if still active
        self.connection_manager.close_session(session_id)
        self._update_status()

    def _open_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self)
        # Connect signal to update all open terminal windows
        dialog.settings_applied.connect(self._apply_settings_to_terminals)
        dialog.exec()
        # Apply to all terminals on close
        self._apply_settings_to_terminals()

    def _apply_settings_to_terminals(self):
        """Apply settings to all open terminal tabs."""
        self._terminal_tabs.apply_settings_to_all()

    def _open_key_manager(self):
        """Open SSH key manager."""
        dialog = KeyManagerDialog(self)
        dialog.exec()

    def _import_connections(self):
        """Import connections from file."""
        from ..utils.export_import import ExportImport
        ExportImport.import_dialog(self, self.database)
        self.connection_list.refresh()
        self._update_status()

    def _export_connections(self):
        """Export connections to file."""
        from ..utils.export_import import ExportImport
        ExportImport.export_dialog(self, self.database)

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About SSH Terminal Manager",
            "SSH Terminal Manager v1.0\n\n"
            "A secure SSH connection manager with Authentik integration.\n\n"
            "Built with PyQt6 and Paramiko"
        )

    def closeEvent(self, event):
        """Handle window close."""
        # Close all terminal tabs
        self._terminal_tabs.close_all_tabs()
        self._terminal_windows.clear()

        # Close all sessions
        self.connection_manager.close_all_sessions()

        self._save_settings()
        event.accept()
