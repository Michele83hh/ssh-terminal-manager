"""
Tab-based terminal container for the main window.
"""
from typing import Optional, Dict

from PyQt6.QtWidgets import (
    QTabWidget, QWidget, QVBoxLayout, QMenu, QMessageBox,
    QToolBar, QLabel, QHBoxLayout, QPushButton, QMainWindow
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QCloseEvent

from .terminal_window import TerminalWidget, SessionBridge
from ..ssh.session import SSHSession
from ..storage.database import Connection
from ..resources import get_icon


class TerminalTab(QWidget):
    """
    A single terminal tab containing the terminal widget and controls.
    """

    closed = pyqtSignal()
    session_timeout = pyqtSignal()
    title_changed = pyqtSignal(str)

    # Default inactivity timeout: 30 minutes (in milliseconds)
    DEFAULT_TIMEOUT_MS = 30 * 60 * 1000

    def __init__(
        self,
        session_id: int,
        session: SSHSession,
        connection: Connection,
        parent=None,
        timeout_minutes: int = 30
    ):
        super().__init__(parent)

        self.session_id = session_id
        self.session = session
        self.connection = connection
        self._disconnected = False

        self._bridge = SessionBridge()

        # Inactivity timeout
        self._timeout_ms = timeout_minutes * 60 * 1000 if timeout_minutes > 0 else 0
        self._inactivity_timer: Optional[QTimer] = None

        self._setup_ui()
        self._setup_session()
        self._setup_inactivity_timer()

    def _setup_ui(self):
        """Setup tab UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Terminal widget with connection-specific settings
        self.terminal = TerminalWidget(
            parent=self,
            connection_settings=self.connection.terminal_settings
        )
        layout.addWidget(self.terminal)

        # Status bar at bottom of tab
        self._status_bar = QWidget()
        status_layout = QHBoxLayout(self._status_bar)
        status_layout.setContentsMargins(8, 4, 8, 4)
        status_layout.setSpacing(8)

        self._status_label = QLabel("Connected")
        self._status_label.setProperty("status", "connected")
        status_layout.addWidget(self._status_label)

        status_layout.addStretch()

        self._host_label = QLabel(f"{self.connection.username}@{self.connection.host}:{self.connection.port}")
        self._host_label.setProperty("subheading", "true")
        status_layout.addWidget(self._host_label)

        layout.addWidget(self._status_bar)

    def _setup_session(self):
        """Connect session events to terminal."""
        self._connect_terminal_signals()

        self._bridge.data_received.connect(self._on_data_received, Qt.ConnectionType.QueuedConnection)
        self._bridge.error_received.connect(self._show_error, Qt.ConnectionType.QueuedConnection)
        self._bridge.disconnected.connect(self._on_disconnected, Qt.ConnectionType.QueuedConnection)

        self.session.on_data = lambda data: self._bridge.data_received.emit(data)
        self.session.on_error = lambda msg: self._bridge.error_received.emit(msg)
        self.session.on_disconnect = lambda reason: self._bridge.disconnected.emit(reason)

        QTimer.singleShot(100, self._resize_pty)

    def _connect_terminal_signals(self):
        """Connect terminal widget signals."""
        self.terminal.data_ready.connect(self._on_terminal_input)

    def create_fresh_terminal(self) -> dict:
        """Create a fresh terminal widget and return saved state from old one.

        This is used during detach/reattach to avoid reparenting issues.
        Returns the state that should be restored after reparenting.
        """
        # Save state from current terminal
        state = self.terminal.get_full_state()

        # Disconnect old terminal
        try:
            self.terminal.data_ready.disconnect(self._on_terminal_input)
        except TypeError:
            pass  # Already disconnected

        # Remove old terminal from layout
        layout = self.layout()
        layout.removeWidget(self.terminal)
        old_terminal = self.terminal

        # Create new terminal widget
        self.terminal = TerminalWidget(
            parent=self,
            connection_settings=self.connection.terminal_settings
        )

        # Skip display updates until state is restored
        self.terminal.set_skip_display_updates(True)

        # Insert at position 0 (before status bar)
        layout.insertWidget(0, self.terminal)

        # Connect new terminal signals
        self._connect_terminal_signals()

        # Schedule old terminal for deletion
        old_terminal.deleteLater()

        return state

    def restore_terminal_state(self, state: dict):
        """Restore terminal state after reparenting."""
        self.terminal.restore_full_state(state)

    def _on_data_received(self, data: bytes):
        """Handle data received from session."""
        self._reset_inactivity_timer()
        self.terminal.append_data(data)

    def _on_terminal_input(self, data: bytes):
        """Handle input from terminal widget."""
        if not self._disconnected:
            self._reset_inactivity_timer()
            self.session.send(data)

    def _show_error(self, message: str):
        """Show error message."""
        self._update_status(f"Error: {message}", "error")

    def _on_disconnected(self, reason: str):
        """Handle disconnection."""
        self.set_disconnected(reason)

    def _update_status(self, message: str, status_type: str = "connected"):
        """Update status bar."""
        self._status_label.setText(message)
        self._status_label.setProperty("status", status_type)
        # Force style refresh
        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _resize_pty(self):
        """Resize PTY to match terminal size."""
        cols, rows = self.terminal.get_size()
        if not self._disconnected:
            self.session.resize_pty(cols, rows)

    def disconnect_session(self):
        """Disconnect the session."""
        self.session.disconnect()
        self.set_disconnected("Disconnected by user")

    def reconnect(self):
        """Reconnect the session."""
        if not self._disconnected:
            self.session.disconnect()

        self._update_status("Reconnecting...", "disconnected")
        self.terminal.setPlainText("")
        self.terminal._screen.reset()

        # Get terminal type from connection settings
        term_type = self.connection.terminal_settings.get('term_type', 'xterm-256color') if self.connection.terminal_settings else 'xterm-256color'

        # Reconnect
        if self.session.connect():
            cols, rows = self.terminal.get_size()
            if self.session.open_shell(cols, rows, term_type):
                self._disconnected = False
                self._update_status("Connected", "connected")
                self.title_changed.emit(self.connection.name)
            else:
                self.set_disconnected("Failed to open shell")
        else:
            self.set_disconnected("Reconnection failed")

    def clear_terminal(self):
        """Clear terminal screen."""
        self.terminal.setPlainText("")
        self.terminal._screen.reset()

    def set_disconnected(self, reason: str):
        """Mark session as disconnected."""
        self._disconnected = True
        self._update_status(f"Disconnected: {reason}", "disconnected")
        self.title_changed.emit(f"[X] {self.connection.name}")

    def is_connected(self) -> bool:
        """Check if session is connected."""
        return not self._disconnected

    def resizeEvent(self, event):
        """Handle resize."""
        super().resizeEvent(event)
        QTimer.singleShot(50, self._resize_pty)

    def _setup_inactivity_timer(self):
        """Setup inactivity timeout timer."""
        if self._timeout_ms > 0:
            self._inactivity_timer = QTimer(self)
            self._inactivity_timer.setSingleShot(True)
            self._inactivity_timer.timeout.connect(self._on_inactivity_timeout)
            self._reset_inactivity_timer()

    def _reset_inactivity_timer(self):
        """Reset inactivity timer."""
        if self._inactivity_timer and self._timeout_ms > 0 and not self._disconnected:
            self._inactivity_timer.start(self._timeout_ms)

    def _stop_inactivity_timer(self):
        """Stop inactivity timer."""
        if self._inactivity_timer:
            self._inactivity_timer.stop()

    def _on_inactivity_timeout(self):
        """Handle inactivity timeout."""
        if not self._disconnected:
            from ..utils.audit_log import AuditLogger, AuditEventType
            audit = AuditLogger.get_instance()
            audit.log_session_event(
                AuditEventType.SESSION_TIMEOUT,
                session_id=self.session_id,
                host=self.connection.host,
                username=self.connection.username,
                reason="Inactivity timeout"
            )

            self.session.disconnect()
            self.set_disconnected("Session timed out due to inactivity")
            self.session_timeout.emit()

    def close_tab(self):
        """Close this tab."""
        self._stop_inactivity_timer()
        if not self._disconnected:
            self.session.disconnect()
        self.closed.emit()


class DetachedTerminalWindow(QMainWindow):
    """
    Standalone window for a detached terminal tab.
    """

    reattach_requested = pyqtSignal(int)  # session_id
    window_closed = pyqtSignal(int)  # session_id

    def __init__(self, tab: TerminalTab, parent=None):
        super().__init__(parent)

        self.tab = tab
        self.session_id = tab.session_id

        self._setup_ui()

    def _setup_ui(self):
        """Setup window UI."""
        self.setWindowTitle(f"{self.tab.connection.name} - SSH Terminal")
        self.resize(800, 600)

        # Create a container widget with layout
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.tab)
        self.setCentralWidget(container)
        self._container = container

        # Ensure tab and terminal are visible
        self.tab.show()
        self.tab.terminal.show()

        # Create menu bar
        menubar = self.menuBar()

        # Session menu
        session_menu = menubar.addMenu("Session")

        reconnect_action = session_menu.addAction(get_icon("refresh"), "Reconnect")
        reconnect_action.triggered.connect(self.tab.reconnect)

        disconnect_action = session_menu.addAction(get_icon("disconnect"), "Disconnect")
        disconnect_action.triggered.connect(self.tab.disconnect_session)

        session_menu.addSeparator()

        reattach_action = session_menu.addAction("Reattach to Main Window")
        reattach_action.triggered.connect(self._request_reattach)

        session_menu.addSeparator()

        close_action = session_menu.addAction(get_icon("close"), "Close")
        close_action.triggered.connect(self.close)

        # View menu
        view_menu = menubar.addMenu("View")

        clear_action = view_menu.addAction("Clear Terminal")
        clear_action.triggered.connect(self.tab.clear_terminal)

        # Update title when connection state changes
        self.tab.title_changed.connect(self._update_title)

    def _update_title(self, title: str):
        """Update window title."""
        self.setWindowTitle(f"{title} - SSH Terminal")

    def _request_reattach(self):
        """Request to reattach this terminal to the main window."""
        self.reattach_requested.emit(self.session_id)

    def closeEvent(self, event: QCloseEvent):
        """Handle window close."""
        # If tab was taken for reattach, just close the window
        if self.tab is None:
            event.accept()
            return

        if self.tab.is_connected():
            result = QMessageBox.question(
                self,
                "Close Session",
                f"Close connection to {self.tab.connection.name}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if result != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        self.tab.close_tab()
        self.window_closed.emit(self.session_id)
        event.accept()


class TerminalTabWidget(QTabWidget):
    """
    Tab widget for managing multiple terminal sessions.
    """

    tab_count_changed = pyqtSignal(int)
    all_tabs_closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._tabs: Dict[int, TerminalTab] = {}
        self._detached_windows: Dict[int, DetachedTerminalWindow] = {}

        self._setup_ui()

    def _setup_ui(self):
        """Setup tab widget."""
        self.setTabsClosable(True)
        self.setMovable(True)
        self.setDocumentMode(True)
        self.setElideMode(Qt.TextElideMode.ElideRight)

        # Tab bar context menu
        self.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabBar().customContextMenuRequested.connect(self._show_tab_context_menu)

        # Close tab on button click
        self.tabCloseRequested.connect(self._on_tab_close_requested)

    def add_terminal(
        self,
        session_id: int,
        session: SSHSession,
        connection: Connection,
        timeout_minutes: int = 30
    ) -> TerminalTab:
        """
        Add a new terminal tab.

        Returns:
            The created TerminalTab
        """
        tab = TerminalTab(
            session_id=session_id,
            session=session,
            connection=connection,
            parent=self,
            timeout_minutes=timeout_minutes
        )

        # Connect signals
        tab.closed.connect(lambda: self._on_tab_closed(session_id))
        tab.title_changed.connect(lambda title: self._on_tab_title_changed(session_id, title))

        # Add tab with icon
        icon = get_icon("terminal")
        index = self.addTab(tab, icon, connection.name)
        self.setTabToolTip(index, f"{connection.username}@{connection.host}:{connection.port}")

        # Store reference
        self._tabs[session_id] = tab

        # Switch to new tab
        self.setCurrentIndex(index)

        self.tab_count_changed.emit(self.count())

        return tab

    def get_tab(self, session_id: int) -> Optional[TerminalTab]:
        """Get terminal tab by session ID."""
        return self._tabs.get(session_id)

    def remove_tab(self, session_id: int):
        """Remove a terminal tab by session ID."""
        tab = self._tabs.get(session_id)
        if tab:
            # Remove from dict first to prevent double-deletion from close_tab signal
            del self._tabs[session_id]

            index = self.indexOf(tab)
            if index >= 0:
                self.removeTab(index)
            tab.close_tab()

            self.tab_count_changed.emit(self.count())

            if self.count() == 0:
                self.all_tabs_closed.emit()

    def _on_tab_close_requested(self, index: int):
        """Handle tab close button click."""
        tab = self.widget(index)
        if isinstance(tab, TerminalTab):
            if tab.is_connected():
                result = QMessageBox.question(
                    self,
                    "Close Session",
                    f"Close connection to {tab.connection.name}?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if result != QMessageBox.StandardButton.Yes:
                    return

            self.remove_tab(tab.session_id)

    def _on_tab_closed(self, session_id: int):
        """Handle tab closed signal."""
        if session_id in self._tabs:
            del self._tabs[session_id]
            self.tab_count_changed.emit(self.count())

            if self.count() == 0:
                self.all_tabs_closed.emit()

    def _on_tab_title_changed(self, session_id: int, title: str):
        """Handle tab title change."""
        tab = self._tabs.get(session_id)
        if tab:
            index = self.indexOf(tab)
            if index >= 0:
                self.setTabText(index, title)

    def _show_tab_context_menu(self, pos):
        """Show context menu for tab."""
        index = self.tabBar().tabAt(pos)
        if index < 0:
            return

        tab = self.widget(index)
        if not isinstance(tab, TerminalTab):
            return

        menu = QMenu(self)

        # Reconnect action
        reconnect_action = menu.addAction(get_icon("refresh"), "Reconnect")
        reconnect_action.triggered.connect(tab.reconnect)
        reconnect_action.setEnabled(not tab.is_connected())

        # Disconnect action
        disconnect_action = menu.addAction(get_icon("disconnect"), "Disconnect")
        disconnect_action.triggered.connect(tab.disconnect_session)
        disconnect_action.setEnabled(tab.is_connected())

        menu.addSeparator()

        # Clear action
        clear_action = menu.addAction("Clear Terminal")
        clear_action.triggered.connect(tab.clear_terminal)

        menu.addSeparator()

        # Detach action
        detach_action = menu.addAction("Detach to Window")
        detach_action.triggered.connect(lambda: self._detach_tab(index))

        menu.addSeparator()

        # Close action
        close_action = menu.addAction(get_icon("close"), "Close Tab")
        close_action.triggered.connect(lambda: self._on_tab_close_requested(index))

        # Close other tabs
        if self.count() > 1:
            close_others_action = menu.addAction("Close Other Tabs")
            close_others_action.triggered.connect(lambda: self._close_other_tabs(index))

        menu.exec(self.tabBar().mapToGlobal(pos))

    def _close_other_tabs(self, keep_index: int):
        """Close all tabs except the one at keep_index."""
        # Collect session IDs to close (iterate backwards to avoid index issues)
        to_close = []
        for i in range(self.count()):
            if i != keep_index:
                tab = self.widget(i)
                if isinstance(tab, TerminalTab):
                    to_close.append(tab.session_id)

        for session_id in to_close:
            self.remove_tab(session_id)

    def close_all_tabs(self):
        """Close all terminal tabs and detached windows."""
        # Close detached windows first
        self.close_all_detached()

        # Then close tabs
        session_ids = list(self._tabs.keys())
        for session_id in session_ids:
            self.remove_tab(session_id)

    def apply_settings_to_all(self):
        """Apply settings to all terminal tabs."""
        for tab in self._tabs.values():
            tab.terminal.apply_settings()

    def _detach_tab(self, index: int):
        """Detach a tab to its own window."""
        tab = self.widget(index)
        if not isinstance(tab, TerminalTab):
            return

        session_id = tab.session_id

        # Save state and create fresh terminal BEFORE reparenting
        # This avoids all pyte buffer corruption from resize events
        saved_state = tab.create_fresh_terminal()

        # Remove from tabs dict
        if session_id in self._tabs:
            del self._tabs[session_id]

        # Remove tab from widget (keeps the widget alive)
        self.removeTab(index)

        # Create detached window with the tab
        window = DetachedTerminalWindow(tab)
        window.reattach_requested.connect(self._reattach_tab)
        window.window_closed.connect(self._on_detached_window_closed)

        # Store reference
        self._detached_windows[session_id] = window

        # Show window
        window.show()

        # Restore state after window is shown
        def restore():
            tab.restore_terminal_state(saved_state)
            tab._resize_pty()
        QTimer.singleShot(50, restore)

        self.tab_count_changed.emit(self.count())

        if self.count() == 0:
            self.all_tabs_closed.emit()

    def _reattach_tab(self, session_id: int):
        """Reattach a detached terminal back to the tab widget."""
        window = self._detached_windows.get(session_id)
        if not window or window.tab is None:
            return

        tab = window.tab

        # Save state and create fresh terminal BEFORE reparenting
        saved_state = tab.create_fresh_terminal()

        # Remove from detached windows
        del self._detached_windows[session_id]

        # Prevent close event from closing the tab
        window.tab = None

        # Remove tab from container layout
        if hasattr(window, '_container') and window._container:
            layout = window._container.layout()
            if layout:
                layout.removeWidget(tab)

        # Reparent to None first, then to tab widget
        tab.setParent(None)

        # Add back to tab widget
        icon = get_icon("terminal")
        index = self.addTab(tab, icon, tab.connection.name)
        self.setTabToolTip(index, f"{tab.connection.username}@{tab.connection.host}:{tab.connection.port}")

        # Store reference
        self._tabs[session_id] = tab

        # Switch to reattached tab
        self.setCurrentIndex(index)

        # Close the empty window
        window.close()

        # Restore state after tab is shown
        def restore():
            tab.restore_terminal_state(saved_state)
            tab._resize_pty()
        QTimer.singleShot(50, restore)

        self.tab_count_changed.emit(self.count())

    def _on_detached_window_closed(self, session_id: int):
        """Handle detached window being closed."""
        if session_id in self._detached_windows:
            del self._detached_windows[session_id]

    def get_all_session_count(self) -> int:
        """Get total count of all sessions (tabs + detached windows)."""
        return len(self._tabs) + len(self._detached_windows)

    def close_all_detached(self):
        """Close all detached windows."""
        for window in list(self._detached_windows.values()):
            window.close()
