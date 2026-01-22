"""
Terminal window for SSH sessions using pyte for VT100 emulation.
"""
from typing import Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QPlainTextEdit,
    QToolBar, QStatusBar, QMessageBox, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QObject, pyqtSlot
from PyQt6.QtGui import (
    QAction, QFont, QColor, QTextCharFormat, QKeyEvent, QInputMethodEvent,
    QPalette, QTextCursor, QTextDocument, QShortcut, QKeySequence
)

import pyte

from ..ssh.session import SSHSession
from ..storage.database import Connection
from .settings_dialog import SettingsDialog


class TerminalWidget(QPlainTextEdit):
    """
    Terminal widget using pyte for proper VT100 emulation.
    """

    data_ready = pyqtSignal(bytes)

    # ANSI color mapping
    COLORS = {
        'black': QColor(0, 0, 0),
        'red': QColor(205, 49, 49),
        'green': QColor(13, 188, 121),
        'yellow': QColor(229, 229, 16),
        'blue': QColor(36, 114, 200),
        'magenta': QColor(188, 63, 188),
        'cyan': QColor(17, 168, 205),
        'white': QColor(229, 229, 229),
        'default': QColor(229, 229, 229),
    }

    def __init__(self, parent=None, connection_settings: dict = None):
        super().__init__(parent)

        self._cols = 120
        self._rows = 30

        self._default_fg = QColor(229, 229, 229)
        self._default_bg = QColor(30, 30, 30)

        # Backspace character (configurable)
        self._backspace_char = b'\x08'  # Default: Control-H
        # Delete key character (configurable)
        self._delete_char = b'\x08'  # Default: same as backspace

        # Connection-specific settings
        self._connection_settings = connection_settings or {}

        # Get scrollback setting
        settings = SettingsDialog.get_terminal_settings()
        self._scrollback_lines = settings.get('scrollback_lines', 10000)

        # Pyte screen with history for scrollback
        self._screen = pyte.HistoryScreen(self._cols, self._rows, history=self._scrollback_lines)
        self._stream = pyte.Stream(self._screen)

        # Scroll offset (0 = at bottom/current, positive = scrolled up into history)
        self._scroll_offset = 0

        # Buffer for incoming data
        self._data_buffer = b''
        self._render_timer = QTimer(self)
        self._render_timer.timeout.connect(self._render_screen)
        self._render_timer.setInterval(16)  # ~60fps for smoother response

        # Flag to skip display updates until state is restored (used after detach/reattach)
        self._skip_display_updates = False

        # Preserved content from before detach/reattach (prepended to pyte output)
        self._preserved_content = ""

        self._setup_ui()

    def _setup_ui(self):
        """Setup terminal appearance."""
        self.apply_settings()

        self.setReadOnly(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setOverwriteMode(True)

        # Disable drag and drop (not appropriate for terminal)
        self.setAcceptDrops(False)

        # Enable input method for international characters (Umlaute, etc.)
        self.setAttribute(Qt.WidgetAttribute.WA_InputMethodEnabled, True)

        # Enable mouse tracking for right-click paste
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_right_click)

    def apply_settings(self):
        """Apply settings from SettingsDialog and connection-specific settings."""
        settings = SettingsDialog.get_terminal_settings()
        global_conn_settings = SettingsDialog.get_connection_settings()

        # Font
        font = QFont(settings['font_family'], settings['font_size'])
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)

        # Colors
        self._default_fg = QColor(settings['fg_color'])
        self._default_bg = QColor(settings['bg_color'])

        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Base, self._default_bg)
        palette.setColor(QPalette.ColorRole.Text, self._default_fg)
        self.setPalette(palette)

        # Cursor style
        cursor_style = settings.get('cursor_style', 'Block')
        if cursor_style == 'Block':
            self.setCursorWidth(8)
        elif cursor_style == 'Underline':
            self.setCursorWidth(2)
        else:  # Bar
            self.setCursorWidth(1)

        # Paste on right-click setting
        self._paste_on_right_click = settings.get('paste_on_right_click', True)

        # Backspace key setting - connection-specific overrides global
        conn_backspace = self._connection_settings.get('backspace_key', 'default')
        if conn_backspace == 'default':
            # Use global setting
            backspace_setting = global_conn_settings.get('backspace_key', 'Control-H')
        else:
            backspace_setting = conn_backspace

        if backspace_setting == 'Control-?':
            self._backspace_char = b'\x7f'  # DEL
        else:
            self._backspace_char = b'\x08'  # Control-H

        # Delete key setting - connection-specific
        delete_setting = self._connection_settings.get('delete_key', 'same_as_backspace')
        if delete_setting == 'ctrl_d':
            self._delete_char = b'\x04'  # Ctrl+D - forward delete (Cisco/bash)
        else:
            self._delete_char = self._backspace_char  # Same as backspace

    def get_size(self) -> tuple:
        """Get terminal size in columns and rows."""
        return self._cols, self._rows

    def keyPressEvent(self, event: QKeyEvent):
        """Handle key press - send to SSH session."""
        key = event.key()
        modifiers = event.modifiers()

        # Handle copy/paste shortcuts
        ctrl = modifiers & Qt.KeyboardModifier.ControlModifier
        shift = modifiers & Qt.KeyboardModifier.ShiftModifier

        # Ctrl+Shift+C or Ctrl+C with selection = Copy
        if ctrl and key == Qt.Key.Key_C:
            if shift or self.textCursor().hasSelection():
                self.copy()
                return
            else:
                # Send interrupt signal (Ctrl+C)
                self.data_ready.emit(b'\x03')
                return

        # Ctrl+Shift+V or Ctrl+V = Paste
        if ctrl and key == Qt.Key.Key_V:
            self._paste_clipboard()
            return

        # Ctrl+Shift+Insert = Paste (alternative)
        if shift and key == Qt.Key.Key_Insert:
            self._paste_clipboard()
            return

        # Shift+PageUp/PageDown = scroll through local history
        if shift and key == Qt.Key.Key_PageUp:
            self._scroll_history(-10)  # Scroll up 10 lines
            return
        if shift and key == Qt.Key.Key_PageDown:
            self._scroll_history(10)  # Scroll down 10 lines
            return

        data = None

        if key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            data = b'\r'
        elif key == Qt.Key.Key_Backspace:
            data = self._backspace_char  # Configurable: Control-H or DEL
        elif key == Qt.Key.Key_Delete:
            data = b'\x1b[3~'  # VT220 delete sequence (forward delete)
        elif key == Qt.Key.Key_Tab:
            data = b'\t'
        elif key == Qt.Key.Key_Escape:
            data = b'\x1b'
        elif key == Qt.Key.Key_Up:
            data = b'\x1b[A'
        elif key == Qt.Key.Key_Down:
            data = b'\x1b[B'
        elif key == Qt.Key.Key_Right:
            data = b'\x1b[C'
        elif key == Qt.Key.Key_Left:
            data = b'\x1b[D'
        elif key == Qt.Key.Key_Home:
            data = b'\x01'  # Ctrl+A - jump to beginning of line
        elif key == Qt.Key.Key_End:
            data = b'\x05'  # Ctrl+E - jump to end of line
        elif key == Qt.Key.Key_PageUp:
            data = b'\x1b[5~'
        elif key == Qt.Key.Key_PageDown:
            data = b'\x1b[6~'
        elif key == Qt.Key.Key_Insert:
            data = b'\x1b[2~'
        elif key >= Qt.Key.Key_F1 and key <= Qt.Key.Key_F12:
            fn = key - Qt.Key.Key_F1 + 1
            if fn <= 4:
                data = f'\x1bO{chr(ord("P") + fn - 1)}'.encode()
            else:
                codes = {5: 15, 6: 17, 7: 18, 8: 19, 9: 20, 10: 21, 11: 23, 12: 24}
                data = f'\x1b[{codes.get(fn, 15)}~'.encode()
        elif ctrl:
            # Other Ctrl combinations
            text = event.text()
            if text:
                char = ord(text[0].lower())
                if 97 <= char <= 122:
                    data = bytes([char - 96])
                elif ord(text[0]) >= 32:
                    # Printable character with Ctrl (e.g., AltGr combinations on Windows)
                    data = text.encode('utf-8')
        else:
            text = event.text()
            if text:
                data = text.encode('utf-8')

        # Fallback: if we have printable text but no data yet, send it
        # This catches edge cases like Umlaute with unusual modifier states
        if data is None:
            text = event.text()
            if text and len(text) > 0 and ord(text[0]) >= 32:
                data = text.encode('utf-8')

        if data:
            self.data_ready.emit(data)

    def _paste_clipboard(self):
        """Paste text from clipboard to terminal."""
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        if text:
            # Convert newlines and send
            text = text.replace('\r\n', '\r').replace('\n', '\r')
            self.data_ready.emit(text.encode('utf-8'))

    def _on_right_click(self, pos):
        """Handle right-click - paste immediately like Putty (if enabled)."""
        if not self._paste_on_right_click:
            # Show default context menu instead
            return

        if self.textCursor().hasSelection():
            # If text is selected, copy it
            self.copy()
        else:
            # Otherwise paste
            self._paste_clipboard()

    def mousePressEvent(self, event):
        """Handle mouse press for middle-click paste."""
        if event.button() == Qt.MouseButton.MiddleButton:
            self._paste_clipboard()
        else:
            super().mousePressEvent(event)

    def _scroll_history(self, lines: int):
        """Scroll through terminal history.

        Args:
            lines: Number of lines to scroll (negative = up, positive = down)
        """
        scrollbar = self.verticalScrollBar()
        font_height = self.fontMetrics().height()

        # Scroll by number of lines * font height
        new_value = scrollbar.value() + (lines * font_height)
        new_value = max(0, min(new_value, scrollbar.maximum()))
        scrollbar.setValue(new_value)

    def inputMethodEvent(self, event: QInputMethodEvent):
        """Handle input method events for international characters."""
        commit_string = event.commitString()
        if commit_string:
            # Send committed text (e.g., Umlaute entered via dead keys)
            self.data_ready.emit(commit_string.encode('utf-8'))
        # Don't call super() as we handle all input ourselves

    @pyqtSlot(bytes)
    def append_data(self, data: bytes):
        """Append received data to terminal."""
        self._data_buffer += data
        if not self._render_timer.isActive():
            self._render_timer.start()

    def refresh_display(self):
        """Force refresh of the terminal display from pyte screen buffer."""
        # Save scroll position
        scrollbar = self.verticalScrollBar()
        scroll_pos = scrollbar.value()
        scroll_max = scrollbar.maximum()

        self._update_display()

        # Restore scroll position (proportionally if max changed)
        new_max = scrollbar.maximum()
        if scroll_max > 0 and new_max > 0:
            new_pos = int(scroll_pos * new_max / scroll_max)
            scrollbar.setValue(new_pos)
        elif new_max > 0:
            # Was at 0, stay at 0
            scrollbar.setValue(0)

    def get_screen_content(self) -> str:
        """Get the current screen content as text."""
        screen_lines = []
        for y in range(self._screen.lines):
            line_chars = []
            for x in range(self._screen.columns):
                char = self._screen.buffer[y][x]
                line_chars.append(char.data if char.data else ' ')
            screen_lines.append(''.join(line_chars).rstrip())

        # Remove trailing empty lines
        while screen_lines and not screen_lines[-1]:
            screen_lines.pop()

        return '\n'.join(screen_lines)

    def _render_screen(self):
        """Process buffer and render pyte screen to widget."""
        if self._data_buffer:
            data = self._data_buffer
            self._data_buffer = b''

            try:
                text = data.decode('utf-8', errors='replace')
            except Exception:
                text = data.decode('latin-1', errors='replace')

            # Feed to pyte
            self._stream.feed(text)

        # Render screen
        self._update_display()

        if not self._data_buffer:
            self._render_timer.stop()

    def get_full_state(self) -> dict:
        """Get complete terminal state for transfer to another widget."""
        # Get content and strip trailing newlines to avoid empty lines
        content = self.toPlainText().rstrip('\n')

        return {
            'content': content,
            'cursor_pos': min(self.textCursor().position(), len(content)),
            'scroll_pos': self.verticalScrollBar().value(),
            'cols': self._cols,
            'rows': self._rows,
            # Save pyte screen state
            'screen_cursor_x': self._screen.cursor.x,
            'screen_cursor_y': self._screen.cursor.y,
        }

    def set_skip_display_updates(self, skip: bool):
        """Set flag to skip display updates (used during detach/reattach)."""
        self._skip_display_updates = skip
        if skip:
            self._render_timer.stop()

    def restore_full_state(self, state: dict):
        """Restore complete terminal state from another widget."""
        # Stop any pending render
        self._render_timer.stop()

        # Clear any buffered data that arrived during transition
        self._data_buffer = b''

        # Reset pyte screen
        self._screen.reset()

        # Store the restored content as preserved content
        # This will be prepended to any new pyte output
        self._preserved_content = state['content']

        # Restore display content
        self.setPlainText(state['content'])

        # Restore cursor position
        cursor = self.textCursor()
        cursor.setPosition(min(state['cursor_pos'], len(state['content'])))
        self.setTextCursor(cursor)

        # Restore scroll position
        self.verticalScrollBar().setValue(state['scroll_pos'])

        # Re-enable display updates
        self._skip_display_updates = False

    def _update_display(self):
        """Render pyte screen to the text widget, including scrollback history."""
        # Skip if waiting for state restore (after detach/reattach)
        if self._skip_display_updates:
            return

        cursor_y = self._screen.cursor.y
        cursor_x = self._screen.cursor.x

        # Get history lines (lines that scrolled off the top)
        history_lines = []
        if hasattr(self._screen, 'history') and self._screen.history.top:
            for hist_line in self._screen.history.top:
                line_chars = []
                for x in range(self._screen.columns):
                    if x < len(hist_line):
                        char = hist_line[x]
                        line_chars.append(char.data if char.data else ' ')
                    else:
                        line_chars.append(' ')
                history_lines.append(''.join(line_chars).rstrip())

        # Get current screen lines
        screen_lines = []
        for y in range(self._screen.lines):
            line_chars = []
            for x in range(self._screen.columns):
                char = self._screen.buffer[y][x]
                line_chars.append(char.data if char.data else ' ')
            line = ''.join(line_chars)

            # Only rstrip lines that are not the cursor line
            if y == cursor_y:
                line = line[:max(cursor_x + 1, len(line.rstrip()))]
                if len(line) < cursor_x:
                    line = line + ' ' * (cursor_x - len(line))
            else:
                line = line.rstrip()

            screen_lines.append(line)

        # Combine history and screen
        all_lines = history_lines + screen_lines

        # Remove trailing empty lines, but keep cursor line
        total_cursor_y = len(history_lines) + cursor_y
        while len(all_lines) > total_cursor_y + 1 and not all_lines[-1]:
            all_lines.pop()

        text = '\n'.join(all_lines)

        # Prepend preserved content from before detach/reattach
        if self._preserved_content:
            if text.strip():
                # Have both preserved and new content
                text = self._preserved_content + '\n' + text
            else:
                # Only have preserved content (no new data yet)
                text = self._preserved_content

        # Check if user is scrolled to the bottom before updating
        scrollbar = self.verticalScrollBar()
        was_at_bottom = scrollbar.value() >= scrollbar.maximum() - 10

        # Update widget
        self.setPlainText(text)

        # Position cursor
        cursor = self.textCursor()

        if self._preserved_content:
            # With preserved content, just move to end
            cursor.movePosition(QTextCursor.MoveOperation.End)
        else:
            # Normal cursor positioning based on pyte screen
            cursor.movePosition(QTextCursor.MoveOperation.Start)

            # Move to cursor position (history lines + screen cursor)
            target_y = min(total_cursor_y, len(all_lines) - 1) if all_lines else 0
            for _ in range(target_y):
                cursor.movePosition(QTextCursor.MoveOperation.Down)

            # Move to x position (within line bounds)
            current_line = all_lines[target_y] if target_y < len(all_lines) else ""
            target_x = min(cursor_x, len(current_line))
            for _ in range(target_x):
                cursor.movePosition(QTextCursor.MoveOperation.Right)

        self.setTextCursor(cursor)

        # Only auto-scroll to cursor if user was at bottom (following mode)
        if was_at_bottom:
            self.ensureCursorVisible()

    def resizeEvent(self, event):
        """Handle resize to update terminal dimensions."""
        super().resizeEvent(event)

        font_metrics = self.fontMetrics()
        char_width = font_metrics.horizontalAdvance('M')
        char_height = font_metrics.height()
        viewport = self.viewport()

        new_cols = max(80, viewport.width() // char_width)
        new_rows = max(24, viewport.height() // char_height)

        if new_cols != self._cols or new_rows != self._rows:
            self._cols = new_cols
            self._rows = new_rows
            self._screen.resize(new_rows, new_cols)


class SessionBridge(QObject):
    """Bridge for thread-safe communication between SSH session and UI."""

    data_received = pyqtSignal(bytes)
    error_received = pyqtSignal(str)
    disconnected = pyqtSignal(str)


class TerminalWindow(QMainWindow):
    """Window containing a terminal session with optional inactivity timeout."""

    closed = pyqtSignal()
    session_timeout = pyqtSignal()  # Emitted when session times out

    # Default inactivity timeout: 30 minutes (in milliseconds)
    # Set to 0 to disable
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
        """Setup window UI."""
        self.setWindowTitle(f"{self.connection.name} - {self.connection.username}@{self.connection.host}")
        self.resize(900, 600)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # Pass connection-specific terminal settings to the widget
        self.terminal = TerminalWidget(
            parent=None,
            connection_settings=self.connection.terminal_settings
        )
        layout.addWidget(self.terminal)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Reconnect button
        reconnect_action = QAction("Reconnect", self)
        reconnect_action.triggered.connect(self._reconnect)
        toolbar.addAction(reconnect_action)

        disconnect_action = QAction("Disconnect", self)
        disconnect_action.triggered.connect(self._disconnect)
        toolbar.addAction(disconnect_action)

        toolbar.addSeparator()

        clear_action = QAction("Clear", self)
        clear_action.triggered.connect(self._clear_terminal)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self._open_settings)
        toolbar.addAction(settings_action)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self._update_status("Connected")

    def _setup_session(self):
        """Connect session events to terminal."""
        self.terminal.data_ready.connect(self._on_terminal_input)

        self._bridge.data_received.connect(self._on_data_received, Qt.ConnectionType.QueuedConnection)
        self._bridge.error_received.connect(self._show_error, Qt.ConnectionType.QueuedConnection)
        self._bridge.disconnected.connect(self._on_disconnected, Qt.ConnectionType.QueuedConnection)

        self.session.on_data = lambda data: self._bridge.data_received.emit(data)
        self.session.on_error = lambda msg: self._bridge.error_received.emit(msg)
        self.session.on_disconnect = lambda reason: self._bridge.disconnected.emit(reason)

        QTimer.singleShot(100, self._resize_pty)

    @pyqtSlot(bytes)
    def _on_data_received(self, data: bytes):
        """Handle data received from session."""
        self._reset_inactivity_timer()  # Session activity
        self.terminal.append_data(data)

    def _on_terminal_input(self, data: bytes):
        """Handle input from terminal widget."""
        if not self._disconnected:
            self._reset_inactivity_timer()  # User activity
            self.session.send(data)

    @pyqtSlot(str)
    def _show_error(self, message: str):
        """Show error message."""
        self._update_status(f"Error: {message}")

    @pyqtSlot(str)
    def _on_disconnected(self, reason: str):
        """Handle disconnection."""
        self.set_disconnected(reason)

    def _update_status(self, message: str):
        """Update status bar."""
        self.statusBar.showMessage(message)

    def _resize_pty(self):
        """Resize PTY to match terminal size."""
        cols, rows = self.terminal.get_size()
        if not self._disconnected:
            self.session.resize_pty(cols, rows)

    def _disconnect(self):
        """Disconnect the session."""
        self.session.disconnect()
        self.set_disconnected("Disconnected by user")

    def _reconnect(self):
        """Reconnect the session."""
        if not self._disconnected:
            self.session.disconnect()

        self._update_status("Reconnecting...")
        self.terminal.setPlainText("")

        # Reset pyte screen
        self.terminal._screen.reset()

        # Get terminal type from connection settings
        term_type = self.connection.terminal_settings.get('term_type', 'xterm-256color') if self.connection.terminal_settings else 'xterm-256color'

        # Reconnect
        if self.session.connect():
            cols, rows = self.terminal.get_size()
            if self.session.open_shell(cols, rows, term_type):
                self._disconnected = False
                self._update_status("Connected")
            else:
                self.set_disconnected("Failed to open shell")
        else:
            self.set_disconnected("Reconnection failed")

    def _clear_terminal(self):
        """Clear terminal screen."""
        self.terminal.setPlainText("")
        self.terminal._screen.reset()

    def _open_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self)
        # Connect signal for live preview when Apply is clicked
        dialog.settings_applied.connect(self.terminal.apply_settings)
        dialog.exec()
        # Apply settings on close (regardless of OK or Cancel after Apply)
        self.terminal.apply_settings()

    def set_disconnected(self, reason: str):
        """Mark session as disconnected."""
        self._disconnected = True
        self._update_status(f"Disconnected: {reason}")

    def resizeEvent(self, event):
        """Handle window resize."""
        super().resizeEvent(event)
        QTimer.singleShot(50, self._resize_pty)

    def closeEvent(self, event):
        """Handle window close."""
        self._stop_inactivity_timer()
        self.closed.emit()
        event.accept()

    def _setup_inactivity_timer(self):
        """Setup inactivity timeout timer."""
        if self._timeout_ms > 0:
            self._inactivity_timer = QTimer(self)
            self._inactivity_timer.setSingleShot(True)
            self._inactivity_timer.timeout.connect(self._on_inactivity_timeout)
            self._reset_inactivity_timer()

    def _reset_inactivity_timer(self):
        """Reset inactivity timer (call on user/session activity)."""
        if self._inactivity_timer and self._timeout_ms > 0 and not self._disconnected:
            self._inactivity_timer.start(self._timeout_ms)

    def _stop_inactivity_timer(self):
        """Stop inactivity timer."""
        if self._inactivity_timer:
            self._inactivity_timer.stop()

    def _on_inactivity_timeout(self):
        """Handle inactivity timeout - disconnect session."""
        if not self._disconnected:
            # Log the timeout
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

    def set_timeout_minutes(self, minutes: int):
        """Set inactivity timeout in minutes (0 to disable)."""
        self._timeout_ms = minutes * 60 * 1000 if minutes > 0 else 0
        if self._timeout_ms > 0:
            if not self._inactivity_timer:
                self._setup_inactivity_timer()
            else:
                self._reset_inactivity_timer()
        else:
            self._stop_inactivity_timer()
