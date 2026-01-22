"""
Connection list widget with tree structure for groups.
"""
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QLineEdit, QMenu, QInputDialog, QMessageBox, QLabel, QPushButton,
    QStyle, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor

from ..storage.database import Database, Connection
from ..resources import get_icon


def create_colored_icon(color: str, size: int = 16) -> QIcon:
    """Create a simple colored square icon for debugging."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(color))
    return QIcon(pixmap)


class ConnectionListWidget(QWidget):
    """
    Widget displaying connections in a tree structure grouped by folder.
    """

    # Signals
    connection_activated = pyqtSignal(int)  # connection_id
    connection_edit_requested = pyqtSignal(int)  # connection_id
    connection_delete_requested = pyqtSignal(int)  # connection_id
    connection_duplicate_requested = pyqtSignal(int)  # connection_id
    new_connection_requested = pyqtSignal()  # Request to create new connection
    settings_requested = pyqtSignal()  # Request to open global settings

    def __init__(self, database: Database, parent=None):
        super().__init__(parent)
        self.database = database
        self._setup_ui()
        self.refresh()

    def _setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header with title
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel("Connections")
        title.setProperty("heading", "true")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Add connection button
        add_btn = QPushButton()
        add_btn.setIcon(get_icon("add"))
        add_btn.setToolTip("New Connection")
        add_btn.setFixedSize(28, 28)
        add_btn.setFlat(True)
        add_btn.clicked.connect(self._emit_new_connection)
        header_layout.addWidget(add_btn)

        layout.addWidget(header)

        # Search box with icon styling
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search connections...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._on_search)
        layout.addWidget(self.search_input)

        # Tree widget
        self.tree = QTreeWidget()
        self.tree.setObjectName("connectionList")
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setAnimated(True)
        self.tree.setIndentation(16)  # Minimal indentation
        self.tree.setIconSize(QSize(16, 16))
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_context_menu)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.tree.setDragDropMode(QTreeWidget.DragDropMode.InternalMove)
        self.tree.setDragEnabled(True)
        self.tree.setAcceptDrops(True)
        self.tree.setDropIndicatorShown(True)
        self.tree.setAlternatingRowColors(False)
        self.tree.setUniformRowHeights(True)
        # Enable horizontal scrollbar for long connection names
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.tree.setWordWrap(False)

        layout.addWidget(self.tree)

    def _emit_new_connection(self):
        """Emit signal to create new connection (handled by main window)."""
        self.new_connection_requested.emit()

    def refresh(self):
        """Refresh the connection list from database."""
        self.tree.clear()

        connections = self.database.get_all_connections()
        groups = self.database.get_all_groups()

        # Use Qt standard icons
        style = QApplication.style()
        folder_icon = style.standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        server_icon = style.standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)

        # Create group items
        group_items = {}
        for group in groups:
            item = QTreeWidgetItem([group.name])
            item.setIcon(0, folder_icon)
            item.setData(0, Qt.ItemDataRole.UserRole, {'type': 'group', 'id': group.id})
            item.setExpanded(group.expanded)
            self.tree.addTopLevelItem(item)
            group_items[group.name] = item

        # Add connections to their groups
        for conn in connections:
            parent = group_items.get(conn.group_name)
            if parent is None:
                # Create group if it doesn't exist
                parent = QTreeWidgetItem([conn.group_name])
                parent.setIcon(0, folder_icon)
                parent.setData(0, Qt.ItemDataRole.UserRole, {'type': 'group', 'id': None})
                self.tree.addTopLevelItem(parent)
                group_items[conn.group_name] = parent

            # Create connection item
            display_text = f"{conn.name} ({conn.username}@{conn.host}:{conn.port})"
            item = QTreeWidgetItem([display_text])
            item.setIcon(0, server_icon)
            item.setData(0, Qt.ItemDataRole.UserRole, {
                'type': 'connection',
                'id': conn.id,
                'connection': conn
            })
            item.setToolTip(0, f"Host: {conn.host}\nPort: {conn.port}\nUser: {conn.username}\nGroup: {conn.group_name}")
            parent.addChild(item)

        # Expand all groups by default
        self.tree.expandAll()

    def _on_search(self, text: str):
        """Filter connections by search text."""
        if not text:
            # Show all items
            for i in range(self.tree.topLevelItemCount()):
                group_item = self.tree.topLevelItem(i)
                group_item.setHidden(False)
                for j in range(group_item.childCount()):
                    group_item.child(j).setHidden(False)
            return

        text = text.lower()

        # Search and filter
        for i in range(self.tree.topLevelItemCount()):
            group_item = self.tree.topLevelItem(i)
            visible_children = 0

            for j in range(group_item.childCount()):
                child = group_item.child(j)
                data = child.data(0, Qt.ItemDataRole.UserRole)
                if data and data['type'] == 'connection':
                    conn = data['connection']
                    matches = (
                        text in conn.name.lower() or
                        text in conn.host.lower() or
                        text in conn.username.lower()
                    )
                    child.setHidden(not matches)
                    if matches:
                        visible_children += 1

            # Hide group if no visible children
            group_item.setHidden(visible_children == 0)

    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle double click on item."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data and data['type'] == 'connection':
            self.connection_activated.emit(data['id'])

    def _show_context_menu(self, pos):
        """Show context menu for item."""
        item = self.tree.itemAt(pos)
        if not item:
            # No item - show menu for adding
            menu = QMenu(self)
            add_group_action = menu.addAction(get_icon("folder"), "Add Group")
            add_group_action.triggered.connect(self._add_group)
            menu.exec(self.tree.mapToGlobal(pos))
            return

        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return

        menu = QMenu(self)

        if data['type'] == 'connection':
            connect_action = menu.addAction(get_icon("connect"), "Connect")
            connect_action.triggered.connect(lambda: self.connection_activated.emit(data['id']))

            menu.addSeparator()

            edit_action = menu.addAction(get_icon("edit"), "Edit Connection")
            edit_action.triggered.connect(lambda: self.connection_edit_requested.emit(data['id']))

            duplicate_action = menu.addAction(get_icon("add"), "Duplicate")
            duplicate_action.triggered.connect(lambda: self.connection_duplicate_requested.emit(data['id']))

            menu.addSeparator()

            settings_action = menu.addAction(get_icon("settings"), "Settings...")
            settings_action.triggered.connect(self.settings_requested.emit)

            menu.addSeparator()

            delete_action = menu.addAction(get_icon("delete"), "Delete")
            delete_action.triggered.connect(lambda: self.connection_delete_requested.emit(data['id']))

        elif data['type'] == 'group':
            rename_action = menu.addAction(get_icon("edit"), "Rename Group")
            rename_action.triggered.connect(lambda: self._rename_group(item))

            add_group_action = menu.addAction(get_icon("folder"), "Add Subgroup")
            add_group_action.triggered.connect(self._add_group)

            menu.addSeparator()

            delete_action = menu.addAction(get_icon("delete"), "Delete Group")
            delete_action.triggered.connect(lambda: self._delete_group(item))

        menu.exec(self.tree.mapToGlobal(pos))

    def _add_group(self):
        """Add a new group."""
        name, ok = QInputDialog.getText(
            self,
            "New Group",
            "Enter group name:"
        )
        if ok and name:
            from ..storage.database import Group
            self.database.add_group(Group(name=name))
            self.refresh()

    def _rename_group(self, item: QTreeWidgetItem):
        """Rename a group."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or data['type'] != 'group':
            return

        old_name = item.text(0)
        if old_name == 'Default':
            QMessageBox.warning(self, "Cannot Rename", "The Default group cannot be renamed.")
            return

        new_name, ok = QInputDialog.getText(
            self,
            "Rename Group",
            "Enter new name:",
            text=old_name
        )
        if ok and new_name and new_name != old_name:
            self.database.rename_group(old_name, new_name)
            self.refresh()

    def _delete_group(self, item: QTreeWidgetItem):
        """Delete a group."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or data['type'] != 'group':
            return

        group_name = item.text(0)
        if group_name == 'Default':
            QMessageBox.warning(self, "Cannot Delete", "The Default group cannot be deleted.")
            return

        child_count = item.childCount()
        message = f"Delete group '{group_name}'?"
        if child_count > 0:
            message += f"\n\n{child_count} connection(s) will be moved to the Default group."

        result = QMessageBox.question(
            self,
            "Delete Group",
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result == QMessageBox.StandardButton.Yes:
            if data['id']:
                self.database.delete_group(data['id'])
            self.refresh()

    def get_selected_connection(self) -> Optional[Connection]:
        """Get currently selected connection."""
        item = self.tree.currentItem()
        if not item:
            return None

        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data and data['type'] == 'connection':
            return data['connection']
        return None

    def get_selected_connection_id(self) -> Optional[int]:
        """Get ID of currently selected connection."""
        conn = self.get_selected_connection()
        return conn.id if conn else None
