"""
Style management for SSH Terminal Manager.
"""
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor


STYLES_DIR = Path(__file__).parent


def load_stylesheet(name: str = "dark_theme") -> str:
    """
    Load a QSS stylesheet by name.

    Args:
        name: Stylesheet name (without .qss extension)

    Returns:
        Stylesheet content as string
    """
    qss_path = STYLES_DIR / f"{name}.qss"
    if qss_path.exists():
        content = qss_path.read_text(encoding='utf-8')

        # Replace icon path placeholders with actual paths
        from ..resources import ICONS_DIR
        icons_path = str(ICONS_DIR).replace('\\', '/')
        content = content.replace('{{ICONS_DIR}}', icons_path)

        return content
    return ""


def apply_theme(app: QApplication, theme: str = "dark") -> None:
    """
    Apply a complete theme to the application.

    Args:
        app: QApplication instance
        theme: Theme name ('dark' or 'light')
    """
    app.setStyle("Fusion")

    if theme == "dark":
        # Apply dark palette
        palette = QPalette()

        # Base colors
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(224, 224, 224))
        palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(37, 37, 38))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(37, 37, 38))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(224, 224, 224))
        palette.setColor(QPalette.ColorRole.Text, QColor(224, 224, 224))
        palette.setColor(QPalette.ColorRole.Button, QColor(60, 60, 60))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(224, 224, 224))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))

        # Disabled colors
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(127, 127, 127))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(127, 127, 127))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(127, 127, 127))

        app.setPalette(palette)

        # Load and apply QSS
        stylesheet = load_stylesheet("dark_theme")
        app.setStyleSheet(stylesheet)


# Color constants for use in code
class Colors:
    """Theme colors for programmatic use."""

    # Dark theme colors
    BACKGROUND = "#1e1e1e"
    BACKGROUND_LIGHT = "#252526"
    BACKGROUND_LIGHTER = "#2d2d2d"

    FOREGROUND = "#e0e0e0"
    FOREGROUND_DIM = "#808080"

    BORDER = "#3c3c3c"
    BORDER_LIGHT = "#4c4c4c"

    ACCENT = "#2a82da"
    ACCENT_HOVER = "#3a92ea"
    ACCENT_PRESSED = "#1a72ca"

    SUCCESS = "#4ec9b0"
    WARNING = "#dcdcaa"
    ERROR = "#c42b1c"

    # Terminal colors (ANSI)
    TERMINAL_BG = "#0c0c0c"
    TERMINAL_FG = "#cccccc"

    # Status bar
    STATUSBAR_BG = "#007acc"
    STATUSBAR_FG = "#ffffff"
