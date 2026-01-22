"""
Resource management for SSH Terminal Manager.
"""
from pathlib import Path
from typing import Optional

from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QPen, QPainterPath, QBrush, QImage
from PyQt6.QtCore import QSize, Qt, QByteArray, QRectF, QPointF
from PyQt6.QtSvg import QSvgRenderer


RESOURCES_DIR = Path(__file__).parent
ICONS_DIR = RESOURCES_DIR / "icons"


class IconProvider:
    """
    Provides icons with color support for the application.
    Uses direct drawing for reliability.
    """

    _cache: dict[tuple[str, str], QIcon] = {}

    # Icon drawing functions
    ICON_DRAWERS = {}

    @classmethod
    def _init_drawers(cls):
        """Initialize icon drawing functions."""
        if cls.ICON_DRAWERS:
            return

        cls.ICON_DRAWERS = {
            'server': cls._draw_server,
            'folder': cls._draw_folder,
            'connect': cls._draw_connect,
            'disconnect': cls._draw_disconnect,
            'add': cls._draw_add,
            'edit': cls._draw_edit,
            'delete': cls._draw_delete,
            'settings': cls._draw_settings,
            'refresh': cls._draw_refresh,
            'terminal': cls._draw_terminal,
            'key': cls._draw_key,
            'import': cls._draw_import,
            'export': cls._draw_export,
            'close': cls._draw_close,
            'sidebar': cls._draw_sidebar,
            'sidebar_collapse': cls._draw_sidebar_collapse,
            'sidebar_expand': cls._draw_sidebar_expand,
        }

    @classmethod
    def get_icon(cls, name: str, color: str = "#e0e0e0") -> QIcon:
        """Get an icon by name with specified color."""
        cls._init_drawers()

        cache_key = (name, color)
        if cache_key in cls._cache:
            return cls._cache[cache_key]

        icon = QIcon()

        # Use direct drawing for reliability
        if name in cls.ICON_DRAWERS:
            for size in [16, 20, 24, 32]:
                pixmap = cls._create_drawn_pixmap(name, color, size)
                if pixmap and not pixmap.isNull():
                    icon.addPixmap(pixmap, QIcon.Mode.Normal)
                    # Also add for selected state
                    icon.addPixmap(pixmap, QIcon.Mode.Selected)

                # Disabled state
                disabled_pixmap = cls._create_drawn_pixmap(name, "#606060", size)
                if disabled_pixmap and not disabled_pixmap.isNull():
                    icon.addPixmap(disabled_pixmap, QIcon.Mode.Disabled)

        # Debug: Check if icon was created
        has_sizes = icon.availableSizes() if not icon.isNull() else []
        if not has_sizes:
            print(f"DEBUG: Icon '{name}' has no available sizes after drawing")

        # Try SVG if direct drawing didn't work
        if icon.isNull() or not icon.availableSizes():
            icon_path = ICONS_DIR / f"{name}.svg"
            if icon_path.exists():
                icon = cls._load_svg_icon(name, color)
                print(f"DEBUG: Tried SVG for '{name}', sizes: {icon.availableSizes()}")

        # Final fallback: create a simple colored square
        if icon.isNull() or not icon.availableSizes():
            print(f"DEBUG: Creating fallback icon for '{name}'")
            icon = cls._create_simple_icon(color)

        cls._cache[cache_key] = icon
        return icon

    @classmethod
    def _create_simple_icon(cls, color: str) -> QIcon:
        """Create a very simple colored icon as ultimate fallback."""
        icon = QIcon()
        for size in [16, 20, 24, 32]:
            pixmap = QPixmap(size, size)
            pixmap.fill(QColor(color))
            icon.addPixmap(pixmap, QIcon.Mode.Normal)
        return icon

    @classmethod
    def _create_placeholder_icon(cls, name: str, color: str) -> QIcon:
        """Create a simple placeholder icon with the first letter of the name."""
        icon = QIcon()
        for size in [16, 20, 24, 32]:
            pixmap = QPixmap(size, size)
            pixmap.fill(Qt.GlobalColor.transparent)

            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

            # Draw a circle with the first letter
            pen = QPen(QColor(color))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.drawEllipse(1, 1, size - 2, size - 2)

            # Draw letter
            from PyQt6.QtGui import QFont
            font = QFont("Segoe UI", int(size * 0.5))
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, name[0].upper())

            painter.end()
            icon.addPixmap(pixmap, QIcon.Mode.Normal)

        return icon

    @classmethod
    def _create_drawn_pixmap(cls, name: str, color: str, size: int) -> QPixmap:
        """Create pixmap by drawing icon directly with filled shapes."""
        # Use QImage for more reliable painting on Windows
        image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)

        painter = QPainter(image)
        if not painter.isActive():
            return QPixmap()

        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        qcolor = QColor(color)
        if not qcolor.isValid():
            qcolor = QColor(224, 224, 224)

        pen = QPen(qcolor)
        stroke_width = max(1.5, size / 12.0)
        pen.setWidthF(stroke_width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        s = size / 24.0

        drawer = cls.ICON_DRAWERS.get(name)
        if drawer:
            try:
                drawer(painter, s, qcolor)
            except Exception as e:
                print(f"Error drawing icon '{name}': {e}")

        painter.end()
        return QPixmap.fromImage(image)

    @classmethod
    def _draw_server(cls, p: QPainter, s: float, color: QColor):
        """Draw server icon - two stacked rectangles with LEDs."""
        # Top box
        p.drawRect(QRectF(3*s, 3*s, 18*s, 7*s))
        # Bottom box
        p.drawRect(QRectF(3*s, 14*s, 18*s, 7*s))
        # LEDs (filled circles)
        old_brush = p.brush()
        p.setBrush(color)
        p.drawEllipse(QPointF(7*s, 6.5*s), 2*s, 2*s)
        p.drawEllipse(QPointF(7*s, 17.5*s), 2*s, 2*s)
        p.setBrush(old_brush)

    @classmethod
    def _draw_folder(cls, p: QPainter, s: float, color: QColor):
        """Draw folder icon."""
        # Simple folder shape
        path = QPainterPath()
        path.moveTo(2*s, 7*s)
        path.lineTo(2*s, 20*s)
        path.lineTo(22*s, 20*s)
        path.lineTo(22*s, 9*s)
        path.lineTo(12*s, 9*s)
        path.lineTo(10*s, 5*s)
        path.lineTo(2*s, 5*s)
        path.closeSubpath()
        p.drawPath(path)

    @classmethod
    def _draw_connect(cls, p: QPainter, s: float, color: QColor):
        """Draw play/connect icon - filled triangle."""
        path = QPainterPath()
        path.moveTo(6*s, 4*s)
        path.lineTo(20*s, 12*s)
        path.lineTo(6*s, 20*s)
        path.closeSubpath()
        p.drawPath(path)

    @classmethod
    def _draw_disconnect(cls, p: QPainter, s: float, color: QColor):
        """Draw pause/disconnect icon - two filled rectangles."""
        p.drawRoundedRect(QRectF(5*s, 4*s, 5*s, 16*s), 1*s, 1*s)
        p.drawRoundedRect(QRectF(14*s, 4*s, 5*s, 16*s), 1*s, 1*s)

    @classmethod
    def _draw_add(cls, p: QPainter, s: float, color: QColor):
        """Draw plus icon - thick cross."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(12*s, 4*s), QPointF(12*s, 20*s))
        p.drawLine(QPointF(4*s, 12*s), QPointF(20*s, 12*s))

    @classmethod
    def _draw_edit(cls, p: QPainter, s: float, color: QColor):
        """Draw edit/pencil icon."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Pencil body
        path = QPainterPath()
        path.moveTo(4*s, 20*s)
        path.lineTo(4*s, 16*s)
        path.lineTo(16*s, 4*s)
        path.lineTo(20*s, 8*s)
        path.lineTo(8*s, 20*s)
        path.closeSubpath()
        p.drawPath(path)
        # Pencil tip
        p.drawLine(QPointF(4*s, 20*s), QPointF(7*s, 17*s))

    @classmethod
    def _draw_delete(cls, p: QPainter, s: float, color: QColor):
        """Draw trash icon."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Lid
        p.drawLine(QPointF(4*s, 6*s), QPointF(20*s, 6*s))
        p.drawLine(QPointF(9*s, 6*s), QPointF(9*s, 4*s))
        p.drawLine(QPointF(9*s, 4*s), QPointF(15*s, 4*s))
        p.drawLine(QPointF(15*s, 4*s), QPointF(15*s, 6*s))
        # Can body
        path = QPainterPath()
        path.moveTo(6*s, 6*s)
        path.lineTo(6*s, 19*s)
        path.quadTo(6*s, 21*s, 8*s, 21*s)
        path.lineTo(16*s, 21*s)
        path.quadTo(18*s, 21*s, 18*s, 19*s)
        path.lineTo(18*s, 6*s)
        p.drawPath(path)
        # Lines inside
        p.drawLine(QPointF(10*s, 10*s), QPointF(10*s, 17*s))
        p.drawLine(QPointF(14*s, 10*s), QPointF(14*s, 17*s))

    @classmethod
    def _draw_settings(cls, p: QPainter, s: float, color: QColor):
        """Draw gear/settings icon."""
        import math
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Inner circle
        p.drawEllipse(QPointF(12*s, 12*s), 3*s, 3*s)
        # Outer gear shape
        for angle in range(0, 360, 45):
            rad = math.radians(angle)
            x1 = 12*s + 5*s * math.cos(rad)
            y1 = 12*s + 5*s * math.sin(rad)
            x2 = 12*s + 9*s * math.cos(rad)
            y2 = 12*s + 9*s * math.sin(rad)
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

    @classmethod
    def _draw_refresh(cls, p: QPainter, s: float, color: QColor):
        """Draw refresh icon - circular arrows."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Arcs
        p.drawArc(QRectF(4*s, 4*s, 16*s, 16*s), 45*16, 180*16)
        p.drawArc(QRectF(4*s, 4*s, 16*s, 16*s), 225*16, 180*16)
        # Arrow heads
        p.setBrush(color)
        # Top arrow
        path1 = QPainterPath()
        path1.moveTo(18*s, 5*s)
        path1.lineTo(21*s, 8*s)
        path1.lineTo(18*s, 11*s)
        path1.closeSubpath()
        p.drawPath(path1)
        # Bottom arrow
        path2 = QPainterPath()
        path2.moveTo(6*s, 19*s)
        path2.lineTo(3*s, 16*s)
        path2.lineTo(6*s, 13*s)
        path2.closeSubpath()
        p.drawPath(path2)

    @classmethod
    def _draw_terminal(cls, p: QPainter, s: float, color: QColor):
        """Draw terminal icon - prompt and cursor."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # > prompt
        p.drawLine(QPointF(4*s, 6*s), QPointF(10*s, 12*s))
        p.drawLine(QPointF(10*s, 12*s), QPointF(4*s, 18*s))
        # Underscore cursor
        p.drawLine(QPointF(12*s, 18*s), QPointF(20*s, 18*s))

    @classmethod
    def _draw_key(cls, p: QPainter, s: float, color: QColor):
        """Draw key icon."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Key head (circle)
        p.drawEllipse(QPointF(8*s, 16*s), 5*s, 5*s)
        # Small circle inside
        p.drawEllipse(QPointF(8*s, 16*s), 2*s, 2*s)
        # Key shaft
        p.drawLine(QPointF(12*s, 12*s), QPointF(20*s, 4*s))
        # Key teeth
        p.drawLine(QPointF(16*s, 8*s), QPointF(19*s, 5*s))
        p.drawLine(QPointF(14*s, 10*s), QPointF(16*s, 8*s))

    @classmethod
    def _draw_import(cls, p: QPainter, s: float, color: QColor):
        """Draw download/import icon."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Box
        path = QPainterPath()
        path.moveTo(4*s, 14*s)
        path.lineTo(4*s, 19*s)
        path.quadTo(4*s, 21*s, 6*s, 21*s)
        path.lineTo(18*s, 21*s)
        path.quadTo(20*s, 21*s, 20*s, 19*s)
        path.lineTo(20*s, 14*s)
        p.drawPath(path)
        # Arrow down
        p.drawLine(QPointF(12*s, 3*s), QPointF(12*s, 14*s))
        # Arrow head
        p.setBrush(color)
        arrow = QPainterPath()
        arrow.moveTo(12*s, 17*s)
        arrow.lineTo(7*s, 11*s)
        arrow.lineTo(17*s, 11*s)
        arrow.closeSubpath()
        p.drawPath(arrow)

    @classmethod
    def _draw_export(cls, p: QPainter, s: float, color: QColor):
        """Draw upload/export icon."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Box
        path = QPainterPath()
        path.moveTo(4*s, 14*s)
        path.lineTo(4*s, 19*s)
        path.quadTo(4*s, 21*s, 6*s, 21*s)
        path.lineTo(18*s, 21*s)
        path.quadTo(20*s, 21*s, 20*s, 19*s)
        path.lineTo(20*s, 14*s)
        p.drawPath(path)
        # Arrow up
        p.drawLine(QPointF(12*s, 17*s), QPointF(12*s, 6*s))
        # Arrow head
        p.setBrush(color)
        arrow = QPainterPath()
        arrow.moveTo(12*s, 3*s)
        arrow.lineTo(7*s, 9*s)
        arrow.lineTo(17*s, 9*s)
        arrow.closeSubpath()
        p.drawPath(arrow)

    @classmethod
    def _draw_close(cls, p: QPainter, s: float, color: QColor):
        """Draw X/close icon."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(6*s, 6*s), QPointF(18*s, 18*s))
        p.drawLine(QPointF(18*s, 6*s), QPointF(6*s, 18*s))

    @classmethod
    def _draw_sidebar(cls, p: QPainter, s: float, color: QColor):
        """Draw sidebar toggle icon - hamburger menu."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(4*s, 6*s), QPointF(20*s, 6*s))
        p.drawLine(QPointF(4*s, 12*s), QPointF(20*s, 12*s))
        p.drawLine(QPointF(4*s, 18*s), QPointF(20*s, 18*s))

    @classmethod
    def _draw_sidebar_collapse(cls, p: QPainter, s: float, color: QColor):
        """Draw sidebar collapse icon - chevron left."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(15*s, 4*s), QPointF(8*s, 12*s))
        p.drawLine(QPointF(8*s, 12*s), QPointF(15*s, 20*s))

    @classmethod
    def _draw_sidebar_expand(cls, p: QPainter, s: float, color: QColor):
        """Draw sidebar expand icon - chevron right."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(9*s, 4*s), QPointF(16*s, 12*s))
        p.drawLine(QPointF(16*s, 12*s), QPointF(9*s, 20*s))

    @classmethod
    def _load_svg_icon(cls, name: str, color: str) -> QIcon:
        """Load icon from SVG file with color replacement."""
        icon_path = ICONS_DIR / f"{name}.svg"
        if not icon_path.exists():
            return QIcon()

        icon = QIcon()
        try:
            svg_content = icon_path.read_text(encoding='utf-8')

            # Create normal state with requested color
            colored_svg = svg_content.replace('stroke="#ffffff"', f'stroke="{color}"')
            svg_bytes = QByteArray(colored_svg.encode('utf-8'))
            renderer = QSvgRenderer(svg_bytes)

            if renderer.isValid():
                for size in [16, 20, 24, 32]:
                    pixmap = QPixmap(size, size)
                    pixmap.fill(Qt.GlobalColor.transparent)
                    painter = QPainter(pixmap)
                    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                    renderer.render(painter)
                    painter.end()
                    icon.addPixmap(pixmap, QIcon.Mode.Normal)

            # Create disabled state with gray color
            disabled_svg = svg_content.replace('stroke="#ffffff"', 'stroke="#606060"')
            disabled_bytes = QByteArray(disabled_svg.encode('utf-8'))
            disabled_renderer = QSvgRenderer(disabled_bytes)

            if disabled_renderer.isValid():
                for size in [16, 20, 24, 32]:
                    pixmap = QPixmap(size, size)
                    pixmap.fill(Qt.GlobalColor.transparent)
                    painter = QPainter(pixmap)
                    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                    disabled_renderer.render(painter)
                    painter.end()
                    icon.addPixmap(pixmap, QIcon.Mode.Disabled)

        except Exception as e:
            # Log error for debugging but continue
            print(f"Warning: Failed to load icon '{name}': {e}")

        return icon

    @classmethod
    def clear_cache(cls):
        """Clear the icon cache."""
        cls._cache.clear()


def get_icon(name: str, color: str = "#e0e0e0") -> QIcon:
    """Get an icon by name."""
    return IconProvider.get_icon(name, color)
