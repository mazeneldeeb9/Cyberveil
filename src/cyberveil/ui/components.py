from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer
from PySide6.QtGui import (
    QColor,
    QConicalGradient,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from cyberveil.ui.theme import COLORS


def icon(kind: str, color: str = COLORS["text"], size: int = 28) -> QIcon:
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(
        QPen(
            QColor(color),
            2.1,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
    )
    painter.setBrush(Qt.BrushStyle.NoBrush)
    scale = size / 32
    painter.scale(scale, scale)
    _draw_icon(painter, kind)
    painter.end()
    return QIcon(pixmap)


def _draw_icon(p: QPainter, kind: str) -> None:
    if kind == "back":
        p.drawLine(22, 6, 10, 16)
        p.drawLine(10, 16, 22, 26)
    elif kind == "bell":
        path = QPainterPath(QPointF(9, 22))
        path.quadTo(11, 19, 11, 13)
        path.quadTo(11, 6, 16, 6)
        path.quadTo(21, 6, 21, 13)
        path.quadTo(21, 19, 23, 22)
        path.closeSubpath()
        p.drawPath(path)
        p.drawArc(QRectF(14, 23, 4, 4), 0, -180 * 16)
    elif kind == "settings":
        p.drawEllipse(QPointF(16, 16), 5, 5)
        for angle in range(0, 360, 45):
            r = math.radians(angle)
            p.drawLine(
                QPointF(16 + math.cos(r) * 8, 16 + math.sin(r) * 8),
                QPointF(16 + math.cos(r) * 12, 16 + math.sin(r) * 12),
            )
    elif kind == "history":
        p.drawEllipse(QPointF(16, 16), 10, 10)
        p.drawLine(16, 16, 16, 10)
        p.drawLine(16, 16, 21, 19)
        p.drawLine(5, 9, 5, 4)
        p.drawLine(5, 4, 10, 4)
    elif kind == "logs":
        p.drawRoundedRect(QRectF(7, 5, 18, 23), 2, 2)
        for y in (11, 16, 21):
            p.drawLine(11, y, 21, y)
    elif kind == "reports":
        p.drawRoundedRect(QRectF(8, 4, 16, 24), 2, 2)
        p.drawLine(12, 20, 12, 24)
        p.drawLine(16, 16, 16, 24)
        p.drawLine(20, 12, 20, 24)
    elif kind == "play":
        path = QPainterPath(QPointF(11, 7))
        path.lineTo(25, 16)
        path.lineTo(11, 25)
        path.closeSubpath()
        p.drawPath(path)
    elif kind == "stop":
        p.drawRoundedRect(QRectF(9, 9, 14, 14), 2, 2)
    elif kind == "search":
        p.drawEllipse(QPointF(14, 14), 7, 7)
        p.drawLine(19, 19, 26, 26)
    elif kind == "export":
        p.drawRoundedRect(QRectF(7, 13, 18, 14), 2, 2)
        p.drawLine(16, 4, 16, 19)
        p.drawLine(10, 10, 16, 4)
        p.drawLine(22, 10, 16, 4)
    elif kind == "memory":
        p.drawRoundedRect(QRectF(7, 8, 18, 16), 3, 3)
        p.drawRoundedRect(QRectF(12, 12, 8, 8), 1, 1)
        for x in (10, 16, 22):
            p.drawLine(x, 4, x, 8)
            p.drawLine(x, 24, x, 28)
    elif kind == "shield":
        path = QPainterPath(QPointF(16, 3))
        path.lineTo(27, 8)
        path.lineTo(25, 20)
        path.quadTo(22, 26, 16, 29)
        path.quadTo(10, 26, 7, 20)
        path.lineTo(5, 8)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(11, 16, 15, 20)
        p.drawLine(15, 20, 22, 12)
    elif kind == "close":
        p.drawLine(9, 9, 23, 23)
        p.drawLine(23, 9, 9, 23)
    else:
        p.drawEllipse(QPointF(16, 16), 9, 9)


class AmbientWidget(QWidget):
    def paintEvent(self, event: object) -> None:
        super().paintEvent(event)  # type: ignore[arg-type]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(COLORS["background"]))
        for center, radius, alpha in (
            (QPointF(0, 0), max(self.width(), self.height()) * 0.58, 78),
            (QPointF(self.width(), self.height()), max(self.width(), self.height()) * 0.68, 48),
        ):
            gradient = QRadialGradient(center, radius)
            gradient.setColorAt(0, QColor(12, 161, 151, alpha))
            gradient.setColorAt(0.42, QColor(10, 73, 85, alpha // 2))
            gradient.setColorAt(1, QColor(8, 24, 39, 0))
            painter.fillRect(self.rect(), gradient)
        painter.end()


class RadarWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(220, 220)
        self.setMaximumSize(300, 300)
        self._angle = 0
        self._active = False
        self._timer = QTimer(self)
        self._timer.setInterval(36)
        self._timer.timeout.connect(self._advance)

    def sizeHint(self) -> QSize:
        return QSize(260, 260)

    def set_active(self, active: bool, *, reduced_motion: bool = False) -> None:
        self._active = active
        if active and not reduced_motion:
            self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def _advance(self) -> None:
        self._angle = (self._angle + 3) % 360
        self.update()

    def paintEvent(self, event: object) -> None:
        side = min(self.width(), self.height()) - 20
        bounds = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        center = bounds.center()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        glow = QRadialGradient(center, side / 2)
        glow.setColorAt(0, QColor(34, 211, 197, 24))
        glow.setColorAt(0.7, QColor(34, 211, 197, 9))
        glow.setColorAt(1, QColor(34, 211, 197, 0))
        p.setBrush(glow)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(bounds)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QColor(57, 138, 142, 150), 1))
        for ratio in (0.25, 0.5, 0.75, 1.0):
            radius = side * ratio / 2
            p.drawEllipse(center, radius, radius)
        p.drawLine(QPointF(bounds.left(), center.y()), QPointF(bounds.right(), center.y()))
        p.drawLine(QPointF(center.x(), bounds.top()), QPointF(center.x(), bounds.bottom()))
        if self._active:
            sweep = QConicalGradient(center, -self._angle)
            sweep.setColorAt(0, QColor(34, 211, 197, 180))
            sweep.setColorAt(0.12, QColor(34, 211, 197, 15))
            sweep.setColorAt(1, QColor(34, 211, 197, 0))
            path = QPainterPath(center)
            path.arcTo(bounds, self._angle, 42)
            path.closeSubpath()
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(sweep)
            p.drawPath(path)
        for dx, dy, alpha in ((0.22, -0.26, 230), (-0.31, 0.18, 150), (0.09, 0.34, 110)):
            point = QPointF(center.x() + dx * side, center.y() + dy * side)
            p.setBrush(QColor(114, 255, 239, alpha))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(point, 3.5, 3.5)
        p.setBrush(QColor(COLORS["accent"]))
        p.drawEllipse(center, 5, 5)
        p.end()


class MetricBlock(QFrame):
    def __init__(self, label: str, value: str = "0", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 10, 4, 10)
        layout.setSpacing(3)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        self.label_label = QLabel(label)
        self.label_label.setObjectName("metricLabel")
        layout.addWidget(self.value_label)
        layout.addWidget(self.label_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)

    def set_label(self, label: str) -> None:
        self.label_label.setText(label)


class EmptyState(QFrame):
    def __init__(self, title: str, detail: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 32, 28, 32)
        layout.setSpacing(8)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("sectionTitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_label = QLabel(detail)
        self.detail_label.setObjectName("muted")
        self.detail_label.setWordWrap(True)
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        layout.addWidget(self.title_label)
        layout.addWidget(self.detail_label)
        layout.addStretch()


class SeverityPill(QLabel):
    def set_severity(self, value: str) -> None:
        colors = {
            "high": COLORS["danger"],
            "medium": COLORS["warning"],
            "low": COLORS["info"],
            "normal": COLORS["success"],
        }
        color = colors.get(value, COLORS["muted"])
        self.setText(value.upper())
        background = QColor(color).darker(450).name()
        self.setStyleSheet(
            f"color: {color}; background: {background}; border-radius: 8px; padding: 4px 9px; font-weight: 750;"
        )
