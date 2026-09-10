from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QApplication, QSplashScreen

from cyberveil.paths import database_path
from cyberveil.storage import Database
from cyberveil.ui.main_window import MainWindow
from cyberveil.ui.theme import COLORS, stylesheet


def _splash() -> QSplashScreen:
    pixmap = QPixmap(720, 420)
    pixmap.fill(QColor(COLORS["background"]))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(COLORS["accent"]), 3))
    painter.drawRoundedRect(302, 86, 116, 126, 26, 26)
    painter.drawLine(328, 149, 353, 173)
    painter.drawLine(353, 173, 393, 125)
    font = QFont("Arial", 31)
    font.setBold(True)
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 4)
    painter.setFont(font)
    painter.setPen(QColor(COLORS["text"]))
    painter.drawText(0, 245, 720, 70, Qt.AlignmentFlag.AlignCenter, "CYBERVEIL")
    painter.setFont(QFont("Arial", 12))
    painter.setPen(QColor(COLORS["muted"]))
    painter.drawText(0, 308, 720, 40, Qt.AlignmentFlag.AlignCenter, "Preparing the local protection console")
    painter.end()
    return QSplashScreen(pixmap)


def create_application() -> QApplication:
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication(sys.argv)
    app.setApplicationName("CYBERVEIL")
    app.setOrganizationName("CYBERVEIL Lab")
    app.setStyle("Fusion")
    app.setStyleSheet(stylesheet())
    return app


def run() -> int:
    app = create_application()
    splash = _splash()
    splash.show()
    app.processEvents()
    window = MainWindow(Database(database_path()))

    def reveal_window() -> None:
        window.show()
        splash.finish(window)

    QTimer.singleShot(700, reveal_window)
    return app.exec()
