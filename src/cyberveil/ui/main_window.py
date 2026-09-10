"""Phase 1 application shell for telemetry collection and persisted audit history."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from cyberveil.collectors import ReplayScenario
from cyberveil.domain import AppSettings, CapabilityReport, ScanSource
from cyberveil.storage import Database
from cyberveil.ui.components import AmbientWidget, icon
from cyberveil.ui.i18n import Translator
from cyberveil.ui.pages import DashboardPage, HistoryPage, LogsPage, NotificationsPage, SettingsPage, show_error
from cyberveil.ui.theme import COLORS
from cyberveil.ui.workers import ScanThread


class Header(QFrame):
    back_requested = Signal()
    notifications_requested = Signal()
    settings_requested = Signal()

    def __init__(self, translator: Translator) -> None:
        super().__init__()
        self.translator = translator
        self.setFixedHeight(72)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(28, 12, 28, 8)
        layout.setSpacing(12)
        self.back = QPushButton()
        self.back.setObjectName("ghost")
        self.back.setIcon(icon("back", COLORS["text"], 26))
        self.back.setFixedSize(46, 46)
        self.back.clicked.connect(self.back_requested)
        self.back.hide()
        layout.addWidget(self.back)
        layout.addStretch()
        self.brand = QLabel('CYBER<span style="color:#22D3C5">VEIL</span>')
        self.brand.setObjectName("brand")
        self.brand.setTextFormat(Qt.TextFormat.RichText)
        self.brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.brand)
        layout.addStretch()
        self.notifications = QPushButton()
        self.notifications.setObjectName("ghost")
        self.notifications.setIcon(icon("bell", COLORS["text"], 25))
        self.notifications.setFixedSize(46, 46)
        self.notifications.clicked.connect(self.notifications_requested)
        layout.addWidget(self.notifications)
        self.settings = QPushButton()
        self.settings.setObjectName("ghost")
        self.settings.setIcon(icon("settings", COLORS["text"], 25))
        self.settings.setFixedSize(46, 46)
        self.settings.clicked.connect(self.settings_requested)
        layout.addWidget(self.settings)
        self.retranslate()

    def set_can_go_back(self, value: bool) -> None:
        self.back.setVisible(value)

    def retranslate(self) -> None:
        self.back.setAccessibleName(self.translator("back"))
        self.back.setToolTip(self.translator("back"))
        self.notifications.setAccessibleName(self.translator("notifications"))
        self.notifications.setToolTip(self.translator("notifications"))
        self.settings.setAccessibleName(self.translator("settings"))
        self.settings.setToolTip(self.translator("settings"))


class MainWindow(QMainWindow):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.settings = database.load_settings()
        self.translator = Translator(self.settings.language)
        self.scan_thread: ScanThread | None = None
        self.current_process_count = 0
        self.current_sample_count = 0
        self._history: list[str] = []

        self.setWindowTitle("CYBERVEIL")
        self.resize(1240, 800)
        self.setMinimumSize(1024, 700)
        root = AmbientWidget()
        root.setObjectName("ambient")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.header = Header(self.translator)
        layout.addWidget(self.header)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self.dashboard = DashboardPage(self.translator, "telemetry-v1")
        self.history_page = HistoryPage(self.translator, database)
        self.logs_page = LogsPage(self.translator, database)
        self.notifications_page = NotificationsPage(self.translator, database)
        self.settings_page = SettingsPage(self.translator, self.settings)
        self.pages: dict[str, QWidget] = {
            "dashboard": self.dashboard,
            "history": self.history_page,
            "logs": self.logs_page,
            "notifications": self.notifications_page,
            "settings": self.settings_page,
        }
        for page in self.pages.values():
            self.stack.addWidget(page)

        self.header.back_requested.connect(self.go_back)
        self.header.notifications_requested.connect(lambda: self.navigate("notifications"))
        self.header.settings_requested.connect(lambda: self.navigate("settings"))
        self.dashboard.navigate.connect(self.navigate)
        self.dashboard.start_live.connect(lambda: self.start_scan(ScanSource.LIVE))
        self.dashboard.start_demo.connect(lambda: self.start_scan(ScanSource.REPLAY))
        self.dashboard.stop_scan.connect(self.stop_scan)
        self.settings_page.settings_saved.connect(self.save_settings)
        self._apply_language()
        self.navigate("dashboard", remember=False)

    def navigate(self, name: str, *, remember: bool = True) -> None:
        page = self.pages.get(name)
        if page is None:
            return
        current_name = self.current_page_name()
        if remember and current_name != name and name != "dashboard":
            self._history.append(current_name)
        self.stack.setCurrentWidget(page)
        self.header.set_can_go_back(name != "dashboard")
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()

    def current_page_name(self) -> str:
        current = self.stack.currentWidget()
        return next((name for name, page in self.pages.items() if page is current), "dashboard")

    def go_back(self) -> None:
        target = self._history.pop() if self._history else "dashboard"
        self.navigate(target, remember=False)

    def start_scan(self, source: ScanSource) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.current_process_count = self.current_sample_count = 0
        self.dashboard.set_metrics(0, 0, 0)
        self.dashboard.set_running(True, replay=source == ScanSource.REPLAY)
        self.scan_thread = ScanThread(
            self.database,
            source=source,
            scenario=ReplayScenario.SUSPICIOUS_BURST,
            parent=self,
        )
        self.scan_thread.telemetry.connect(self._telemetry_updated)
        self.scan_thread.capabilities.connect(self._capabilities_updated)
        self.scan_thread.scan_finished.connect(self._scan_finished)
        self.scan_thread.failed.connect(self._scan_failed)
        self.scan_thread.start()
        self.navigate("dashboard", remember=False)

    def stop_scan(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            self.dashboard.status_title.setText(self.translator("stopping"))
            self.scan_thread.request_stop()

    def _telemetry_updated(self, sample_count: int, process_count: int) -> None:
        self.current_sample_count = sample_count
        self.current_process_count = process_count
        self.dashboard.set_metrics(sample_count, process_count, 0)

    def _capabilities_updated(self, report: CapabilityReport) -> None:
        self.dashboard.set_capabilities(report)

    def _scan_finished(self, session_id: str, status: str) -> None:
        del session_id, status
        self.dashboard.mark_complete()
        self.history_page.refresh()
        self.logs_page.refresh()
        if self.scan_thread:
            self.scan_thread.deleteLater()
            self.scan_thread = None

    def _scan_failed(self, message: str) -> None:
        self.dashboard.set_running(False)
        show_error(self, self.translator("error"), message)
        if self.scan_thread:
            self.scan_thread.deleteLater()
            self.scan_thread = None

    def save_settings(self, settings: AppSettings) -> None:
        self.settings = settings
        self.database.save_settings(settings)
        self.translator.set_language(settings.language)
        self._apply_language()
        self.dashboard.radar.set_active(
            bool(self.scan_thread and self.scan_thread.isRunning()),
            reduced_motion=settings.reduced_motion,
        )

    def _apply_language(self) -> None:
        direction = Qt.LayoutDirection.RightToLeft if self.translator.is_rtl else Qt.LayoutDirection.LeftToRight
        self.setLayoutDirection(direction)
        self.header.retranslate()
        for page in self.pages.values():
            retranslate = getattr(page, "retranslate", None)
            if callable(retranslate):
                retranslate()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.request_stop()
            self.scan_thread.wait(4_000)
        self.database.close()
        super().closeEvent(event)
