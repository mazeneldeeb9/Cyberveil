from __future__ import annotations

import json
from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cyberveil.domain import (
    AppSettings,
    CapabilityReport,
    Severity,
)
from cyberveil.storage import Database
from cyberveil.ui.components import EmptyState, MetricBlock, RadarWidget, icon
from cyberveil.ui.i18n import Translator
from cyberveil.ui.theme import COLORS


def page_heading(title: str, detail: str) -> tuple[QWidget, QLabel, QLabel]:
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(5)
    title_label = QLabel(title)
    title_label.setObjectName("pageTitle")
    detail_label = QLabel(detail)
    detail_label.setObjectName("body")
    detail_label.setWordWrap(True)
    layout.addWidget(title_label)
    layout.addWidget(detail_label)
    return widget, title_label, detail_label


def configure_table(table: QTableWidget) -> None:
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.setShowGrid(False)
    table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)


class DashboardPage(QWidget):
    start_live = Signal()
    start_demo = Signal()
    stop_scan = Signal()
    navigate = Signal(str)

    def __init__(self, translator: Translator, model_version: str) -> None:
        super().__init__()
        self.translator = translator
        self.model_version = model_version
        self._running = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(54, 34, 54, 42)
        outer.setSpacing(24)

        top = QHBoxLayout()
        top.setSpacing(16)
        title_col = QVBoxLayout()
        title_col.setSpacing(8)
        self.title = QLabel()
        self.title.setObjectName("pageTitle")
        self.subtitle = QLabel()
        self.subtitle.setObjectName("body")
        self.lab = QLabel()
        self.lab.setObjectName("labBadge")
        self.lab.setSizePolicy(self.lab.sizePolicy().horizontalPolicy(), self.lab.sizePolicy().verticalPolicy())
        title_col.addWidget(self.title)
        title_col.addWidget(self.subtitle)
        title_col.addWidget(self.lab, 0, Qt.AlignmentFlag.AlignLeft)
        title_col.addStretch()
        top.addLayout(title_col, 1)
        top.addStretch()
        outer.addLayout(top)

        hero = QFrame()
        hero.setObjectName("panel")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(34, 28, 34, 28)
        hero_layout.setSpacing(30)
        copy = QVBoxLayout()
        copy.setSpacing(12)
        self.status_title = QLabel()
        self.status_title.setObjectName("heroTitle")
        self.status_title.setWordWrap(True)
        self.status_detail = QLabel()
        self.status_detail.setObjectName("body")
        self.status_detail.setWordWrap(True)
        self.status_detail.setMaximumWidth(560)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        buttons = QHBoxLayout()
        buttons.setSpacing(12)
        self.primary = QPushButton()
        self.primary.setObjectName("primary")
        self.primary.setIcon(icon("play", COLORS["ink"], 22))
        self.primary.setIconSize(self.primary.iconSize().expandedTo(self.primary.iconSize()))
        self.primary.clicked.connect(self._primary_clicked)
        self.demo = QPushButton()
        self.demo.setIcon(icon("shield", COLORS["accent"], 22))
        self.demo.clicked.connect(self.start_demo)
        buttons.addWidget(self.primary, 2)
        buttons.addWidget(self.demo, 1)
        copy.addStretch()
        copy.addWidget(self.status_title)
        copy.addWidget(self.status_detail)
        copy.addWidget(self.progress)
        copy.addSpacing(5)
        copy.addLayout(buttons)
        copy.addStretch()
        self.radar = RadarWidget()
        hero_layout.addLayout(copy, 3)
        hero_layout.addWidget(self.radar, 2, Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(hero, 1)

        metrics = QFrame()
        metrics.setObjectName("metricStrip")
        metric_layout = QHBoxLayout(metrics)
        metric_layout.setContentsMargins(22, 2, 22, 2)
        metric_layout.setSpacing(20)
        self.metric_processes = MetricBlock("")
        self.metric_samples = MetricBlock("")
        self.metric_detections = MetricBlock("")
        self.metric_model = MetricBlock("", "")
        for block in (
            self.metric_processes,
            self.metric_samples,
            self.metric_detections,
            self.metric_model,
        ):
            metric_layout.addWidget(block, 1)
        outer.addWidget(metrics)

        actions = QHBoxLayout()
        actions.setSpacing(14)
        self.history_button = self._action_button("history", lambda: self.navigate.emit("history"))
        self.logs_button = self._action_button("logs", lambda: self.navigate.emit("logs"))
        actions.addWidget(self.history_button)
        actions.addWidget(self.logs_button)
        outer.addLayout(actions)
        self.retranslate()

    def _action_button(self, kind: str, callback: Callable[[], None]) -> QPushButton:
        button = QPushButton()
        button.setObjectName("actionTile")
        button.setIcon(icon(kind, COLORS["accent"], 36))
        button.setIconSize(button.iconSize().expandedTo(button.iconSize()))
        button.clicked.connect(callback)
        return button

    def _primary_clicked(self) -> None:
        self.stop_scan.emit() if self._running else self.start_live.emit()

    def set_running(self, running: bool, *, replay: bool = False) -> None:
        self._running = running
        self.radar.set_active(running, reduced_motion=False)
        self.progress.setVisible(running)
        self.demo.setEnabled(not running)
        self.status_title.setText(self.translator("scanning") if running else self.translator("idle"))
        self.status_detail.setText(self.translator("scanning_detail") if running else self.translator("idle_detail"))
        self.primary.setText(self.translator("stop_scan") if running else self.translator("start_scan"))
        self.primary.setIcon(icon("stop" if running else "play", COLORS["ink"], 22))
        if replay and running:
            self.status_detail.setText(self.translator("safe_replay_note"))

    def mark_complete(self) -> None:
        self.set_running(False)
        self.status_title.setText(self.translator("complete"))

    def set_metrics(self, sample_count: int, process_count: int, detection_count: int) -> None:
        self.metric_samples.set_value(f"{sample_count:,}")
        self.metric_processes.set_value(f"{process_count:,}")
        self.metric_detections.set_value(str(detection_count))

    def set_capabilities(self, report: CapabilityReport) -> None:
        value = self.translator("degraded") if report.is_degraded else self.translator("full_visibility")
        self.metric_processes.set_label(f"{self.translator('processes')} · {value}")

    def retranslate(self) -> None:
        self.title.setText(self.translator("dashboard"))
        self.subtitle.setText(self.translator("dashboard_subtitle"))
        self.lab.setText(self.translator("lab_badge"))
        self.status_title.setText(self.translator("scanning") if self._running else self.translator("idle"))
        self.status_detail.setText(
            self.translator("scanning_detail") if self._running else self.translator("idle_detail")
        )
        self.primary.setText(self.translator("stop_scan") if self._running else self.translator("start_scan"))
        self.demo.setText(self.translator("safe_demo"))
        self.metric_processes.set_label(self.translator("processes"))
        self.metric_samples.set_label(self.translator("samples"))
        self.metric_detections.set_label(self.translator("detections"))
        self.metric_model.set_label(self.translator("model"))
        self.metric_model.set_value(
            self.translator("fallback_model")
            if self.model_version.startswith("rules")
            else self.translator("trained_model")
        )
        self.history_button.setText(self.translator("view_history"))
        self.logs_button.setText(self.translator("view_logs"))


class HistoryPage(QWidget):
    report_requested = Signal(str)

    def __init__(self, translator: Translator, database: Database) -> None:
        super().__init__()
        self.translator = translator
        self.database = database
        layout = QVBoxLayout(self)
        layout.setContentsMargins(54, 34, 54, 42)
        layout.setSpacing(20)
        heading, self.title, self.detail = page_heading("", "")
        layout.addWidget(heading)
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName("Search scan history")
        self.search.textChanged.connect(self.refresh)
        layout.addWidget(self.search)
        self.table = QTableWidget(0, 6)
        configure_table(self.table)
        self.table.cellDoubleClicked.connect(self._open_row)
        layout.addWidget(self.table, 1)
        self.empty = EmptyState("", "")
        self.empty.hide()
        layout.addWidget(self.empty, 1)
        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        records = self.database.list_scans(search=self.search.text().strip())
        self.table.setRowCount(len(records))
        self.table.setVisible(bool(records))
        self.empty.setVisible(not records)
        for row, item in enumerate(records):
            duration = "—"
            if item.ended_at:
                seconds = max(0, int((item.ended_at - item.started_at).total_seconds()))
                duration = f"{seconds} {self.translator('seconds')}"
            values = (
                self.translator.format_datetime(item.started_at),
                item.source.value,
                item.status.value,
                str(item.detection_count),
                str(item.blocked_count),
                duration,
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.session_id)
                self.table.setItem(row, column, cell)

    def _open_row(self, row: int, column: int) -> None:
        item = self.table.item(row, 0)
        if item:
            self.report_requested.emit(str(item.data(Qt.ItemDataRole.UserRole)))

    def retranslate(self) -> None:
        self.title.setText(self.translator("history"))
        self.detail.setText(self.translator("history_detail"))
        self.search.setPlaceholderText(self.translator("search_history"))
        self.table.setHorizontalHeaderLabels(
            (
                self.translator("date"),
                self.translator("source"),
                self.translator("status"),
                self.translator("detections"),
                self.translator("blocked"),
                self.translator("duration"),
            )
        )
        self.empty.title_label.setText(self.translator("no_history"))
        self.empty.detail_label.setText(self.translator("no_history_detail"))


class LogsPage(QWidget):
    def __init__(self, translator: Translator, database: Database) -> None:
        super().__init__()
        self.translator = translator
        self.database = database
        layout = QVBoxLayout(self)
        layout.setContentsMargins(54, 34, 54, 42)
        layout.setSpacing(20)
        heading, self.title, self.detail = page_heading("", "")
        layout.addWidget(heading)
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.refresh)
        layout.addWidget(self.search)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.log_view.setFont(QFont("Menlo", 11))
        layout.addWidget(self.log_view, 1)
        self.empty = EmptyState("", "")
        self.empty.hide()
        layout.addWidget(self.empty, 1)
        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        records = self.database.list_logs(search=self.search.text().strip())
        lines = []
        for item in reversed(records):
            context = json.dumps(item.context, ensure_ascii=False, separators=(",", ":"))
            lines.append(f"{item.occurred_at.isoformat()}  {item.level:<8} {item.event:<22} {item.message}  {context}")
        self.log_view.setPlainText("\n".join(lines))
        self.log_view.setVisible(bool(records))
        self.empty.setVisible(not records)

    def retranslate(self) -> None:
        self.title.setText(self.translator("logs"))
        self.detail.setText(self.translator("logs_detail"))
        self.search.setPlaceholderText(self.translator("search_logs"))
        self.empty.title_label.setText(self.translator("no_logs"))
        self.empty.detail_label.setText(self.translator("no_logs_detail"))


class NotificationsPage(QWidget):
    detection_requested = Signal(str)

    def __init__(self, translator: Translator, database: Database) -> None:
        super().__init__()
        self.translator = translator
        self.database = database
        layout = QVBoxLayout(self)
        layout.setContentsMargins(54, 34, 54, 42)
        layout.setSpacing(20)
        heading, self.title, self.detail = page_heading("", "")
        layout.addWidget(heading)
        self.table = QTableWidget(0, 5)
        configure_table(self.table)
        self.table.cellDoubleClicked.connect(self._open_row)
        layout.addWidget(self.table, 1)
        self.empty = EmptyState("", "")
        self.empty.hide()
        layout.addWidget(self.empty, 1)
        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        items = self.database.list_detections(limit=300)
        self.table.setRowCount(len(items))
        self.table.setVisible(bool(items))
        self.empty.setVisible(not items)
        for row, item in enumerate(items):
            values = (
                self.translator.format_datetime(item.observed_at),
                item.process_name,
                f"{item.score:.0%}",
                item.severity.value,
                item.disposition.value,
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.detection_id)
                if column == 3:
                    cell.setForeground(
                        QColor(COLORS["danger"] if item.severity == Severity.HIGH else COLORS["warning"])
                    )
                self.table.setItem(row, column, cell)

    def _open_row(self, row: int, column: int) -> None:
        item = self.table.item(row, 0)
        if item:
            self.detection_requested.emit(str(item.data(Qt.ItemDataRole.UserRole)))

    def retranslate(self) -> None:
        self.title.setText(self.translator("notifications"))
        self.detail.setText(self.translator("no_notifications_detail"))
        self.table.setHorizontalHeaderLabels(
            (
                self.translator("date"),
                self.translator("process"),
                self.translator("score"),
                self.translator("severity"),
                self.translator("action"),
            )
        )
        self.empty.title_label.setText(self.translator("no_notifications"))
        self.empty.detail_label.setText(self.translator("no_notifications_detail"))


class SettingsPage(QWidget):
    settings_saved = Signal(object)

    def __init__(self, translator: Translator, settings: AppSettings) -> None:
        super().__init__()
        self.translator = translator
        self._settings = settings
        outer = QVBoxLayout(self)
        outer.setContentsMargins(54, 34, 54, 42)
        outer.setSpacing(18)
        heading, self.title, self.detail = page_heading("", "")
        outer.addWidget(heading)

        scroll = QScrollArea()
        scroll.setObjectName("settingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.viewport().setObjectName("settingsViewport")
        body = QWidget()
        body.setObjectName("settingsBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(2, 2, 12, 2)
        panel = QFrame()
        panel.setObjectName("panel")
        panel.setMinimumWidth(760)
        panel.setMaximumWidth(1040)
        form = QFormLayout(panel)
        form.setContentsMargins(28, 26, 28, 26)
        form.setHorizontalSpacing(34)
        form.setVerticalSpacing(16)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignTop)

        self.language = QComboBox()
        self.language.addItem("English", "en")
        self.language.addItem("العربية", "ar")
        self.retention = QSpinBox()
        self.retention.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self.retention.setRange(1, 365)
        self.redact = QCheckBox()
        self.reduced_motion = QCheckBox()
        self.labels: list[QLabel] = []
        for widget in (self.language, self.retention, self.redact, self.reduced_motion):
            label = QLabel()
            label.setObjectName("muted")
            self.labels.append(label)
            form.addRow(label, widget)

        body_layout.addWidget(panel, 0, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        body_layout.addStretch()
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        bottom = QHBoxLayout()
        self.saved = QLabel()
        self.saved.setStyleSheet(f"color:{COLORS['success']}")
        self.saved.hide()
        bottom.addWidget(self.saved)
        bottom.addStretch()
        self.save_button = QPushButton()
        self.save_button.setObjectName("primary")
        self.save_button.clicked.connect(self._save)
        bottom.addWidget(self.save_button)
        outer.addLayout(bottom)
        self.set_settings(settings)
        self.retranslate()

    def _save(self) -> None:
        settings = self._settings.model_copy(
            update={
                "language": str(self.language.currentData()),
                "retention_days": self.retention.value(),
                "redact_sensitive": self.redact.isChecked(),
                "reduced_motion": self.reduced_motion.isChecked(),
            }
        )
        self._settings = settings
        self.settings_saved.emit(settings)
        self.saved.setText(self.translator("saved"))
        self.saved.show()

    def set_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        self.language.setCurrentIndex(0 if settings.language == "en" else 1)
        self.retention.setValue(settings.retention_days)
        self.redact.setChecked(settings.redact_sensitive)
        self.reduced_motion.setChecked(settings.reduced_motion)

    def retranslate(self) -> None:
        self.title.setText(self.translator("settings"))
        self.detail.setText(self.translator("settings_phase1_detail"))
        for label, key in zip(
            self.labels,
            ("language", "retention", "redact", "reduced_motion"),
            strict=True,
        ):
            label.setText(self.translator(key))
        self.save_button.setText(self.translator("save"))
        self.saved.setText(self.translator("saved"))


def show_error(parent: QWidget, title: str, message: str) -> None:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Critical)
    box.setWindowTitle(title)
    box.setText(title)
    box.setInformativeText(message)
    box.setStandardButtons(QMessageBox.StandardButton.Close)
    box.exec()
