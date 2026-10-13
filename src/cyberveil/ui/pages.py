from __future__ import annotations

import html
import json
from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
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
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from cyberveil.domain import (
    AppSettings,
    CapabilityReport,
    DetectionDisposition,
    DetectionResult,
    ForensicAnalysis,
    IncidentReport,
    ScanSource,
    Severity,
)
from cyberveil.reports import ReportService
from cyberveil.storage import Database
from cyberveil.ui.components import EmptyState, MetricBlock, RadarWidget, icon
from cyberveil.ui.filters import RecordFilters
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
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("dashboardScroll")
        scroll.viewport().setObjectName("dashboardViewport")
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        body = QWidget()
        body.setObjectName("dashboardBody")
        outer = QVBoxLayout(body)
        scroll.setWidget(body)
        page_layout.addWidget(scroll)
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
        self.capability_note = QLabel()
        self.capability_note.setObjectName("muted")
        self.capability_note.setWordWrap(True)
        self.capability_note.hide()
        title_col.addWidget(self.capability_note)
        title_col.addStretch()
        top.addLayout(title_col, 1)
        top.addStretch()
        outer.addLayout(top)

        hero = QFrame()
        hero.setMinimumHeight(276)
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
        self.reports_button = self._action_button("reports", lambda: self.navigate.emit("reports"))
        actions.addWidget(self.history_button)
        actions.addWidget(self.logs_button)
        actions.addWidget(self.reports_button)
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
        self.capability_note.setText(self.translator("permission_body") if report.is_degraded else "")
        fields = ", ".join((*report.unavailable, *report.permission_denied))
        self.capability_note.setToolTip(fields + "\n" + "\n".join(report.notes))
        self.capability_note.setVisible(report.is_degraded)

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
        self.reports_button.setText(self.translator("view_reports"))


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
        self.filters = RecordFilters(translator)
        self.search = self.filters.search
        self.filters.changed.connect(self.refresh)
        layout.addWidget(self.filters)
        self.table = QTableWidget(0, 6)
        configure_table(self.table)
        self.table.cellActivated.connect(self._open_row)
        layout.addWidget(self.table, 1)
        self.empty = EmptyState("", "")
        self.empty.hide()
        layout.addWidget(self.empty, 1)
        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        selected = self.filters.choice.currentData()
        records = self.database.list_scans(limit=self.filters.limit + 1, search=self.search.text().strip(),
                                           source=ScanSource(selected) if selected else None)
        self.filters.more.setEnabled(len(records) > self.filters.limit)
        records = records[:self.filters.limit]
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
                self.translator.observation(item.source.value),
                self.translator.observation(item.status.value),
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
        self.filters.retranslate()
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
        self.search.setAccessibleName(self.translator("search_logs"))
        self.log_view.setAccessibleName(self.translator("logs"))
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
        self.filters = RecordFilters(translator, detections=True)
        self.filters.changed.connect(self.refresh)
        layout.addWidget(self.filters)
        self.table = QTableWidget(0, 5)
        configure_table(self.table)
        self.table.cellActivated.connect(self._open_row)
        layout.addWidget(self.table, 1)
        self.empty = EmptyState("", "")
        self.empty.hide()
        layout.addWidget(self.empty, 1)
        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        selected = self.filters.choice.currentData()
        items = self.database.list_detections(limit=self.filters.limit + 1,
                                             search=self.filters.search.text().strip(),
                                             severity=Severity(selected) if selected else None)
        self.filters.more.setEnabled(len(items) > self.filters.limit)
        items = items[:self.filters.limit]
        self.table.setRowCount(len(items))
        self.table.setVisible(bool(items))
        self.empty.setVisible(not items)
        for row, item in enumerate(items):
            values = (
                self.translator.format_datetime(item.observed_at),
                item.process_name,
                f"{item.score:.0%}",
                self.translator.observation(item.severity.value),
                self.translator.observation(item.disposition.value),
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
        self.filters.retranslate()
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


class ReportsPage(QWidget):
    report_requested = Signal(str)
    export_requested = Signal(str, str)

    def __init__(self, translator: Translator, database: Database) -> None:
        super().__init__()
        self.translator = translator
        self.database = database
        layout = QVBoxLayout(self)
        layout.setContentsMargins(54, 34, 54, 42)
        layout.setSpacing(20)
        heading, self.title, self.detail = page_heading("", "")
        layout.addWidget(heading)
        self.filters = RecordFilters(translator)
        self.filters.changed.connect(self.refresh)
        layout.addWidget(self.filters)
        self.table = QTableWidget(0, 5)
        configure_table(self.table)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellActivated.connect(self._open)
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        actions.addStretch()
        self.open_button = QPushButton()
        self.open_button.setObjectName("primary")
        self.open_button.clicked.connect(self._open_selected)
        self.pdf_button = QPushButton()
        self.pdf_button.setIcon(icon("export", COLORS["accent"], 20))
        self.pdf_button.clicked.connect(lambda: self._export("pdf"))
        self.json_button = QPushButton()
        self.json_button.clicked.connect(lambda: self._export("json"))
        self.csv_button = QPushButton()
        self.csv_button.clicked.connect(lambda: self._export("csv"))
        for button in (self.csv_button, self.json_button, self.pdf_button, self.open_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.retranslate()
        self.refresh()

    def refresh(self) -> None:
        selected = self.filters.choice.currentData()
        records = self.database.list_scans(limit=self.filters.limit + 1, search=self.filters.search.text().strip(),
                                           source=ScanSource(selected) if selected else None)
        self.filters.more.setEnabled(len(records) > self.filters.limit)
        records = records[:self.filters.limit]
        self.table.setRowCount(len(records))
        for row, item in enumerate(records):
            values = (
                self.translator.format_datetime(item.started_at),
                self.translator.observation(item.source.value),
                self.translator.observation(item.status.value),
                str(item.detection_count),
                str(item.blocked_count),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.session_id)
                self.table.setItem(row, column, cell)
        if records:
            self.table.selectRow(0)
        self._selection_changed()

    def _selected_id(self) -> str | None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return str(item.data(Qt.ItemDataRole.UserRole)) if item else None

    def _selection_changed(self) -> None:
        active = self._selected_id() is not None
        for button in (self.open_button, self.pdf_button, self.json_button, self.csv_button):
            button.setEnabled(active)

    def _open(self, row: int, column: int) -> None:
        self._open_selected()

    def _open_selected(self) -> None:
        if session_id := self._selected_id():
            self.report_requested.emit(session_id)

    def _export(self, format_name: str) -> None:
        if session_id := self._selected_id():
            self.export_requested.emit(session_id, format_name)

    def retranslate(self) -> None:
        self.title.setText(self.translator("reports"))
        self.filters.retranslate()
        self.detail.setText(self.translator("reports_detail"))
        self.table.setHorizontalHeaderLabels(
            (
                self.translator("date"),
                self.translator("source"),
                self.translator("status"),
                self.translator("detections"),
                self.translator("blocked"),
            )
        )
        self.open_button.setText(self.translator("open_report"))
        self.pdf_button.setText(self.translator("export_pdf"))
        self.json_button.setText(self.translator("export_json"))
        self.csv_button.setText(self.translator("export_csv"))


class ReportPage(QWidget):
    export_requested = Signal(str, str)
    explain_requested = Signal(str)

    def __init__(self, translator: Translator) -> None:
        super().__init__()
        self.translator = translator
        self.report: IncidentReport | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(54, 34, 54, 42)
        layout.setSpacing(18)
        top = QHBoxLayout()
        heading, self.title, self.detail = page_heading("", "")
        top.addWidget(heading, 1)
        self.badge = QLabel()
        self.badge.setObjectName("labBadge")
        top.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(top)
        self.view_mode = QComboBox()
        self.view_mode.addItems(["", ""])
        self.view_mode.currentIndexChanged.connect(self._render)
        layout.addWidget(self.view_mode, 0, Qt.AlignmentFlag.AlignLeading)
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(False)
        self.browser.setOpenLinks(False)
        layout.addWidget(self.browser, 1)
        actions = QHBoxLayout()
        actions.addStretch()
        self.explain_button = QPushButton()
        self.explain_button.clicked.connect(self._explain)
        self.csv_button = QPushButton()
        self.csv_button.clicked.connect(lambda: self._export("csv"))
        self.json_button = QPushButton()
        self.json_button.clicked.connect(lambda: self._export("json"))
        self.pdf_button = QPushButton()
        self.pdf_button.setObjectName("primary")
        self.pdf_button.clicked.connect(lambda: self._export("pdf"))
        for button in (self.explain_button, self.csv_button, self.json_button, self.pdf_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.retranslate()

    def set_report(self, report: IncidentReport) -> None:
        self.report = report
        self._render()

    def set_explanation(self, summary: str, impact: str, next_steps: tuple[str, ...], source: str) -> None:
        items = "".join(f"<li>{html.escape(text)}</li>" for text in next_steps)
        self.browser.append(
            f"<hr><h2>{self.translator('local_explanation')}</h2>"
            f"<p>{self.translator('explanation_fallback' if source == 'CYBERVEIL template' else 'explanation_ai')}</p>"
            f"<p>{html.escape(summary)}</p><p>{html.escape(impact)}</p>"
            f"<ul>{items}</ul><p><small>{html.escape(source)}</small></p>"
        )

    def _render(self) -> None:
        if self.report:
            self.browser.setHtml(ReportService.to_html(
                self.report, language=self.translator.language,
                full=self.view_mode.currentIndex() == 0, dark=True,
            ))

    def _export(self, format_name: str) -> None:
        if self.report:
            self.export_requested.emit(self.report.scan.session_id, format_name)

    def _explain(self) -> None:
        if self.report:
            self.explain_requested.emit(self.report.scan.session_id)

    def retranslate(self) -> None:
        self.title.setText(self.translator("full_analysis"))
        self.view_mode.setItemText(0, self.translator("full_analysis"))
        self.view_mode.setItemText(1, self.translator("summary_report"))
        self.view_mode.setAccessibleName(self.translator("reports"))
        self.browser.setAccessibleName(self.translator("full_analysis"))
        self.detail.setText(self.translator("reports_detail"))
        self.badge.setText(self.translator("lab_badge"))
        self.explain_button.setText(self.translator("explain"))
        self.csv_button.setText(self.translator("export_csv"))
        self.json_button.setText(self.translator("export_json"))
        self.pdf_button.setText(self.translator("export_pdf"))
        self._render()


class SettingsPage(QWidget):
    settings_saved = Signal(object)
    forensics_requested = Signal()
    demo_process_requested = Signal()
    retention_requested = Signal()

    def __init__(self, translator: Translator, settings: AppSettings) -> None:
        super().__init__()
        self.translator = translator
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
        body_layout.setSpacing(0)
        panel = QFrame()
        panel.setObjectName("panel")
        panel.setMinimumWidth(820)
        panel.setMaximumWidth(1120)
        form = QFormLayout(panel)
        form.setContentsMargins(28, 26, 28, 26)
        form.setHorizontalSpacing(34)
        form.setVerticalSpacing(16)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignTop)
        self.language = QComboBox()
        self.language.addItem("English", "en")
        self.language.addItem("العربية", "ar")
        self.language.setCurrentIndex(0 if settings.language == "en" else 1)
        self.threshold = QSpinBox()
        self.threshold.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self.threshold.setRange(50, 99)
        self.threshold.setSuffix("%")
        self.threshold.setValue(round(settings.detection_threshold * 100))
        self.auto_block = QCheckBox()
        self.auto_block.setChecked(False)
        self.auto_block.setEnabled(False)
        self.retention = QSpinBox()
        self.retention.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self.retention.setRange(1, 365)
        self.retention.setValue(settings.retention_days)
        self.redact = QCheckBox()
        self.redact.setChecked(settings.redact_sensitive)
        self.ollama = QCheckBox()
        self.ollama.setChecked(settings.ollama_enabled)
        self.ollama_model = QLineEdit(settings.ollama_model)
        self.ollama_model.setPlaceholderText("gemma3:4b")
        self.reduced_motion = QCheckBox()
        self.reduced_motion.setChecked(settings.reduced_motion)
        self.labels: list[QLabel] = []
        for widget in (
            self.language,
            self.threshold,
            self.auto_block,
            self.retention,
            self.redact,
            self.ollama,
            self.ollama_model,
            self.reduced_motion,
        ):
            label = QLabel()
            label.setObjectName("muted")
            label.setWordWrap(True)
            label.setMaximumWidth(340)
            label.setBuddy(widget)
            self.labels.append(label)
            form.addRow(label, widget)
        self.forensics_button = QPushButton()
        self.forensics_button.setIcon(icon("memory", COLORS["accent"], 22))
        self.forensics_button.clicked.connect(self.forensics_requested)
        form.addRow(QLabel(), self.forensics_button)
        self.demo_process_button = QPushButton()
        self.demo_process_button.setIcon(icon("shield", COLORS["accent"], 22))
        self.demo_process_button.clicked.connect(self.demo_process_requested)
        form.addRow(QLabel(), self.demo_process_button)
        self.retention_button = QPushButton()
        self.retention_button.clicked.connect(self.retention_requested)
        form.addRow(QLabel(), self.retention_button)
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
        self.retranslate()

    def _save(self) -> None:
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.:/-]{0,200}", self.ollama_model.text().strip()):
            self.saved.setText(self.translator("invalid_model"))
            self.saved.setWordWrap(True)
            self.saved.setStyleSheet(f"color:{COLORS['warning']}")
            self.saved.show()
            self.ollama_model.setFocus()
            return
        settings = AppSettings(
            language=str(self.language.currentData()),
            detection_threshold=self.threshold.value() / 100,
            auto_block=self.auto_block.isChecked(),
            retention_days=self.retention.value(),
            redact_sensitive=self.redact.isChecked(),
            ollama_enabled=self.ollama.isChecked(),
            ollama_model=self.ollama_model.text().strip(),
            reduced_motion=self.reduced_motion.isChecked(),
        )
        self.settings_saved.emit(settings)
        self.saved.setStyleSheet(f"color:{COLORS['success']}")
        self.saved.setText(self.translator("saved"))
        self.saved.show()

    def set_settings(self, settings: AppSettings) -> None:
        self.language.setCurrentIndex(0 if settings.language == "en" else 1)
        self.threshold.setValue(round(settings.detection_threshold * 100))
        self.auto_block.setChecked(False)
        self.retention.setValue(settings.retention_days)
        self.redact.setChecked(settings.redact_sensitive)
        self.ollama.setChecked(settings.ollama_enabled)
        self.ollama_model.setText(settings.ollama_model)
        self.reduced_motion.setChecked(settings.reduced_motion)

    def retranslate(self) -> None:
        self.title.setText(self.translator("settings"))
        self.detail.setText(self.translator("experimental_model"))
        keys = (
            "language",
            "threshold",
            "auto_block",
            "retention",
            "redact",
            "ollama",
            "ollama_model",
            "reduced_motion",
        )
        for label, key in zip(self.labels, keys, strict=True):
            label.setText(self.translator(key))
            if label.buddy():
                label.buddy().setAccessibleName(self.translator(key))
        self.auto_block.setText("")
        self.auto_block.setAccessibleName(self.translator("auto_block"))
        self.auto_block.setToolTip(self.translator("experimental_model"))
        self.demo_process_button.setText(self.translator("demo_process"))
        self.retention_button.setText(self.translator("apply_retention"))
        self.forensics_button.setText(self.translator("forensics"))
        self.forensics_button.setToolTip(self.translator("forensics_detail"))
        self.save_button.setText(self.translator("save"))
        self.saved.setText(self.translator("saved"))


class ForensicsPage(QWidget):
    analyze_requested = Signal(str, str)

    def __init__(self, translator: Translator) -> None:
        super().__init__()
        self.translator = translator
        layout = QVBoxLayout(self)
        layout.setContentsMargins(54, 34, 54, 42)
        layout.setSpacing(18)
        heading, self.title, self.detail = page_heading("", "")
        layout.addWidget(heading)
        panel = QFrame()
        panel.setObjectName("panel")
        form = QFormLayout(panel)
        form.setContentsMargins(28, 24, 28, 24)
        form.setSpacing(16)
        path_row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setReadOnly(True)
        self.choose = QPushButton()
        self.choose.clicked.connect(self._choose)
        path_row.addWidget(self.path, 1)
        path_row.addWidget(self.choose)
        self.os = QComboBox()
        self.os.addItem("Windows", "windows")
        self.os.addItem("Linux", "linux")
        self.os.addItem("macOS", "mac")
        self.image_label = QLabel()
        self.os_label = QLabel()
        form.addRow(self.image_label, path_row)
        form.addRow(self.os_label, self.os)
        layout.addWidget(panel)
        actions = QHBoxLayout()
        self.state = QLabel()
        self.state.setObjectName("muted")
        actions.addWidget(self.state)
        actions.addStretch()
        self.analyze = QPushButton()
        self.analyze.setObjectName("primary")
        self.analyze.clicked.connect(self._analyze)
        actions.addWidget(self.analyze)
        layout.addLayout(actions)
        self.results = QPlainTextEdit()
        self.results.setReadOnly(True)
        self.results.setFont(QFont("Menlo", 11))
        layout.addWidget(self.results, 1)
        self.retranslate()

    def _choose(self) -> None:
        value, _ = QFileDialog.getOpenFileName(self, self.translator("choose_image"))
        if value:
            self.path.setText(value)

    def _analyze(self) -> None:
        from pathlib import Path

        if not Path(self.path.text()).is_file():
            self.set_error(self.translator("choose_required"))
            return
        if self.path.text():
            self.state.setText(self.translator("analysis_running"))
            self.analyze.setEnabled(False)
            self.choose.setEnabled(False)
            self.os.setEnabled(False)
            self.analyze_requested.emit(self.path.text(), str(self.os.currentData()))

    def set_result(self, value: object) -> None:
        serializable = value.model_dump(mode="json") if isinstance(value, ForensicAnalysis) else value
        self.results.setPlainText(json.dumps(serializable, indent=2, ensure_ascii=False, default=str))
        failed = isinstance(value, ForensicAnalysis) and any(f.category == "analysis_error" for f in value.findings)
        self.state.setText(self.translator("analysis_partial" if failed else "analysis_complete"))
        self.analyze.setEnabled(True)
        self.choose.setEnabled(True)
        self.os.setEnabled(True)

    def set_error(self, message: str) -> None:
        self.results.setPlainText(message)
        self.state.setText(self.translator("error"))
        self.analyze.setEnabled(True)
        self.choose.setEnabled(True)
        self.os.setEnabled(True)

    def retranslate(self) -> None:
        self.title.setText(self.translator("forensics"))
        self.detail.setText(self.translator("forensics_detail"))
        self.image_label.setText(self.translator("choose_image"))
        self.os_label.setText(self.translator("operating_system"))
        self.choose.setText(self.translator("choose_image"))
        self.analyze.setText(self.translator("analyze"))
        self.path.setAccessibleName(self.translator("choose_image"))
        self.os.setAccessibleName(self.translator("operating_system"))
        self.results.setAccessibleName(self.translator("forensics"))


class DetectionDialog(QDialog):
    ignore_requested = Signal(object)
    block_requested = Signal(object)

    def __init__(self, translator: Translator, detection: DetectionResult, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.translator = translator
        self.detection = detection
        self.setModal(True)
        self.setMinimumWidth(560)
        self.setWindowTitle(translator("fileless_detected"))
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft if translator.is_rtl else Qt.LayoutDirection.LeftToRight)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 24)
        layout.setSpacing(16)
        top = QHBoxLayout()
        mark = QLabel("!")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(46, 46)
        mark.setStyleSheet(
            f"background:{COLORS['danger']};color:white;border-radius:14px;font-size:26px;font-weight:800"
        )
        copy = QVBoxLayout()
        title = QLabel(translator("fileless_detected"))
        title.setObjectName("sectionTitle")
        detail = QLabel(translator("detected_message"))
        if detection.source == ScanSource.DEMO_PROCESS:
            title.setText(translator("demo_process"))
            detail.setText(translator("demo_process_detail"))
            self.setWindowTitle(translator("demo_process"))
        detail.setObjectName("muted")
        detail.setWordWrap(True)
        copy.addWidget(title)
        copy.addWidget(detail)
        top.addWidget(mark)
        top.addLayout(copy, 1)
        layout.addLayout(top)
        panel = QFrame()
        panel.setObjectName("panel")
        facts = QVBoxLayout(panel)
        facts.setContentsMargins(20, 18, 20, 18)
        process_label = QLabel(f"{translator('process')}: {detection.process_name}  ·  PID {detection.pid}")
        process_label.setTextFormat(Qt.TextFormat.PlainText)
        process_label.setWordWrap(True)
        facts.addWidget(process_label)
        score = QLabel(
            f"{translator('score')}: {detection.score:.0%}  ·  "
            f"{translator('severity')}: {translator.observation(detection.severity.value)}"
        )
        score_color = COLORS["danger"] if detection.severity == Severity.HIGH else COLORS["warning"]
        score.setStyleSheet(f"color:{score_color};font-weight:750")
        facts.addWidget(score)
        reasons = QLabel("\n".join(f"• {translator.observation(reason)}" for reason in detection.reasons) or "—")
        reasons.setWordWrap(True)
        reasons.setTextFormat(Qt.TextFormat.PlainText)
        reasons.setObjectName("muted")
        facts.addWidget(QLabel(translator("why_flagged")))
        facts.addWidget(reasons)
        note = QLabel(translator("evidence_note"))
        note.setObjectName("muted")
        note.setWordWrap(True)
        facts.addWidget(note)
        if detection.missing_fields:
            missing = QLabel(f"{translator('permission_title')}: {', '.join(detection.missing_fields)}")
            missing.setWordWrap(True)
            facts.addWidget(missing)
        if detection.source == ScanSource.REPLAY:
            replay_note = QLabel(translator("safe_replay_note"))
            replay_note.setWordWrap(True)
            replay_note.setObjectName("dim")
            facts.addWidget(replay_note)
        layout.addWidget(panel)
        buttons = QHBoxLayout()
        self.ignore = QPushButton(translator("ignore"))
        self.ignore.clicked.connect(lambda: self.ignore_requested.emit(detection))
        self.block = QPushButton(translator("block_process"))
        if detection.source == ScanSource.REPLAY:
            self.block.setText(translator("simulate_block"))
        resolved = detection.disposition == DetectionDisposition.BLOCKED
        self.block.setEnabled(not resolved)
        self.ignore.setEnabled(not resolved)
        self.ignore.setDefault(True)
        self.block.setObjectName("danger")
        self.block.clicked.connect(lambda: self.block_requested.emit(detection))
        buttons.addStretch()
        buttons.addWidget(self.ignore)
        buttons.addWidget(self.block)
        layout.addLayout(buttons)


def show_error(parent: QWidget, title: str, message: str) -> None:
    box = QMessageBox(parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setIcon(QMessageBox.Icon.Critical)
    box.setWindowTitle(title)
    box.setText(title)
    box.setInformativeText(message)
    box.setStandardButtons(QMessageBox.StandardButton.Close)
    box.exec()
