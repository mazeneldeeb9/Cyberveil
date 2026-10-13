"""
THESIS: Make behavior visible as a calm operating instrument; refuse a generic metric-card dashboard.
OWN-WORLD: Deep navy field, precise teal instrumentation, restrained luminous depth, and consistent line controls.
STORY: The user sees protection readiness, starts observation, understands evidence, and takes a guarded action.
FIRST VIEWPORT: A large live radar and plain-language state dominate;
scan controls sit beside it and evidence routes follow.
FORM: The supplied CYBERVEIL desktop references are the incumbent authority; no generated direction seed applies.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md
"""

from __future__ import annotations

import platform
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Qt, QThreadPool, Signal, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from cyberveil.collectors import ReplayScenario
from cyberveil.detection import CompositeClassifier
from cyberveil.domain import (
    AppSettings,
    CapabilityReport,
    DetectionDisposition,
    DetectionResult,
    ForensicAnalysis,
    LogRecord,
    RemediationAction,
    RemediationRequest,
    RemediationResult,
    RemediationStatus,
    ScanRecord,
    ScanSource,
    ScanStatus,
    Severity,
    utc_now,
)
from cyberveil.forensics.service import ForensicService
from cyberveil.integrations import OllamaExplainer
from cyberveil.integrations.ollama import ReportExplanation
from cyberveil.paths import bundled_model_path, report_dir
from cyberveil.remediation import ProcessRemediator
from cyberveil.remediation.demo import HarmlessDemo
from cyberveil.reports import ReportService
from cyberveil.storage import Database
from cyberveil.ui.components import AmbientWidget, icon
from cyberveil.ui.i18n import Translator
from cyberveil.ui.pages import (
    DashboardPage,
    DetectionDialog,
    ForensicsPage,
    HistoryPage,
    LogsPage,
    NotificationsPage,
    ReportPage,
    ReportsPage,
    SettingsPage,
    show_error,
)
from cyberveil.ui.theme import COLORS
from cyberveil.ui.workers import FunctionJob, ScanThread


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
        self.brand = QLabel()
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
        self.brand.setText('CYBER<span style="color:#22D3C5">VEIL</span>')
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
        self.classifier = CompositeClassifier(bundled_model_path())
        self.report_service = ReportService(database)
        self.remediator = ProcessRemediator()
        self.thread_pool = QThreadPool.globalInstance()
        self.scan_thread: ScanThread | None = None
        self.current_session_id: str | None = None
        self.current_process_count = 0
        self.current_sample_count = 0
        self.current_detection_count = 0
        self._dialogs: set[DetectionDialog] = set()
        self._history: list[str] = []
        self._pending_actions: set[str] = set()
        self._action_detections: dict[str, DetectionResult] = {}
        self._demo_processes: dict[str, tuple[HarmlessDemo, str]] = {}
        self._pending_explanation: tuple[str, str] | None = None
        self._forensics_running = False
        self._closing = False

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

        self.dashboard = DashboardPage(self.translator, self.classifier.version)
        self.history_page = HistoryPage(self.translator, database)
        self.logs_page = LogsPage(self.translator, database)
        self.notifications_page = NotificationsPage(self.translator, database)
        self.reports_page = ReportsPage(self.translator, database)
        self.report_page = ReportPage(self.translator)
        self.settings_page = SettingsPage(self.translator, self.settings)
        self.forensics_page = ForensicsPage(self.translator)
        self.pages: dict[str, QWidget] = {
            "dashboard": self.dashboard,
            "history": self.history_page,
            "logs": self.logs_page,
            "notifications": self.notifications_page,
            "reports": self.reports_page,
            "report": self.report_page,
            "settings": self.settings_page,
            "forensics": self.forensics_page,
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
        self.history_page.report_requested.connect(self.open_report)
        self.notifications_page.detection_requested.connect(self.open_detection_by_id)
        self.reports_page.report_requested.connect(self.open_report)
        self.reports_page.export_requested.connect(self.export_report)
        self.report_page.export_requested.connect(self.export_report)
        self.report_page.explain_requested.connect(self.explain_report)
        self.settings_page.settings_saved.connect(self.save_settings)
        self.settings_page.forensics_requested.connect(lambda: self.navigate("forensics"))
        self.settings_page.demo_process_requested.connect(self.start_demo_process)
        self.settings_page.retention_requested.connect(self.apply_retention)
        self.forensics_page.analyze_requested.connect(self.analyze_memory)
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
        self.current_process_count = self.current_sample_count = self.current_detection_count = 0
        self.dashboard.set_metrics(0, 0, 0)
        self.dashboard.set_running(True, replay=source == ScanSource.REPLAY)
        self.scan_thread = ScanThread(
            self.database,
            self.settings.model_copy(deep=True),
            source=source,
            scenario=ReplayScenario.SUSPICIOUS_BURST,
            parent=self,
        )
        self.scan_thread.session_started.connect(self._scan_started)
        self.scan_thread.telemetry.connect(self._telemetry_updated)
        self.scan_thread.detection.connect(self._detection_created)
        self.scan_thread.capabilities.connect(self._capabilities_updated)
        self.scan_thread.scan_finished.connect(self._scan_finished)
        self.scan_thread.failed.connect(self._scan_failed)
        self.scan_thread.finished.connect(self._release_scan_thread)
        self.scan_thread.start()
        self.dashboard.radar.set_active(True, reduced_motion=self.settings.reduced_motion)
        self.navigate("dashboard", remember=False)

    def stop_scan(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            self.dashboard.status_title.setText(self.translator("stopping"))
            self.scan_thread.request_stop()

    def _scan_started(self, session_id: str) -> None:
        self.current_session_id = session_id

    def _telemetry_updated(self, sample_count: int, process_count: int) -> None:
        if self._closing:
            return
        self.current_sample_count = sample_count
        self.current_process_count = process_count
        self.dashboard.set_metrics(sample_count, process_count, self.current_detection_count)

    def _capabilities_updated(self, report: CapabilityReport) -> None:
        if self._closing:
            return
        self.dashboard.set_capabilities(report)

    def _detection_created(self, detection: DetectionResult) -> None:
        if self._closing:
            return
        self.current_detection_count += 1
        self.dashboard.set_metrics(self.current_sample_count, self.current_process_count, self.current_detection_count)
        self.notifications_page.refresh()
        if detection.severity != Severity.HIGH:
            return
        if self.settings.auto_block and detection.source == ScanSource.REPLAY:
            self._run_remediation(detection, RemediationAction.TERMINATE, confirmed_by="auto-policy")
        else:
            self.show_detection(detection)

    def _scan_finished(self, session_id: str, status: str) -> None:
        if self._closing:
            return
        self.dashboard.mark_complete()
        self.history_page.refresh()
        self.logs_page.refresh()
        self.reports_page.refresh()

    def _scan_failed(self, message: str) -> None:
        if self._closing:
            return
        self.dashboard.set_running(False)
        self.dashboard.status_title.setText(self.translator("error"))
        self.dashboard.status_detail.setText(self.translator("scan_failed_detail"))
        show_error(self, self.translator("error"), message)

    def _release_scan_thread(self) -> None:
        if self.scan_thread and not self.scan_thread.isRunning():
            self.scan_thread.deleteLater()
            self.scan_thread = None

    def show_detection(self, detection: DetectionResult) -> None:
        dialog = DetectionDialog(self.translator, detection, self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._dialogs.add(dialog)
        dialog.destroyed.connect(lambda: self._dialogs.discard(dialog))
        dialog.ignore_requested.connect(lambda item: self._ignore_from_dialog(dialog, item))
        dialog.block_requested.connect(lambda item: self._block_from_dialog(dialog, item))
        dialog.rejected.connect(lambda: self._finish_demo(detection.detection_id))
        dialog.open()

    def _ignore_from_dialog(self, dialog: DetectionDialog, detection: DetectionResult) -> None:
        dialog.accept()
        self.ignore_detection(detection)

    def _block_from_dialog(self, dialog: DetectionDialog, detection: DetectionResult) -> None:
        if detection.source != ScanSource.REPLAY:
            answer = QMessageBox.question(
                self,
                self.translator("confirm_block"),
                self.translator("confirm_block_detail").format(name=detection.process_name, pid=detection.pid),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        dialog.accept()
        self._run_remediation(detection, RemediationAction.TERMINATE)

    def open_detection_by_id(self, detection_id: str) -> None:
        detection = self.database.get_detection(detection_id)
        if detection:
            self.show_detection(detection)

    def ignore_detection(self, detection: DetectionResult) -> None:
        request = RemediationRequest(
            detection_id=detection.detection_id,
            pid=detection.pid,
            process_started_at=detection.process_started_at,
            process_name=detection.process_name,
            action=RemediationAction.IGNORE,
            simulation=detection.source == ScanSource.REPLAY,
        )
        result = self.remediator.execute(request)
        self.database.record_remediation(result)
        self._finish_demo(detection.detection_id)
        self.database.log(
            LogRecord(
                event="detection.ignored",
                message=result.message,
                context={"detection_id": detection.detection_id},
            )
        )
        self.notifications_page.refresh()

    def _run_remediation(
        self,
        detection: DetectionResult,
        action: RemediationAction,
        *,
        confirmed_by: str = "user",
    ) -> None:
        if detection.detection_id in self._pending_actions:
            return
        current = self.database.get_detection(detection.detection_id)
        if current is None or current.disposition == DetectionDisposition.BLOCKED:
            return
        self._pending_actions.add(detection.detection_id)
        self._action_detections[detection.detection_id] = detection
        request = RemediationRequest(
            detection_id=detection.detection_id,
            pid=detection.pid,
            process_started_at=detection.process_started_at,
            process_name=detection.process_name,
            action=action,
            confirmed_by=confirmed_by,
            simulation=detection.source == ScanSource.REPLAY,
        )
        job = FunctionJob(self.remediator.execute, request)
        job.signals.succeeded.connect(self._remediation_ready)
        job.signals.failed_with_context.connect(self._remediation_job_failed)
        self.thread_pool.start(job)

    @Slot(object)
    def _remediation_ready(self, result: object) -> None:
        if isinstance(result, RemediationResult):
            detection = self._action_detections.pop(result.detection_id, None)
            if detection:
                self._remediation_finished(detection, result)

    @Slot(object, str)
    def _remediation_job_failed(self, request: object, message: str) -> None:
        if isinstance(request, RemediationRequest):
            self._action_detections.pop(request.detection_id, None)
            self._pending_actions.discard(request.detection_id)
        show_error(self, self.translator("remediation_failed"), message)

    def _remediation_finished(self, detection: DetectionResult, result: object) -> None:
        self._pending_actions.discard(detection.detection_id)
        if not isinstance(result, RemediationResult):
            return
        self.database.record_remediation(result)
        succeeded = result.status == RemediationStatus.SUCCEEDED
        self._finish_demo(detection.detection_id)
        title = self.translator("remediation_success" if succeeded else "remediation_failed")
        box = QMessageBox(self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setWindowTitle(title)
        box.setText(title)
        box.setInformativeText(result.message)
        box.setIcon(QMessageBox.Icon.Information if succeeded else QMessageBox.Icon.Warning)
        box.exec()
        self.notifications_page.refresh()
        self.history_page.refresh()
        self.reports_page.refresh()

    def open_report(self, session_id: str) -> None:
        try:
            report = self.report_service.build(session_id)
        except ValueError as exc:
            show_error(self, self.translator("error"), str(exc))
            return
        self.report_page.set_report(report)
        self.navigate("report")

    def export_report(self, session_id: str, format_name: str) -> None:
        suggested = report_dir() / f"cyberveil-{session_id[:8]}.{format_name}"
        path, _ = QFileDialog.getSaveFileName(self, self.translator(f"export_{format_name}"), str(suggested))
        if not path:
            return
        try:
            report = self.report_service.build(session_id)
            destination = Path(path)
            if format_name == "pdf":
                self.report_service.export_pdf(report, destination, language=self.settings.language)
            elif format_name == "csv":
                self.report_service.export_csv(report, destination, language=self.settings.language)
            else:
                self.report_service.export_json(report, destination, language=self.settings.language)
        except (ValueError, OSError) as exc:
            show_error(self, self.translator("error"), str(exc))
            return
        QMessageBox.information(self, self.translator(f"export_{format_name}"), str(destination))

    def explain_report(self, session_id: str) -> None:
        if self._pending_explanation:
            return
        report = self.report_service.build(session_id)
        self._pending_explanation = (session_id, self.settings.language)
        self.report_page.explain_button.setEnabled(False)
        self.report_page.explain_button.setText(self.translator("explanation_loading"))
        explainer = OllamaExplainer(self.settings.ollama_model if self.settings.ollama_enabled else "",
                                   redact_sensitive=self.settings.redact_sensitive)
        job = FunctionJob(explainer.explain, report, language=self.settings.language)
        job.signals.succeeded.connect(self._explanation_ready)
        job.signals.failed.connect(self._explanation_failed)
        self.thread_pool.start(job)

    @Slot(object)
    def _explanation_ready(self, explanation: object) -> None:
        if self._closing:
            return
        pending = self._pending_explanation
        self._pending_explanation = None
        self.report_page.explain_button.setEnabled(True)
        self.report_page.explain_button.setText(self.translator("explain"))
        if not isinstance(explanation, ReportExplanation):
            return
        current = self.report_page.report
        if current is None or pending != (current.scan.session_id, self.settings.language):
            return
        self.report_page.set_explanation(
            explanation.summary,
            explanation.impact,
            explanation.next_steps,
            explanation.generated_by,
        )

    @Slot(str)
    def _explanation_failed(self, message: str) -> None:
        if self._closing:
            return
        self._pending_explanation = None
        self.report_page.explain_button.setEnabled(True)
        self.report_page.explain_button.setText(self.translator("explain"))
        show_error(self, self.translator("error"), message)

    def apply_retention(self) -> None:
        if self.scan_thread or self.thread_pool.activeThreadCount() or self._demo_processes:
            self.statusBar().showMessage(self.translator("wait_for_jobs"))
            return
        days = self.settings_page.retention.value()
        answer = QMessageBox.question(
            self, self.translator("retention_confirm"), self.translator("retention_detail").format(days=days),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        scans, logs = self.database.purge_history(days)
        self.statusBar().showMessage(self.translator("retention_done").format(scans=scans, logs=logs))
        for page in (self.history_page, self.logs_page, self.reports_page, self.notifications_page):
            page.refresh()

    def save_settings(self, settings: AppSettings) -> None:
        if not self.classifier.auto_block_allowed:
            settings = settings.model_copy(update={"auto_block": False})
        self.settings = settings
        self.settings_page.set_settings(settings)
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

    def analyze_memory(self, image_path: str, operating_system: str) -> None:
        if self._forensics_running:
            return
        self._forensics_running = True
        service = ForensicService(self.database)
        job = FunctionJob(service.analyze, Path(image_path), operating_system)
        job.signals.succeeded.connect(self._forensics_ready)
        job.signals.failed.connect(self._forensics_failed)
        self.thread_pool.start(job)

    @Slot(object)
    def _forensics_ready(self, result: object) -> None:
        if self._closing:
            return
        self._forensics_running = False
        if not isinstance(result, ForensicAnalysis):
            return
        self.forensics_page.set_result(result)
        self.history_page.refresh()
        self.reports_page.refresh()
        self.logs_page.refresh()

    @Slot(str)
    def _forensics_failed(self, message: str) -> None:
        if self._closing:
            return
        self._forensics_running = False
        self.forensics_page.set_error(message)

    def start_demo_process(self) -> None:
        if self._demo_processes:
            return
        demo = HarmlessDemo()
        session_id = str(uuid4())
        self.database.create_scan(
            ScanRecord(
                session_id=session_id,
                source=ScanSource.DEMO_PROCESS,
                status=ScanStatus.RUNNING,
                started_at=utc_now(),
                operating_system=platform.system(),
                model_version="manual-containment-demo",
            )
        )
        detection = demo.detection(session_id)
        self.database.save_detection(detection)
        self._demo_processes[detection.detection_id] = (demo, session_id)
        self.database.log(
            LogRecord(
                event="demo.started",
                message="Harmless child launched for confirmed termination",
                context={"session_id": session_id, "pid": demo.child.pid},
            )
        )
        self.show_detection(detection)

    def _finish_demo(self, detection_id: str) -> None:
        entry = self._demo_processes.pop(detection_id, None)
        if entry:
            demo, session_id = entry
            demo.close()
            self.database.finish_scan(session_id, ScanStatus.COMPLETED, 0, 1)
            self.history_page.refresh()
            self.reports_page.refresh()

    def closeEvent(self, event: object) -> None:
        if self.thread_pool.activeThreadCount() or self._pending_actions:
            self.statusBar().showMessage(self.translator("wait_for_jobs"))
            event.ignore()  # type: ignore[attr-defined]
            return
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.request_stop()
            if not self.scan_thread.wait(4_000):
                event.ignore()  # type: ignore[attr-defined]
                return
        for detection_id in list(self._demo_processes):
            self._finish_demo(detection_id)
        self._closing = True
        self.database.close()
        super().closeEvent(event)  # type: ignore[arg-type]
