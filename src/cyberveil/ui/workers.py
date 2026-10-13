from __future__ import annotations

import threading
import time

from PySide6.QtCore import QObject, QRunnable, QThread, Signal

from cyberveil.collectors import PsutilCollector, ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import CompositeClassifier
from cyberveil.domain import AppSettings, LogRecord, ScanSource, ScanStatus
from cyberveil.engine import MonitoringEngine
from cyberveil.paths import bundled_model_path
from cyberveil.storage import Database


class ScanThread(QThread):
    session_started = Signal(str)
    telemetry = Signal(int, int)
    detection = Signal(object)
    capabilities = Signal(object)
    scan_finished = Signal(str, str)
    failed = Signal(str)

    def __init__(
        self,
        database: Database,
        settings: AppSettings,
        *,
        source: ScanSource,
        scenario: ReplayScenario = ReplayScenario.SUSPICIOUS_BURST,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.database = database
        self.settings = settings
        self.source = source
        self.scenario = scenario
        self._stop_requested = threading.Event()

    def request_stop(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        engine = MonitoringEngine(
            self.database,
            CompositeClassifier(bundled_model_path()),
            self.settings,
            source=self.source,
        )
        try:
            engine.start()
            self.session_started.emit(engine.session_id)
            if self.source == ScanSource.REPLAY:
                self._run_replay(engine)
            else:
                self._run_live(engine)
                if engine.sample_count == 0 and not self._stop_requested.is_set():
                    raise RuntimeError("No processes could be observed; check operating-system permissions.")
            status = ScanStatus.STOPPED if self._stop_requested.is_set() else ScanStatus.COMPLETED
            engine.finish(status)
            self.scan_finished.emit(engine.session_id, status.value)
        except Exception as exc:  # worker boundary reports and records failure
            engine.finish(ScanStatus.FAILED, str(exc))
            self.failed.emit(str(exc))

    def _run_replay(self, engine: MonitoringEngine) -> None:
        for batch in replay_samples(self.scenario, engine.session_id):
            if self._stop_requested.is_set():
                break
            for result in engine.ingest(batch):
                self.detection.emit(result)
            self.telemetry.emit(engine.sample_count, len(batch))
            self.msleep(130)

    def _run_live(self, engine: MonitoringEngine) -> None:
        collector = PsutilCollector()
        last_capabilities = None
        next_sample = time.monotonic()
        while not self._stop_requested.wait(max(0, next_sample - time.monotonic())):
            batch = collector.collect(engine.session_id)
            for result in engine.ingest(batch):
                self.detection.emit(result)
            capabilities = collector.capabilities
            self.capabilities.emit(capabilities)
            if capabilities != last_capabilities:
                self.database.log(LogRecord(
                    level="WARNING" if capabilities.is_degraded else "INFO",
                    event="telemetry.capabilities", message="Telemetry capabilities updated",
                    context={"session_id": engine.session_id, **capabilities.model_dump(mode="json")},
                ))
                last_capabilities = capabilities
            self.telemetry.emit(engine.sample_count, len(batch))
            next_sample = max(next_sample + 1.0, time.monotonic())


class JobSignals(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    failed_with_context = Signal(object, str)


class FunctionJob(QRunnable):
    def __init__(self, function: object, *args: object, **kwargs: object) -> None:
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.signals = JobSignals()

    def run(self) -> None:
        try:
            result = self.function(*self.args, **self.kwargs)  # type: ignore[operator]
        except Exception as exc:
            self.signals.failed_with_context.emit(self.args[0] if self.args else None, str(exc))
            self.signals.failed.emit(str(exc))
        else:
            self.signals.succeeded.emit(result)
