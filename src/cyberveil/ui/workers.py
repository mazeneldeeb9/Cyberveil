from __future__ import annotations

import platform
import threading
from uuid import uuid4

from PySide6.QtCore import QObject, QThread, Signal

from cyberveil.collectors import PsutilCollector, ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.domain import LogRecord, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.storage import Database


class ScanThread(QThread):
    telemetry = Signal(int, int)
    capabilities = Signal(object)
    scan_finished = Signal(str, str)
    failed = Signal(str)

    def __init__(
        self,
        database: Database,
        *,
        source: ScanSource,
        scenario: ReplayScenario = ReplayScenario.SUSPICIOUS_BURST,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.database = database
        self.source = source
        self.scenario = scenario
        self.session_id = str(uuid4())
        self.sample_count = 0
        self._stop_requested = threading.Event()

    def request_stop(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        self.database.create_scan(
            ScanRecord(
                session_id=self.session_id,
                source=self.source,
                status=ScanStatus.RUNNING,
                started_at=utc_now(),
                operating_system=platform.system(),
                model_version="telemetry-v1",
            )
        )
        self.database.log(
            LogRecord(
                event="scan.started",
                message="Local telemetry session started",
                context={"session_id": self.session_id, "source": self.source.value},
            )
        )
        try:
            if self.source == ScanSource.REPLAY:
                self._run_replay()
            else:
                self._run_live()
            status = ScanStatus.STOPPED if self._stop_requested.is_set() else ScanStatus.COMPLETED
            self._finish(status)
        except Exception as exc:
            self._finish(ScanStatus.FAILED, str(exc))
            self.failed.emit(str(exc))

    def _run_replay(self) -> None:
        for batch in replay_samples(self.scenario, self.session_id):
            if self._stop_requested.is_set():
                break
            self.sample_count += len(batch)
            self.telemetry.emit(self.sample_count, len(batch))
            self.msleep(130)

    def _run_live(self) -> None:
        collector = PsutilCollector()
        while not self._stop_requested.wait(1.0):
            batch = collector.collect(self.session_id)
            self.sample_count += len(batch)
            self.capabilities.emit(collector.capabilities)
            self.telemetry.emit(self.sample_count, len(batch))

    def _finish(self, status: ScanStatus, error: str | None = None) -> None:
        self.database.finish_scan(self.session_id, status, self.sample_count, 0, error)
        self.database.log(
            LogRecord(
                level="ERROR" if error else "INFO",
                event="scan.finished",
                message=error or f"Telemetry session {status.value}",
                context={"session_id": self.session_id, "samples": self.sample_count},
            )
        )
        self.scan_finished.emit(self.session_id, status.value)
