from __future__ import annotations

import platform
from datetime import datetime, timedelta
from uuid import uuid4

from cyberveil.detection.features import FeatureExtractor
from cyberveil.detection.runtime import CompositeClassifier
from cyberveil.domain import (
    AppSettings,
    DetectionResult,
    LogRecord,
    ScanRecord,
    ScanSource,
    ScanStatus,
    Severity,
    TelemetrySample,
    utc_now,
)
from cyberveil.storage import Database


class MonitoringEngine:
    """Owns one scan session and keeps UI/threading concerns outside detection logic."""

    def __init__(
        self,
        database: Database,
        classifier: CompositeClassifier,
        settings: AppSettings,
        *,
        source: ScanSource,
    ) -> None:
        self.database = database
        self.classifier = classifier
        self.settings = settings
        self.source = source
        self.session_id = str(uuid4())
        self.extractor = FeatureExtractor()
        self.started_at: datetime | None = None
        self.sample_count = 0
        self.detection_count = 0
        self._last_detection: dict[str, datetime] = {}
        self._last_inference: dict[str, datetime] = {}
        self._last_severity: dict[str, Severity] = {}

    def start(self) -> ScanRecord:
        if self.started_at is not None:
            raise RuntimeError("Monitoring session is already started")
        self.started_at = utc_now()
        record = ScanRecord(
            session_id=self.session_id,
            source=self.source,
            status=ScanStatus.RUNNING,
            started_at=self.started_at,
            operating_system=platform.system(),
            model_version=self.classifier.version,
        )
        self.database.create_scan(record)
        self.database.log(
            LogRecord(
                event="scan.started",
                message=f"{self.source.value.title()} monitoring session started",
                context={"session_id": self.session_id, "model": self.classifier.version},
            )
        )
        if self.classifier.load_error:
            self.database.log(
                LogRecord(
                    level="WARNING",
                    event="model.fallback",
                    message="The trained model could not be loaded; transparent rules are active.",
                    context={"error": self.classifier.load_error},
                )
            )
        return record

    def ingest(self, samples: list[TelemetrySample]) -> list[DetectionResult]:
        if self.started_at is None:
            raise RuntimeError("Monitoring session has not started")
        emitted: list[DetectionResult] = []
        if any(sample.session_id != self.session_id or sample.source != self.source for sample in samples):
            raise ValueError("Telemetry belongs to a different session or source")
        self.sample_count += len(samples)
        if samples:
            now = max(sample.observed_at for sample in samples)
            self.extractor.prune(now)
            for key, observed in list(self._last_inference.items()):
                if now - observed > timedelta(seconds=30):
                    self._last_inference.pop(key, None)
                    self._last_detection.pop(key, None)
                    self._last_severity.pop(key, None)
        for sample in samples:
            last_inference = self._last_inference.get(sample.process_key)
            due = last_inference is None or sample.observed_at - last_inference >= timedelta(seconds=2)
            window = self.extractor.ingest(sample, emit=due)
            if window is None:
                continue
            last_inference = self._last_inference.get(window.process_key)
            if last_inference and window.window_end - last_inference < timedelta(seconds=2):
                continue
            self._last_inference[window.process_key] = window.window_end
            result = self.classifier.score(
                window,
                threshold=self.settings.detection_threshold,
                source=self.source,
            )
            if result.severity not in (Severity.MEDIUM, Severity.HIGH):
                continue
            previous = self._last_detection.get(window.process_key)
            escalated = (
                result.severity == Severity.HIGH and self._last_severity.get(window.process_key) != Severity.HIGH
            )
            if previous and not escalated and result.observed_at - previous < timedelta(seconds=10):
                continue
            self._last_detection[window.process_key] = result.observed_at
            self._last_severity[window.process_key] = result.severity
            self.database.save_detection(result)
            self.database.log(
                LogRecord(
                    level="WARNING" if result.severity == Severity.MEDIUM else "CRITICAL",
                    event="detection.created",
                    message=f"Suspicious behavior detected in {result.process_name}",
                    context={
                        "detection_id": result.detection_id,
                        "score": round(result.score, 4),
                        "severity": result.severity.value,
                        "reasons": result.reasons,
                    },
                )
            )
            self.detection_count += 1
            emitted.append(result)
        return emitted

    def finish(self, status: ScanStatus = ScanStatus.COMPLETED, error: str | None = None) -> None:
        if self.started_at is None:
            return
        self.database.finish_scan(
            self.session_id,
            status,
            self.sample_count,
            self.detection_count,
            error,
        )
        self.database.log(
            LogRecord(
                level="ERROR" if error else "INFO",
                event="scan.finished",
                message=f"Monitoring session {status.value}",
                context={
                    "session_id": self.session_id,
                    "samples": self.sample_count,
                    "detections": self.detection_count,
                    "error": error,
                },
            )
        )
        self.started_at = None
