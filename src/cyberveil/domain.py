from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScanSource(StrEnum):
    LIVE = "live"
    REPLAY = "replay"
    FORENSIC = "forensic"


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class Severity(StrEnum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionDisposition(StrEnum):
    OPEN = "open"
    IGNORED = "ignored"
    BLOCKED = "blocked"
    BLOCK_FAILED = "block_failed"


class RemediationAction(StrEnum):
    TERMINATE = "terminate"
    FORCE_KILL = "force_kill"
    IGNORE = "ignore"


class RemediationStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REFUSED = "refused"
    FAILED = "failed"
    STALE_PROCESS = "stale_process"


class CapabilityReport(FrozenModel):
    operating_system: str
    available: tuple[str, ...] = ()
    unavailable: tuple[str, ...] = ()
    permission_denied: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def is_degraded(self) -> bool:
        return bool(self.unavailable or self.permission_denied)


class TelemetrySample(FrozenModel):
    sample_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    observed_at: datetime = Field(default_factory=utc_now)
    source: ScanSource = ScanSource.LIVE
    pid: int = Field(ge=0)
    process_started_at: float = Field(ge=0)
    name: str = Field(min_length=1, max_length=260)
    parent_pid: int | None = Field(default=None, ge=0)
    username: str | None = Field(default=None, max_length=260)
    cpu_percent: float = Field(default=0, ge=0)
    rss_bytes: int = Field(default=0, ge=0)
    thread_count: int = Field(default=0, ge=0)
    child_count: int = Field(default=0, ge=0)
    connection_count: int | None = Field(default=None, ge=0)
    listening_port_count: int | None = Field(default=None, ge=0)
    open_file_count: int | None = Field(default=None, ge=0)
    read_bytes: int | None = Field(default=None, ge=0)
    write_bytes: int | None = Field(default=None, ge=0)
    command_hint: str | None = Field(default=None, max_length=160)

    @property
    def process_key(self) -> str:
        return f"{self.pid}:{self.process_started_at:.6f}"


class FeatureWindow(FrozenModel):
    session_id: str
    process_key: str
    pid: int
    process_name: str
    started_at: float
    window_start: datetime
    window_end: datetime
    schema_version: str = "1"
    values: dict[str, float]
    missing_fields: tuple[str, ...] = ()


class DetectionResult(FrozenModel):
    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    observed_at: datetime = Field(default_factory=utc_now)
    pid: int
    process_started_at: float
    process_name: str
    model_version: str
    score: float = Field(ge=0, le=1)
    severity: Severity
    label: str
    threshold: float = Field(ge=0, le=1)
    reasons: tuple[str, ...] = ()
    disposition: DetectionDisposition = DetectionDisposition.OPEN
    source: ScanSource = ScanSource.LIVE


class RemediationRequest(FrozenModel):
    detection_id: str
    pid: int
    process_started_at: float
    process_name: str
    action: RemediationAction
    confirmed_by: str = "user"
    simulation: bool = False


class RemediationResult(FrozenModel):
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    detection_id: str
    occurred_at: datetime = Field(default_factory=utc_now)
    action: RemediationAction
    status: RemediationStatus
    message: str


class ScanRecord(FrozenModel):
    session_id: str
    source: ScanSource
    status: ScanStatus
    started_at: datetime
    ended_at: datetime | None = None
    operating_system: str
    sample_count: int = 0
    detection_count: int = 0
    blocked_count: int = 0
    model_version: str = "rules-v1"
    error: str | None = None


class LogRecord(FrozenModel):
    log_id: int | None = None
    occurred_at: datetime = Field(default_factory=utc_now)
    level: str = "INFO"
    event: str
    message: str
    context: dict[str, Any] = Field(default_factory=dict)


class ForensicFinding(FrozenModel):
    plugin: str
    category: str
    severity: Severity = Severity.LOW
    title: str
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentReport(FrozenModel):
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=utc_now)
    scan: ScanRecord
    detections: tuple[DetectionResult, ...] = ()
    actions: tuple[RemediationResult, ...] = ()
    forensic_findings: tuple[ForensicFinding, ...] = ()
    lab_only: bool = True


class AppSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str = Field(default="en", pattern="^(en|ar)$")
    detection_threshold: float = Field(default=0.85, ge=0.5, le=0.99)
    auto_block: bool = False
    retention_days: int = Field(default=30, ge=1, le=365)
    redact_sensitive: bool = True
    ollama_enabled: bool = False
    ollama_model: str = ""
    reduced_motion: bool = False
