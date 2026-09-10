from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberveil.domain import (
    AppSettings,
    DetectionDisposition,
    DetectionResult,
    LogRecord,
    RemediationResult,
    ScanRecord,
    ScanSource,
    ScanStatus,
    utc_now,
)

SCHEMA_VERSION = 1


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._configure()
        self._migrate()

    def _configure(self) -> None:
        with self._connection:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = NORMAL")

    def _migrate(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    session_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    operating_system TEXT NOT NULL,
                    sample_count INTEGER NOT NULL DEFAULT 0,
                    detection_count INTEGER NOT NULL DEFAULT 0,
                    blocked_count INTEGER NOT NULL DEFAULT 0,
                    model_version TEXT NOT NULL,
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
                    observed_at TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    process_started_at REAL NOT NULL,
                    process_name TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    label TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    reasons_json TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    source TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_actions (
                    action_id TEXT PRIMARY KEY,
                    detection_id TEXT NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    level TEXT NOT NULL,
                    event TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_session ON detections(session_id);
                CREATE INDEX IF NOT EXISTS idx_detections_observed ON detections(observed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_occurred ON logs(occurred_at DESC);
                """
            )
            row = self._connection.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
            if row is None:
                self._connection.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
            elif int(row["version"]) != SCHEMA_VERSION:
                raise RuntimeError(f"Unsupported database schema version: {row['version']}")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def create_scan(self, record: ScanRecord) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO scans(
                    session_id, source, status, started_at, ended_at, operating_system,
                    sample_count, detection_count, blocked_count, model_version, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.session_id,
                    record.source.value,
                    record.status.value,
                    record.started_at.isoformat(),
                    record.ended_at.isoformat() if record.ended_at else None,
                    record.operating_system,
                    record.sample_count,
                    record.detection_count,
                    record.blocked_count,
                    record.model_version,
                    record.error,
                ),
            )

    def finish_scan(
        self,
        session_id: str,
        status: ScanStatus,
        sample_count: int,
        detection_count: int,
        error: str | None = None,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE scans SET status = ?, ended_at = ?, sample_count = ?,
                    detection_count = ?, error = ? WHERE session_id = ?
                """,
                (
                    status.value,
                    utc_now().isoformat(),
                    sample_count,
                    detection_count,
                    error,
                    session_id,
                ),
            )

    def increment_blocked(self, session_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE scans SET blocked_count = blocked_count + 1 WHERE session_id = ?",
                (session_id,),
            )

    def save_detection(self, result: DetectionResult) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO detections(
                    detection_id, session_id, observed_at, pid, process_started_at,
                    process_name, model_version, score, severity, label, threshold,
                    reasons_json, disposition, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.detection_id,
                    result.session_id,
                    result.observed_at.isoformat(),
                    result.pid,
                    result.process_started_at,
                    result.process_name,
                    result.model_version,
                    result.score,
                    result.severity.value,
                    result.label,
                    result.threshold,
                    json.dumps(result.reasons, ensure_ascii=False),
                    result.disposition.value,
                    result.source.value,
                ),
            )

    def set_detection_disposition(self, detection_id: str, disposition: DetectionDisposition) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE detections SET disposition = ? WHERE detection_id = ?",
                (disposition.value, detection_id),
            )

    def save_action(self, result: RemediationResult) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO remediation_actions(
                    action_id, detection_id, occurred_at, action, status, message
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.action_id,
                    result.detection_id,
                    result.occurred_at.isoformat(),
                    result.action.value,
                    result.status.value,
                    result.message,
                ),
            )

    def log(self, record: LogRecord) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO logs(occurred_at, level, event, message, context_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.occurred_at.isoformat(),
                    record.level.upper(),
                    record.event,
                    record.message,
                    json.dumps(record.context, ensure_ascii=False, default=str),
                ),
            )

    def list_scans(self, limit: int = 100, search: str = "") -> list[ScanRecord]:
        query = "SELECT * FROM scans"
        params: list[Any] = []
        if search:
            query += " WHERE source LIKE ? OR status LIKE ? OR started_at LIKE ?"
            term = f"%{search}%"
            params.extend((term, term, term))
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [self._scan_from_row(row) for row in rows]

    def get_scan(self, session_id: str) -> ScanRecord | None:
        with self._lock:
            row = self._connection.execute("SELECT * FROM scans WHERE session_id = ?", (session_id,)).fetchone()
        return self._scan_from_row(row) if row else None

    def list_detections(self, session_id: str | None = None, limit: int = 200) -> list[DetectionResult]:
        query = "SELECT * FROM detections"
        params: list[Any] = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [self._detection_from_row(row) for row in rows]

    def get_detection(self, detection_id: str) -> DetectionResult | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
            ).fetchone()
        return self._detection_from_row(row) if row else None

    def list_actions(self, detection_ids: list[str] | None = None) -> list[RemediationResult]:
        query = "SELECT * FROM remediation_actions"
        params: list[Any] = []
        if detection_ids:
            marks = ",".join("?" for _ in detection_ids)
            query += f" WHERE detection_id IN ({marks})"
            params.extend(detection_ids)
        query += " ORDER BY occurred_at DESC"
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [
            RemediationResult(
                action_id=row["action_id"],
                detection_id=row["detection_id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                action=row["action"],
                status=row["status"],
                message=row["message"],
            )
            for row in rows
        ]

    def list_logs(self, limit: int = 500, search: str = "") -> list[LogRecord]:
        query = "SELECT * FROM logs"
        params: list[Any] = []
        if search:
            query += " WHERE event LIKE ? OR message LIKE ? OR context_json LIKE ?"
            term = f"%{search}%"
            params.extend((term, term, term))
        query += " ORDER BY occurred_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [
            LogRecord(
                log_id=row["log_id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                level=row["level"],
                event=row["event"],
                message=row["message"],
                context=json.loads(row["context_json"]),
            )
            for row in rows
        ]

    def load_settings(self) -> AppSettings:
        with self._lock:
            row = self._connection.execute("SELECT value_json FROM settings WHERE key = 'app'").fetchone()
        if not row:
            return AppSettings()
        try:
            return AppSettings.model_validate_json(row["value_json"])
        except ValueError:
            return AppSettings()

    def save_settings(self, settings: AppSettings) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO settings(key, value_json) VALUES ('app', ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
                """,
                (settings.model_dump_json(),),
            )

    @staticmethod
    def _scan_from_row(row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            session_id=row["session_id"],
            source=ScanSource(row["source"]),
            status=ScanStatus(row["status"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=datetime.fromisoformat(row["ended_at"]) if row["ended_at"] else None,
            operating_system=row["operating_system"],
            sample_count=row["sample_count"],
            detection_count=row["detection_count"],
            blocked_count=row["blocked_count"],
            model_version=row["model_version"],
            error=row["error"],
        )

    @staticmethod
    def _detection_from_row(row: sqlite3.Row) -> DetectionResult:
        return DetectionResult(
            detection_id=row["detection_id"],
            session_id=row["session_id"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
            pid=row["pid"],
            process_started_at=row["process_started_at"],
            process_name=row["process_name"],
            model_version=row["model_version"],
            score=row["score"],
            severity=row["severity"],
            label=row["label"],
            threshold=row["threshold"],
            reasons=tuple(json.loads(row["reasons_json"])),
            disposition=row["disposition"],
            source=row["source"],
        )
