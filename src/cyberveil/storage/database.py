from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cyberveil.domain import (
    AppSettings,
    DetectionDisposition,
    DetectionResult,
    ForensicFinding,
    LogRecord,
    RemediationAction,
    RemediationResult,
    RemediationStatus,
    ScanRecord,
    ScanSource,
    ScanStatus,
    Severity,
    utc_now,
)

SCHEMA_VERSION = 2


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
                CREATE TABLE IF NOT EXISTS forensic_findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES scans(session_id) ON DELETE CASCADE,
                    finding_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_session ON detections(session_id);
                CREATE INDEX IF NOT EXISTS idx_detections_observed ON detections(observed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_occurred ON logs(occurred_at DESC);
                """
            )
            row = self._connection.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
            columns = {item[1] for item in self._connection.execute("PRAGMA table_info(detections)")}
            if "evidence_json" not in columns:
                self._connection.execute("ALTER TABLE detections ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '{}'")
            if row is None:
                self._connection.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
            elif int(row["version"]) == 1:
                self._connection.execute("UPDATE schema_meta SET version = ?", (SCHEMA_VERSION,))
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
                    reasons_json, disposition, source, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps({"values": result.feature_values, "missing": result.missing_fields}),
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

    def list_scans(
        self,
        limit: int = 100,
        search: str = "",
        *,
        source: ScanSource | None = None,
        status: ScanStatus | None = None,
    ) -> list[ScanRecord]:
        query = "SELECT * FROM scans"
        params: list[Any] = []
        conditions = []
        if search:
            conditions.append(
                "(source LIKE ? ESCAPE '\\' OR status LIKE ? ESCAPE '\\' "
                "OR started_at LIKE ? ESCAPE '\\' OR session_id LIKE ? ESCAPE '\\')"
            )
            term = self._search_term(search)
            params.extend((term, term, term, term))
        for column, value in (("source", source), ("status", status)):
            if value is not None:
                conditions.append(f"{column} = ?")
                params.append(value.value)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [self._scan_from_row(row) for row in rows]

    def get_scan(self, session_id: str) -> ScanRecord | None:
        with self._lock:
            row = self._connection.execute("SELECT * FROM scans WHERE session_id = ?", (session_id,)).fetchone()
        return self._scan_from_row(row) if row else None

    def list_detections(
        self,
        session_id: str | None = None,
        limit: int | None = 200,
        *,
        search: str = "",
        severity: Severity | None = None,
        disposition: DetectionDisposition | None = None,
    ) -> list[DetectionResult]:
        query = "SELECT * FROM detections"
        params: list[Any] = []
        conditions = []
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if search:
            conditions.append("(process_name LIKE ? ESCAPE '\\' OR detection_id LIKE ? ESCAPE '\\')")
            params.extend((self._search_term(search), self._search_term(search)))
        for column, value in (("severity", severity), ("disposition", disposition)):
            if value is not None:
                conditions.append(f"{column} = ?")
                params.append(value.value)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(-1 if limit is None else limit)
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
        if detection_ids == []:
            return []
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

    def list_actions_for_session(self, session_id: str) -> list[RemediationResult]:
        # A join avoids SQLite's bound-variable limit on large incident histories.
        with self._lock:
            rows = self._connection.execute(
                "SELECT a.* FROM remediation_actions a JOIN detections d USING(detection_id) "
                "WHERE d.session_id = ? ORDER BY a.occurred_at DESC",
                (session_id,),
            ).fetchall()
        return [RemediationResult(**dict(row)) for row in rows]

    @staticmethod
    def _search_term(value: str) -> str:
        return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def purge_history(self, retention_days: int) -> tuple[int, int]:
        """Only call after explicit UI/CLI confirmation; active sessions are preserved."""
        if not 1 <= retention_days <= 365:
            raise ValueError("Retention must be between 1 and 365 days")
        cutoff = (utc_now() - timedelta(days=retention_days)).isoformat()
        with self._lock, self._connection:
            scans = self._connection.execute(
                "DELETE FROM scans WHERE status != 'running' AND COALESCE(ended_at, started_at) < ?",
                (cutoff,),
            ).rowcount
            logs = self._connection.execute(
                "DELETE FROM logs WHERE occurred_at < ? AND COALESCE(json_extract(context_json, '$.session_id'), '') "
                "NOT IN (SELECT session_id FROM scans WHERE status = 'running')",
                (cutoff,),
            ).rowcount
        self.log(
            LogRecord(
                event="history.retention",
                message="Confirmed history retention applied",
                context={"scans_removed": scans, "logs_removed": logs, "days": retention_days},
            )
        )
        return scans, logs

    def record_remediation(self, result: RemediationResult) -> None:
        """Commit action, disposition, counter, and audit event together; retries are idempotent."""
        with self._lock, self._connection:
            if self._connection.execute(
                "SELECT 1 FROM remediation_actions WHERE action_id = ?",
                (result.action_id,),
            ).fetchone():
                return
            row = self._connection.execute(
                "SELECT session_id, disposition FROM detections WHERE detection_id = ?",
                (result.detection_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Cannot record action for an unknown detection")
            succeeded = result.status == RemediationStatus.SUCCEEDED
            disposition = (
                DetectionDisposition.IGNORED
                if result.action == RemediationAction.IGNORE
                else DetectionDisposition.BLOCKED
                if succeeded
                else DetectionDisposition.BLOCK_FAILED
            )
            self._connection.execute(
                "INSERT INTO remediation_actions VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.action_id,
                    result.detection_id,
                    result.occurred_at.isoformat(),
                    result.action.value,
                    result.status.value,
                    result.message,
                ),
            )
            if row["disposition"] != DetectionDisposition.BLOCKED.value:
                self._connection.execute(
                    "UPDATE detections SET disposition = ? WHERE detection_id = ?",
                    (disposition.value, result.detection_id),
                )
                if disposition == DetectionDisposition.BLOCKED:
                    self._connection.execute(
                        "UPDATE scans SET blocked_count = blocked_count + 1 WHERE session_id = ?",
                        (row["session_id"],),
                    )
            self._connection.execute(
                "INSERT INTO logs(occurred_at, level, event, message, context_json) VALUES (?, ?, ?, ?, ?)",
                (
                    result.occurred_at.isoformat(),
                    "INFO" if succeeded else "ERROR",
                    "remediation.finished",
                    result.message,
                    json.dumps({"detection_id": result.detection_id, "status": result.status.value}),
                ),
            )

    def save_forensic_findings(self, session_id: str, findings: tuple[ForensicFinding, ...]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                "INSERT INTO forensic_findings(session_id, finding_json) VALUES (?, ?)",
                [(session_id, finding.model_dump_json()) for finding in findings],
            )

    def list_forensic_findings(self, session_id: str) -> tuple[ForensicFinding, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT finding_json FROM forensic_findings WHERE session_id = ? ORDER BY finding_id",
                (session_id,),
            ).fetchall()
        return tuple(ForensicFinding.model_validate_json(row["finding_json"]) for row in rows)

    def list_logs(self, limit: int = 500, search: str = "") -> list[LogRecord]:
        query = "SELECT * FROM logs"
        params: list[Any] = []
        if search:
            query += " WHERE event LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' OR context_json LIKE ? ESCAPE '\\'"
            term = self._search_term(search)
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
            feature_values=json.loads(row["evidence_json"]).get("values", {}),
            missing_fields=tuple(json.loads(row["evidence_json"]).get("missing", [])),
            disposition=row["disposition"],
            source=row["source"],
        )
