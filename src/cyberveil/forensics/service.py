from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from cyberveil.domain import ForensicAnalysis, LogRecord, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.forensics.volatility import VolatilityAnalyzer
from cyberveil.storage import Database


class ForensicService:
    def __init__(self, database: Database, analyzer: VolatilityAnalyzer | None = None) -> None:
        self.database = database
        self.analyzer = analyzer or VolatilityAnalyzer()

    def analyze(self, image: Path, operating_system: str) -> ForensicAnalysis:
        session_id = str(uuid4())
        self.database.create_scan(
            ScanRecord(
                session_id=session_id,
                source=ScanSource.FORENSIC,
                status=ScanStatus.RUNNING,
                started_at=utc_now(),
                operating_system=operating_system,
                model_version="volatility3-offline",
            )
        )
        try:
            findings = self.analyzer.analyze(image, operating_system)
        except Exception as exc:
            self.database.finish_scan(session_id, ScanStatus.FAILED, 0, 0, str(exc))
            self.database.log(LogRecord(level="ERROR", event="forensics.failed", message=str(exc)))
            raise
        errors = sum(finding.category == "analysis_error" for finding in findings)
        status = ScanStatus.FAILED if errors else ScanStatus.COMPLETED
        self.database.save_forensic_findings(session_id, findings)
        self.database.finish_scan(
            session_id,
            status,
            0,
            0,
            f"{errors} plugin(s) failed; partial findings saved" if errors else None,
        )
        self.database.log(
            LogRecord(
                level="WARNING" if errors else "INFO",
                event="forensics.finished",
                message="Offline memory analysis finished",
                context={"session_id": session_id, "plugins": len(findings), "errors": errors},
            )
        )
        return ForensicAnalysis(session_id=session_id, findings=findings)
