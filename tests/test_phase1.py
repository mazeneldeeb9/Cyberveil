from pathlib import Path

from cyberveil.domain import AppSettings, LogRecord, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.storage import Database


def test_phase1_history_logs_and_settings_persist(tmp_path: Path) -> None:
    path = tmp_path / "phase1.db"
    database = Database(path)
    database.create_scan(
        ScanRecord(
            session_id="phase1-scan",
            source=ScanSource.REPLAY,
            status=ScanStatus.RUNNING,
            started_at=utc_now(),
            operating_system="TestOS",
            model_version="telemetry-v1",
        )
    )
    database.finish_scan("phase1-scan", ScanStatus.COMPLETED, 18, 0)
    database.log(LogRecord(event="scan.finished", message="Telemetry session completed"))
    database.save_settings(AppSettings(language="ar", retention_days=14))
    database.close()
    reopened = Database(path)
    scan = reopened.get_scan("phase1-scan")
    assert scan is not None and scan.sample_count == 18
    assert reopened.list_logs()[0].event == "scan.finished"
    assert reopened.load_settings().language == "ar"
    reopened.close()
