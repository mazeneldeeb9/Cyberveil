from pathlib import Path

from cyberveil.domain import (
    DetectionResult,
    LogRecord,
    ScanRecord,
    ScanSource,
    ScanStatus,
    Severity,
    utc_now,
)
from cyberveil.storage import Database


def test_database_round_trip(database: Database) -> None:
    scan = ScanRecord(
        session_id="scan-1",
        source=ScanSource.REPLAY,
        status=ScanStatus.RUNNING,
        started_at=utc_now(),
        operating_system="TestOS",
    )
    database.create_scan(scan)
    detection = DetectionResult(
        detection_id="detection-1",
        session_id=scan.session_id,
        pid=12,
        process_started_at=1.0,
        process_name="safe-lab",
        model_version="rules-v1",
        score=0.91,
        severity=Severity.HIGH,
        label="suspicious",
        threshold=0.85,
        reasons=("Test evidence",),
        source=ScanSource.REPLAY,
    )
    database.save_detection(detection)
    database.finish_scan(scan.session_id, ScanStatus.COMPLETED, 20, 1)
    database.log(LogRecord(event="test.event", message="Recorded"))

    loaded = database.get_scan(scan.session_id)
    assert loaded is not None and loaded.sample_count == 20
    assert database.get_detection(detection.detection_id) == detection
    assert database.list_logs()[0].event == "test.event"


def test_invalid_settings_fall_back_to_defaults(tmp_path: Path) -> None:
    database = Database(tmp_path / "invalid.db")
    with database._connection:  # deliberately corrupt stored user preference
        database._connection.execute("INSERT INTO settings VALUES ('app', '{bad json')")
    assert database.load_settings().language == "en"
    database.close()
