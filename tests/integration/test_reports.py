import json

from cyberveil.domain import ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.reports import ReportService
from cyberveil.storage import Database


def test_json_and_csv_exports(database: Database, tmp_path) -> None:
    database.create_scan(
        ScanRecord(
            session_id="report-scan",
            source=ScanSource.REPLAY,
            status=ScanStatus.COMPLETED,
            started_at=utc_now(),
            operating_system="TestOS",
        )
    )
    service = ReportService(database)
    report = service.build("report-scan")
    json_path = service.export_json(report, tmp_path / "report.json")
    csv_path = service.export_csv(report, tmp_path / "report.csv")
    assert json.loads(json_path.read_text())["lab_only"] is True
    assert "lab_only" in csv_path.read_text(encoding="utf-8-sig")
