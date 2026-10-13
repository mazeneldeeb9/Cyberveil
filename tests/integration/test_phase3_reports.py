import csv
import json

import pytest

from cyberveil.domain import (
    DetectionResult,
    ForensicFinding,
    IncidentReport,
    RemediationAction,
    RemediationResult,
    RemediationStatus,
    ScanRecord,
    ScanSource,
    ScanStatus,
    Severity,
    utc_now,
)
from cyberveil.reports import ReportService


@pytest.fixture
def incident():
    detection = DetectionResult(
        session_id="s",
        pid=999,
        process_started_at=1000,
        process_name="private-client-name.exe",
        model_version="test",
        score=0.9,
        severity=Severity.HIGH,
        label="suspicious",
        threshold=0.85,
        reasons=("Rapid memory growth",),
        feature_values={"rss_delta_mb": 200.0},
        missing_fields=("io",),
    )
    return IncidentReport(
        scan=ScanRecord(
            session_id="s",
            source=ScanSource.REPLAY,
            status=ScanStatus.FAILED,
            started_at=utc_now(),
            operating_system="test",
            detection_count=1,
            error="private/path",
        ),
        detections=(detection,),
        actions=(
            RemediationResult(
                detection_id=detection.detection_id,
                action=RemediationAction.TERMINATE,
                status=RemediationStatus.REFUSED,
                message="private process details",
            ),
        ),
        forensic_findings=(
            ForensicFinding(
                plugin="windows.pslist",
                category="analysis_error",
                title="Failure",
                details={"message": "/Users/private/file", "pid": 999},
            ),
        ),
    )


@pytest.mark.parametrize("language", ["en", "ar"])
def test_full_exports_include_actions_forensics_and_redact(database, incident, tmp_path, language, qapp):
    service = ReportService(database)
    for format_name in ("json", "csv", "pdf"):
        target = tmp_path / f"report.{format_name}"
        getattr(service, f"export_{format_name}")(incident, target, language=language)
        assert target.stat().st_size > 100
    json_text = (tmp_path / "report.json").read_text(encoding="utf-8")
    data = json.loads(json_text)
    assert data["redacted"] is True
    assert data["language"] == language
    assert data["actions"] and data["forensic_findings"]
    assert "private" not in json_text
    assert "private" not in (tmp_path / "report.csv").read_text(encoding="utf-8-sig")
    assert incident.detections[0].process_name == "private-client-name.exe"
    assert data["detections"][0]["feature_values"]["rss_delta_mb"] == 200
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF-")
    rows = list(csv.reader((tmp_path / "report.csv").open(encoding="utf-8-sig")))
    assert {r[0] for r in rows[1:]} == {"summary", "detection", "action", "forensic"}


@pytest.mark.parametrize("name", ['=HYPERLINK("https://example.com")', "+1+1", "-1+1", "@SUM(A1)", "  =1+1", "\ttext"])
def test_csv_neutralizes_formulas(database, incident, tmp_path, name):
    report = incident.model_copy(
        update={"detections": (incident.detections[0].model_copy(update={"process_name": name}),)}
    )
    path = ReportService(database).export_csv(report, tmp_path / "safe.csv", redact_sensitive=False)
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    assert rows[1]["process_name"] == "'" + name


def test_html_is_escaped_and_failed_scan_is_not_clean(database, incident):
    report = incident.model_copy(
        update={"scan": incident.scan.model_copy(update={"error": '<img src="file:///secret">'}), "detections": ()}
    )
    html = ReportService.to_html(report)
    assert "&lt;img" in html and "<img src=" not in html
    assert "did not complete" in html
    assert "No suspicious behavior recorded" not in html
    assert "Action audit trail" in html
    summary = ReportService.to_html(report, full=False)
    assert "Action audit trail" not in summary


def test_report_actions_are_selected_by_session(database, incident):
    database.create_scan(incident.scan)
    database.save_detection(incident.detections[0])
    database.record_remediation(incident.actions[0])
    result = ReportService(database).build("s")
    assert len(result.actions) == 1
    assert not database.list_actions_for_session("missing")
