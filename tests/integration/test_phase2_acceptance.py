from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from cyberveil.domain import (
    ForensicFinding,
    RemediationAction,
    RemediationRequest,
    RemediationStatus,
    ScanRecord,
    ScanSource,
    ScanStatus,
    utc_now,
)
from cyberveil.forensics.service import ForensicService
from cyberveil.forensics.volatility import PLUGIN_SETS, VolatilityAnalyzer
from cyberveil.remediation import ProcessRemediator
from cyberveil.remediation.demo import HarmlessDemo
from cyberveil.reports import ReportService
from cyberveil.storage import Database


def test_harmless_child_termination_and_atomic_audit(database):
    database.create_scan(
        ScanRecord(
            session_id="demo",
            source=ScanSource.DEMO_PROCESS,
            status=ScanStatus.RUNNING,
            started_at=utc_now(),
            operating_system="test",
        )
    )
    with HarmlessDemo() as demo:
        detection = demo.detection("demo")
        database.save_detection(detection)
        result = ProcessRemediator().execute(
            RemediationRequest(
                detection_id=detection.detection_id,
                pid=detection.pid,
                process_started_at=detection.process_started_at,
                process_name=detection.process_name,
                action=RemediationAction.TERMINATE,
            )
        )
        assert result.status == RemediationStatus.SUCCEEDED
        assert demo.child.poll() is not None
        database.record_remediation(result)
        database.record_remediation(result)
        assert len(database.list_actions([detection.detection_id])) == 1
        assert database.get_scan("demo").blocked_count == 1
        assert database.list_actions([]) == []
        report = ReportService(database).build("demo")
        assert report.actions == (result,)


def test_forensic_findings_survive_restart(tmp_path):
    path = tmp_path / "forensic.db"
    database = Database(path)
    analyzer = Mock()
    analyzer.analyze.return_value = (
        ForensicFinding(
            plugin="pslist", category="memory_analysis", title="One process", details={"rows": [{"PID": 12}]}
        ),
        ForensicFinding(plugin="malfind", category="analysis_error", title="Missing symbols"),
    )
    result = ForensicService(database, analyzer).analyze(Path("memory.raw"), "windows")
    database.close()
    reopened = Database(path)
    report = ReportService(reopened).build(result.session_id)
    assert report.forensic_findings == result.findings
    assert report.scan.status == ScanStatus.FAILED
    assert "partial findings" in report.scan.error
    reopened.close()


@pytest.mark.parametrize("output", ["not-json", "null", "123"])
def test_invalid_volatility_output_is_an_error_not_a_finding(tmp_path, output):
    image = tmp_path / "memory.raw"
    image.touch()
    analyzer = VolatilityAnalyzer("vol-test")
    with patch("cyberveil.forensics.volatility.subprocess.run", return_value=Mock(returncode=0, stdout=output)) as run:
        findings = analyzer.analyze(image, "windows")
    assert all(f.category == "analysis_error" for f in findings)
    assert run.call_count == len(PLUGIN_SETS["windows"])
    assert "--offline" in run.call_args.args[0]
    assert run.call_args.kwargs.get("shell", False) is False


def test_volatility_timeout_preserves_completed_plugin_results(tmp_path):
    import subprocess

    image = tmp_path / "memory.raw"
    image.touch()
    analyzer = VolatilityAnalyzer("vol-test")
    with patch(
        "cyberveil.forensics.volatility.subprocess.run",
        side_effect=[
            Mock(returncode=0, stdout='[{"PID": 42}]'),
            subprocess.TimeoutExpired("vol", 180),
        ],
    ):
        findings = analyzer.analyze(image, "linux")
    assert findings[0].category == "memory_analysis"
    assert findings[1].category == "analysis_error"


def test_phase1_database_migrates_without_losing_history(tmp_path):
    database = Database(tmp_path / "old.db")
    database.create_scan(
        ScanRecord(
            session_id="phase1",
            source=ScanSource.REPLAY,
            status=ScanStatus.COMPLETED,
            started_at=utc_now(),
            operating_system="test",
        )
    )
    with database._connection:
        database._connection.execute("UPDATE schema_meta SET version = 1")
        database._connection.execute("ALTER TABLE detections DROP COLUMN evidence_json")
        database._connection.execute("DROP TABLE forensic_findings")
    database.close()
    reopened = Database(tmp_path / "old.db")
    assert reopened.get_scan("phase1") is not None
    assert reopened.list_forensic_findings("phase1") == ()
    reopened.close()
