from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cyberveil.detection.api_model import ApiBehaviorClassifier, bundled_api_model_path
from cyberveil.domain import RemediationAction, RemediationRequest, RemediationStatus, ScanSource, ScanStatus
from cyberveil.forensics.sandbox import SandboxAnalysisService, read_sandbox_report
from cyberveil.remediation import ProcessRemediator
from cyberveil.reports import ReportService
from cyberveil.storage import Database


@pytest.fixture
def report_file(tmp_path: Path) -> Path:
    # Synthetic schema fixture, never counted as a malware validation result.
    apis = ApiBehaviorClassifier().vocabulary[:40]
    report = {
        "target": {"file": {"sha256": "a" * 64, "name": "fixture.exe"}},
        "info": {"started": "2026-01-01 00:00:00", "ended": "2026-01-01 00:02:00"},
        "behavior": {"processes": [{"process_id": 999999, "process_name": "fixture.exe",
                                    "calls": [{"api": api, "repeated": 0} for api in apis]}]},
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    return path


def test_classifier_ignores_verdict_names_and_identity(report_file: Path, tmp_path: Path) -> None:
    database = Database(tmp_path / "data.db")
    service = SandboxAnalysisService(database)
    original = service.analyze(report_file)
    payload = json.loads(report_file.read_text())
    payload.update(signatures=[{"name": "known virus", "severity": 10}], malscore=10,
                   label="malware", family="ransomware")
    payload["target"]["file"].update(name="harmless.exe", sha256="b" * 64)
    payload["behavior"]["processes"][0].update(process_name="other.exe", process_id=42)
    report_file.write_text(json.dumps(payload))
    modified = service.analyze(report_file)
    assert original["score"] == modified["score"]
    assert original["verdict"] == modified["verdict"]
    assert original["report_sha256"] != modified["report_sha256"]
    scan = database.get_scan(str(modified["session_id"]))
    assert scan and scan.source == ScanSource.SANDBOX and scan.blocked_count == 0
    built = ReportService(database).build(scan.session_id)
    assert built.forensic_findings[0].details["actions_taken"] == 0
    html = ReportService.to_html(built)
    assert "Recorded sandbox evidence" in html and "Import started" in html
    assert "Offline memory analysis" not in html
    arabic = ReportService.to_html(built, language="ar")
    assert f'dir="ltr" style="margin:0; text-align:left;">{scan.session_id}</p>' in arabic
    ReportService(database).export_json(built, tmp_path / "export.json", redact_sensitive=False)
    assert json.loads((tmp_path / "export.json").read_text())["scan"]["source"] == "sandbox_report"
    database.close()


def test_repetition_and_order_do_not_change_api_presence_score(report_file: Path) -> None:
    classifier = ApiBehaviorClassifier()
    original = read_sandbox_report(report_file)
    payload = json.loads(report_file.read_text())
    calls = payload["behavior"]["processes"][0]["calls"]
    calls.reverse()
    calls[0]["repeated"] = 100
    calls.append(dict(calls[0]))
    report_file.write_text(json.dumps(payload))
    changed = read_sandbox_report(report_file)
    assert changed.call_count > original.call_count
    assert classifier.predict(set(original.apis)) == classifier.predict(set(changed.apis))


@pytest.mark.parametrize("kind", ["empty", "few", "unknown", "missing_hash", "malformed_api", "external_calls"])
def test_inadequate_or_unsupported_report_is_failed_not_clean(
    report_file: Path, tmp_path: Path, kind: str,
) -> None:
    payload = json.loads(report_file.read_text())
    process = payload["behavior"]["processes"][0]
    if kind == "empty":
        process["calls"] = []
    elif kind == "few":
        process["calls"] = process["calls"][:9]
    elif kind == "unknown":
        process["calls"] = [{"api": f"UnsupportedAPI{i}"} for i in range(20)]
    elif kind == "missing_hash":
        payload["target"]["file"] = {}
    elif kind == "malformed_api":
        process["calls"][0]["api"] = "$(not-an-api)"
    else:
        process["calls"] = "../../personal-file.json"
    report_file.write_text(json.dumps(payload))
    database = Database(tmp_path / "data.db")
    with pytest.raises(ValueError):
        SandboxAnalysisService(database).analyze(report_file)
    scan = database.list_scans()[0]
    assert scan.status == ScanStatus.FAILED and scan.error and scan.detection_count == 0
    database.close()


def test_model_corruption_and_cycles_are_rejected(tmp_path: Path) -> None:
    payload = json.loads(bundled_api_model_path().read_text())
    path = tmp_path / "model.json"
    payload["runtime"]["trees"][0]["left"][0] = 0
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="checksum"):
        ApiBehaviorClassifier(path)
    payload["runtime_sha256"] = hashlib.sha256(
        json.dumps(payload["runtime"], sort_keys=True, allow_nan=False).encode(),
    ).hexdigest()
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="edges"):
        ApiBehaviorClassifier(path)


@pytest.mark.parametrize("simulation", [False, True])
def test_offline_evidence_cannot_touch_any_local_process(simulation: bool) -> None:
    request = RemediationRequest(
        detection_id="historical", pid=42, process_started_at=1, process_name="anything",
        action=RemediationAction.TERMINATE, source=ScanSource.SANDBOX, simulation=simulation,
    )
    with patch("cyberveil.remediation.process.psutil.Process", side_effect=AssertionError("Local process touched")):
        result = ProcessRemediator().execute(request)
    assert result.status == RemediationStatus.REFUSED


def test_artifact_split_membership_has_no_overlap() -> None:
    evidence = json.loads((Path(__file__).parents[2] / "docs/evidence/windows-api-evaluation.json").read_text())
    for key in ("partition_sample_hashes", "partition_fingerprints"):
        membership = [set(evidence[key][split]) for split in ("fit", "validation", "test")]
        assert all(not left & right for i, left in enumerate(membership) for right in membership[i + 1:])
    assert evidence["exclusions"]["ambiguous_sample_hashes"] == 6
