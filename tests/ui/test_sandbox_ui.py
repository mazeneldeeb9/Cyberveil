from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cyberveil.detection.api_model import ApiBehaviorClassifier
from cyberveil.domain import DetectionResult, ScanSource, Severity
from cyberveil.forensics.sandbox import SandboxAnalysisService
from cyberveil.storage import Database
from cyberveil.ui.i18n import Translator
from cyberveil.ui.main_window import MainWindow
from cyberveil.ui.pages import DetectionDialog


@pytest.mark.parametrize("language", ["en", "ar"])
@pytest.mark.parametrize("score", [0.59, 0.1])
def test_import_opens_alert_only_for_new_flagged_report(  # type: ignore[no-untyped-def]
    qtbot, tmp_path: Path, language: str, score: float,
) -> None:
    # Schema fixture for UI wiring, not research validation evidence.
    apis = ApiBehaviorClassifier().vocabulary[:40]
    report = tmp_path / "fixture.json"
    report.write_text(json.dumps({
        "target": {"file": {"sha256": "e" * 64}},
        "behavior": {"processes": [{"process_id": 42, "calls": [
            {"api": api} for api in apis
        ]}]},
    }))
    window = MainWindow(Database(tmp_path / "data.db"))
    qtbot.addWidget(window)
    window.save_settings(window.settings.model_copy(update={"language": language}))
    window.show()
    # Existing notifications must not be reopened by a later import.
    with patch.object(ApiBehaviorClassifier, "predict", return_value=(0.9, tuple(apis))):
        previous = SandboxAnalysisService(window.database).analyze(report)
    with (
        patch("cyberveil.ui.main_window.QFileDialog.getOpenFileName", return_value=(str(report), "")),
        patch.object(ApiBehaviorClassifier, "predict", return_value=(score, tuple(apis))),
    ):
        window.import_sandbox_report()
        qtbot.waitUntil(lambda: not window._sandbox_running, timeout=10000)
        qtbot.waitUntil(lambda: window.thread_pool.activeThreadCount() == 0, timeout=10000)
    scan = window.database.list_scans()[0]
    assert scan.source == ScanSource.SANDBOX and scan.blocked_count == 0
    assert scan.session_id != previous["session_id"]
    assert window.current_page_name() == "report"
    assert window.dashboard.sandbox_button.isEnabled()
    assert window.notifications_page.table.rowCount() == (2 if score >= 0.47 else 1)
    if score >= 0.47:
        assert len(window._dialogs) == 1
        dialog = next(iter(window._dialogs))
        assert dialog.isVisible()
        assert dialog.detection.session_id == scan.session_id
        assert dialog.detection.score == score
        assert dialog.windowTitle() == window.translator("sandbox_detection")
        assert not dialog.block.isEnabled()
        dialog.reject()
    else:
        assert not window._dialogs
    assert not window.database.list_actions()
    window.close()


def test_offline_alert_disables_block_in_both_languages(qtbot) -> None:  # type: ignore[no-untyped-def]
    detection = DetectionResult(
        session_id="offline", pid=0, process_started_at=0, process_name="Recorded sandbox execution",
        model_version="fixture", score=0.9, severity=Severity.HIGH, label="suspicious_sandbox_behavior",
        threshold=0.5, source=ScanSource.SANDBOX,
    )
    for language in ("en", "ar"):
        dialog = DetectionDialog(Translator(language), detection)
        qtbot.addWidget(dialog)
        assert not dialog.block.isEnabled()
        assert dialog.block.toolTip()
        dialog.close()


def test_busy_status_survives_language_change(qtbot, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    window = MainWindow(Database(tmp_path / "data.db"))
    qtbot.addWidget(window)
    window.dashboard.set_sandbox_busy(True)
    for language in ("ar", "en"):
        window.save_settings(window.settings.model_copy(update={"language": language}))
        assert not window.dashboard.sandbox_button.isEnabled()
        assert window.dashboard.sandbox_note.text() == window.translator("sandbox_running")
    window.dashboard.set_sandbox_busy(False)
    assert window.dashboard.sandbox_button.isEnabled()
    assert window.dashboard.sandbox_note.text() == window.translator("sandbox_detail")
    window.close()
