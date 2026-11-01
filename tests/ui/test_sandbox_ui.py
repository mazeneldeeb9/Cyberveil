from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from cyberveil.detection.api_model import ApiBehaviorClassifier
from cyberveil.domain import DetectionResult, ScanSource, Severity
from cyberveil.storage import Database
from cyberveil.ui.i18n import Translator
from cyberveil.ui.main_window import MainWindow
from cyberveil.ui.pages import DetectionDialog


def test_import_finishes_in_history_without_process_actions(qtbot, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    # Schema fixture for UI wiring, not research validation evidence.
    report = tmp_path / "fixture.json"
    report.write_text(json.dumps({
        "target": {"file": {"sha256": "e" * 64}},
        "behavior": {"processes": [{"process_id": 42, "calls": [
            {"api": api} for api in ApiBehaviorClassifier().vocabulary[:40]
        ]}]},
    }))
    window = MainWindow(Database(tmp_path / "data.db"))
    qtbot.addWidget(window)
    with patch("cyberveil.ui.main_window.QFileDialog.getOpenFileName", return_value=(str(report), "")):
        window.import_sandbox_report()
    qtbot.waitUntil(lambda: not window._sandbox_running, timeout=10000)
    qtbot.waitUntil(lambda: window.thread_pool.activeThreadCount() == 0, timeout=10000)
    scan = window.database.list_scans()[0]
    assert scan.source == ScanSource.SANDBOX and scan.blocked_count == 0
    assert window.current_page_name() == "report"
    assert window.dashboard.sandbox_button.isEnabled()
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
