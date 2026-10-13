from PySide6.QtWidgets import QMessageBox

from cyberveil.domain import IncidentReport, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.integrations import OllamaExplainer
from cyberveil.ui.main_window import MainWindow


def test_retention_cancel_does_not_delete(qtbot, database, monkeypatch):
    window = MainWindow(database)
    qtbot.addWidget(window)
    calls = []
    monkeypatch.setattr(database, "purge_history", lambda days: calls.append(days))
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Cancel)
    window.apply_retention()
    assert calls == []


def test_model_validation_preserves_settings(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.settings_page.ollama_model.setText("invalid model\n")
    window.settings_page.save_button.click()
    assert database.load_settings().ollama_model == ""
    assert window.translator("invalid_model") in window.settings_page.saved.text()


def test_stale_explanation_not_added_to_different_report(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    scan = ScanRecord(
        session_id="new",
        source=ScanSource.REPLAY,
        status=ScanStatus.COMPLETED,
        started_at=utc_now(),
        operating_system="test",
    )
    report = IncidentReport(scan=scan)
    window.report_page.set_report(report)
    window._pending_explanation = ("old", "en")
    window._explanation_ready(OllamaExplainer("").explain(report))
    assert "Local explanation" not in window.report_page.browser.toPlainText()
    assert window._pending_explanation is None
    assert window.report_page.explain_button.isEnabled()


def test_arabic_filters_accessibility_and_summary_mode(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.save_settings(window.settings.model_copy(update={"language": "ar", "reduced_motion": True}))
    filters = window.notifications_page.filters
    assert filters.search.accessibleName() == window.translator("search_notifications")
    filters.choice.setCurrentIndex(1)
    assert filters.choice.currentData() == "high"
    assert not window.dashboard.radar._timer.isActive()
    assert window.report_page.view_mode.itemText(1) == window.translator("summary_report")


def test_missing_memory_image_is_actionable(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    page = window.forensics_page
    page._analyze()
    assert page.results.toPlainText() == window.translator("choose_required")
    assert page.analyze.isEnabled()


def test_queued_worker_results_after_close_do_not_access_database(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.close()
    window._scan_finished("old", "stopped")
    window._forensics_ready(None)
    window._explanation_ready(None)
    window._telemetry_updated(10, 1)
    assert window._closing
