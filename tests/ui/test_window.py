from PySide6.QtWidgets import QMessageBox, QScrollArea

from cyberveil.domain import ScanSource, ScanStatus
from cyberveil.ui.main_window import MainWindow
from cyberveil.ui.theme import stylesheet
from cyberveil.ui.workers import ScanThread


def test_window_navigation_and_rtl(qtbot, database) -> None:
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.show()
    assert window.current_page_name() == "dashboard"
    window.navigate("history")
    assert window.current_page_name() == "history"
    window.settings.language = "ar"
    window.save_settings(window.settings)
    assert window.layoutDirection().name == "RightToLeft"


def test_settings_surface_is_explicitly_themed(qtbot, database) -> None:
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.navigate("settings")

    scroll = window.settings_page.findChild(QScrollArea, "settingsScroll")
    assert scroll is not None
    assert scroll.viewport().objectName() == "settingsViewport"
    assert window.settings_page.auto_block.text() == ""
    assert "QWidget#settingsViewport" in stylesheet()


def test_replay_thread_persists_alerts_and_can_be_stopped(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.show()
    window.start_scan(ScanSource.REPLAY)
    qtbot.waitUntil(lambda: window.scan_thread is None, timeout=15000)
    scan = database.list_scans()[0]
    assert scan.status == ScanStatus.COMPLETED
    assert scan.detection_count > 0
    window.navigate("notifications")
    assert window.notifications_page.table.rowCount() > 0
    for dialog in list(window._dialogs):
        dialog.reject()
    thread = ScanThread(database, window.settings, source=ScanSource.REPLAY)
    thread.request_stop()
    with qtbot.waitSignal(thread.finished, timeout=5000):
        thread.start()
    assert database.list_scans()[0].status == ScanStatus.STOPPED


def test_experimental_model_cannot_enable_live_auto_block(qtbot, database):
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.save_settings(window.settings.model_copy(update={"auto_block": True}))
    assert database.load_settings().auto_block is False
    assert not window.settings_page.auto_block.isEnabled()


def test_demo_dialog_cancel_then_confirm_termination(qtbot, database, monkeypatch):
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.show()
    window.start_demo_process()
    dialog = next(iter(window._dialogs))
    detection = dialog.detection
    demo, _ = window._demo_processes[detection.detection_id]
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Cancel)
    window._block_from_dialog(dialog, detection)
    assert demo.child.poll() is None
    assert not database.list_actions([detection.detection_id])
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QMessageBox, "exec", lambda *args: 0)
    window._block_from_dialog(dialog, detection)
    qtbot.waitUntil(
        lambda: not window._pending_actions and window.thread_pool.activeThreadCount() == 0,
        timeout=10000,
    )
    assert demo.child.poll() is not None
    assert database.get_scan(detection.session_id).blocked_count == 1
    assert not window._demo_processes
