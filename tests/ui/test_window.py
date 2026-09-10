from PySide6.QtWidgets import QScrollArea

from cyberveil.ui.main_window import MainWindow
from cyberveil.ui.theme import stylesheet


def test_window_navigation_rtl_and_settings_theme(qtbot, database) -> None:
    window = MainWindow(database)
    qtbot.addWidget(window)
    window.show()
    assert window.current_page_name() == "dashboard"
    window.navigate("history")
    assert window.current_page_name() == "history"

    settings = window.settings.model_copy(update={"language": "ar"})
    window.save_settings(settings)
    assert window.layoutDirection().name == "RightToLeft"
    window.navigate("settings")
    scroll = window.settings_page.findChild(QScrollArea, "settingsScroll")
    assert scroll is not None
    assert scroll.viewport().objectName() == "settingsViewport"
    assert "QWidget#settingsViewport" in stylesheet()
