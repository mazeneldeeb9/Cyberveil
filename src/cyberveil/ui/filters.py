from __future__ import annotations

from PySide6.QtCore import QSignalBlocker, QTimer, Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QPushButton, QWidget

from cyberveil.ui.i18n import Translator


class RecordFilters(QWidget):
    """Bounded, searchable results with translated structured filters and paging."""

    changed = Signal()

    def __init__(self, translator: Translator, *, detections: bool = False) -> None:
        super().__init__()
        self.translator = translator
        self.detections = detections
        self.limit = 100
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setMaxLength(260)
        self.search.setClearButtonEnabled(True)
        self.choice = QComboBox()
        self.more = QPushButton()
        self.more.clicked.connect(self._more)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(180)
        self._debounce.timeout.connect(self._reset)
        self.search.textChanged.connect(lambda: self._debounce.start())
        self.choice.currentIndexChanged.connect(self._reset)
        layout.addWidget(self.search, 1)
        layout.addWidget(self.choice)
        layout.addWidget(self.more)
        self.retranslate()

    def _reset(self) -> None:
        self.limit = 100
        self.changed.emit()

    def _more(self) -> None:
        self.limit += 100
        self.changed.emit()

    def retranslate(self) -> None:
        tr = self.translator
        selected = self.choice.currentData()
        with QSignalBlocker(self.choice):
            self.choice.clear()
            self.choice.addItem(tr("all_severities" if self.detections else "all_sources"), None)
            options = ("high", "medium", "low") if self.detections else ("live", "replay", "demo_process", "forensic")
            for value in options:
                self.choice.addItem(tr.observation(value), value)
            self.choice.setCurrentIndex(max(0, self.choice.findData(selected)))
        key = "search_notifications" if self.detections else "search_history"
        self.search.setPlaceholderText(tr(key))
        self.search.setAccessibleName(tr(key))
        self.choice.setAccessibleName(tr("severity" if self.detections else "source"))
        self.more.setText(tr("load_more"))
