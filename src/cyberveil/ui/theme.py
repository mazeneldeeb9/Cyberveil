from __future__ import annotations

COLORS = {
    "ink": "#06111F",
    "background": "#081827",
    "surface": "#10253A",
    "surface_raised": "#173149",
    "surface_hover": "#1D3B55",
    "line": "#284A61",
    "accent": "#22D3C5",
    "accent_deep": "#0C918C",
    "accent_soft": "#90F4EA",
    "text": "#F3F8FA",
    "muted": "#A9C0CC",
    "dim": "#718C9C",
    "danger": "#FF6674",
    "warning": "#F5C45A",
    "info": "#5B9CFF",
    "success": "#3DD6A2",
}


def stylesheet() -> str:
    c = COLORS
    return f"""
    * {{
        font-size: 14px;
        color: {c["text"]};
    }}
    QMainWindow, QWidget#root, QWidget#ambient {{ background: {c["background"]}; }}
    QScrollArea#settingsScroll,
    QWidget#settingsViewport,
    QWidget#settingsBody {{
        background: transparent;
        border: none;
    }}
    QLabel#brand {{ font-size: 20px; font-weight: 800; letter-spacing: 2px; }}
    QLabel#pageTitle {{ font-size: 30px; font-weight: 700; }}
    QLabel#heroTitle {{ font-size: 34px; font-weight: 750; }}
    QLabel#sectionTitle {{ font-size: 19px; font-weight: 700; }}
    QLabel#body {{ color: {c["muted"]}; font-size: 15px; }}
    QLabel#muted {{ color: {c["muted"]}; }}
    QLabel#dim {{ color: {c["dim"]}; font-size: 12px; }}
    QLabel#metricValue {{ font-size: 24px; font-weight: 750; color: {c["text"]}; }}
    QLabel#metricLabel {{ color: {c["muted"]}; font-size: 12px; }}
    QLabel#labBadge {{
        color: {c["accent_soft"]}; background: #123B45; border: 1px solid #2A756F;
        border-radius: 9px; padding: 4px 9px; font-size: 10px; font-weight: 700;
    }}
    QFrame#panel {{
        background: {c["surface"]}; border: 1px solid {c["line"]}; border-radius: 16px;
    }}
    QFrame#raisedPanel {{
        background: {c["surface_raised"]}; border-radius: 14px;
    }}
    QFrame#metricStrip {{
        background: #0D2133; border-top: 1px solid {c["line"]}; border-bottom: 1px solid {c["line"]};
    }}
    QPushButton {{
        min-height: 42px; border-radius: 12px; padding: 0 18px; font-weight: 650;
        background: {c["surface_raised"]}; border: 1px solid {c["line"]};
    }}
    QPushButton:hover {{ background: {c["surface_hover"]}; border-color: #3A6A83; }}
    QPushButton:focus {{ border: 2px solid {c["accent"]}; }}
    QPushButton:pressed {{ background: #12283C; }}
    QPushButton:disabled {{ color: {c["dim"]}; background: #0B1B2A; border-color: #20394A; }}
    QPushButton#primary {{
        color: #031A1A; background: {c["accent"]}; border: none; font-size: 15px; font-weight: 750;
    }}
    QPushButton#primary:hover {{ background: #4BE0D4; }}
    QPushButton#danger {{ color: white; background: #C94655; border: none; }}
    QPushButton#danger:hover {{ background: #E25362; }}
    QPushButton#ghost {{ background: transparent; border: none; min-width: 42px; padding: 0 8px; }}
    QPushButton#ghost:hover {{ background: #173149; }}
    QPushButton#actionTile {{
        min-height: 112px; text-align: left; padding: 18px 20px; background: {c["surface"]};
        border: 1px solid {c["line"]}; border-radius: 15px; font-size: 16px;
    }}
    QPushButton#actionTile:hover {{ background: {c["surface_raised"]}; border-color: {c["accent_deep"]}; }}
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
        min-height: 42px; background: #0B1D2E; border: 1px solid {c["line"]};
        border-radius: 11px; padding: 0 13px; selection-background-color: {c["accent_deep"]};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border: 2px solid {c["accent"]}; }}
    QComboBox::drop-down {{ border: none; width: 30px; }}
    QCheckBox {{ spacing: 10px; min-height: 30px; }}
    QCheckBox::indicator {{
        width: 20px; height: 20px; border: 1px solid {c["line"]};
        border-radius: 6px; background: #0B1D2E;
    }}
    QCheckBox::indicator:checked {{ background: {c["accent"]}; border-color: {c["accent"]}; }}
    QTableWidget, QTableView {{
        background: #0B1D2E; alternate-background-color: #0E2335; border: 1px solid {c["line"]};
        border-radius: 13px; gridline-color: {c["line"]}; selection-background-color: #174A55;
    }}
    QHeaderView::section {{
        background: #123C46; color: {c["text"]}; border: none; border-right: 1px solid #28616B;
        padding: 12px; font-weight: 700;
    }}
    QTableWidget::item {{ padding: 9px; border-bottom: 1px solid #1B364A; }}
    QProgressBar {{ height: 7px; background: #10273A; border: none; border-radius: 3px; text-align: center; }}
    QProgressBar::chunk {{ background: {c["accent"]}; border-radius: 3px; }}
    QScrollBar:vertical {{ width: 10px; background: #0C1D2C; margin: 0; }}
    QScrollBar::handle:vertical {{ background: #236D71; min-height: 35px; border-radius: 5px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QTextBrowser, QPlainTextEdit {{
        background: #071522; border: 1px solid {c["line"]}; border-radius: 12px;
        padding: 12px; selection-background-color: {c["accent_deep"]};
    }}
    QDialog {{ background: {c["background"]}; }}
    QToolTip {{ color: {c["text"]}; background: {c["surface_raised"]}; border: 1px solid {c["line"]}; padding: 6px; }}
    """
