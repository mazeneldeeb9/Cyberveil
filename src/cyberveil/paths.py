from __future__ import annotations

import os
import platform
from pathlib import Path


def data_dir() -> Path:
    override = os.environ.get("CYBERVEIL_DATA_DIR")
    if override:
        path = Path(override).expanduser()
    elif platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        path = base / "Cyberveil"
    elif platform.system() == "Darwin":
        path = Path.home() / "Library" / "Application Support" / "Cyberveil"
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "cyberveil"
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_dir() / "cyberveil.db"


def report_dir() -> Path:
    path = data_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def bundled_model_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "models" / "behavior-model.skops"
