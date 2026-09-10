from __future__ import annotations

import os
from pathlib import Path

import pytest

from cyberveil.storage import Database

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def database(tmp_path: Path) -> Database:
    instance = Database(tmp_path / "test.db")
    yield instance
    instance.close()
