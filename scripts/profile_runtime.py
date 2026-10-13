"""Measure the real GUI/live worker on reference hardware, without remediation."""

import argparse
import json
import os
import platform
import tempfile
import time
from pathlib import Path

import psutil
from PySide6.QtCore import QTimer

from cyberveil.domain import ScanSource
from cyberveil.storage import Database
from cyberveil.ui.app import create_application
from cyberveil.ui.main_window import MainWindow


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--output", type=Path, default=Path("tmp/runtime-profile.json"))
    args = parser.parse_args()
    if not 20 <= args.seconds <= 120:
        parser.error("Profile duration must be between 20 and 120 seconds")
    app = create_application()
    work = tempfile.TemporaryDirectory(prefix="cyberveil-profile-")
    database = Database(Path(work.name) / "profile.db")
    window = MainWindow(database)
    window.show()
    process = psutil.Process()
    observations = []
    process.cpu_percent()
    started = time.monotonic()
    window.start_scan(ScanSource.LIVE)
    timer = QTimer()

    def sample() -> None:
        observations.append({"cpu": process.cpu_percent(), "rss_mb": process.memory_info().rss / 1024**2})
        # Do not terminate or ignore any live process. Closing an alert only dismisses its display.
        for dialog in list(window._dialogs):
            dialog.reject()

    def finish() -> None:
        timer.stop()
        window.stop_scan()
        if window.scan_thread:
            window.scan_thread.wait(15000)
        scans = database.list_scans()
        result = {
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "qt_platform": os.environ.get("QT_QPA_PLATFORM", "native"),
            "duration_seconds": round(time.monotonic() - started, 2),
            "average_cpu_percent_one_core": sum(x["cpu"] for x in observations) / len(observations),
            "peak_rss_mb": max(x["rss_mb"] for x in observations),
            "samples": scans[0].sample_count,
            "detections": scans[0].detection_count,
            "status": scans[0].status.value,
            "actions_taken": len(database.list_actions()),
            "targets": {"average_cpu_below_percent": 5, "peak_rss_below_mb": 300},
            "scope": "development Mac, live GUI and pipeline; not a cross-platform benchmark",
        }
        result["targets_passed"] = result["average_cpu_percent_one_core"] < 5 and result["peak_rss_mb"] < 300
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2), flush=True)
        window.close()
        app.quit()

    timer.timeout.connect(sample)
    timer.start(1000)
    QTimer.singleShot(args.seconds * 1000, finish)
    code = app.exec()
    work.cleanup()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
