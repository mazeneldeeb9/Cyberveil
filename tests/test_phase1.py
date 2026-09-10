from __future__ import annotations

from pathlib import Path

from cyberveil.collectors import ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.domain import AppSettings, LogRecord, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.storage import Database


def test_safe_replay_is_deterministic() -> None:
    first = list(replay_samples(ReplayScenario.SUSPICIOUS_BURST, "session", steps=4))
    second = list(replay_samples(ReplayScenario.SUSPICIOUS_BURST, "session", steps=4))
    first_values = [(item[0].pid, item[0].cpu_percent, item[0].rss_bytes) for item in first]
    second_values = [(item[0].pid, item[0].cpu_percent, item[0].rss_bytes) for item in second]
    assert first_values == second_values
    assert all(item[0].source is ScanSource.REPLAY for item in first)


def test_scan_history_logs_and_settings_persist(tmp_path: Path) -> None:
    path = tmp_path / "phase1.db"
    database = Database(path)
    database.create_scan(
        ScanRecord(
            session_id="phase1-scan",
            source=ScanSource.REPLAY,
            status=ScanStatus.RUNNING,
            started_at=utc_now(),
            operating_system="TestOS",
            model_version="telemetry-v1",
        )
    )
    database.finish_scan("phase1-scan", ScanStatus.COMPLETED, 18, 0)
    database.log(LogRecord(event="scan.finished", message="Telemetry session completed"))
    database.save_settings(AppSettings(language="ar", retention_days=14))
    database.close()

    reopened = Database(path)
    assert reopened.get_scan("phase1-scan").sample_count == 18  # type: ignore[union-attr]
    assert reopened.list_logs()[0].event == "scan.finished"
    assert reopened.load_settings().language == "ar"
    reopened.close()
