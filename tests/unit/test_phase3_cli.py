from cyberveil import cli
from cyberveil.domain import TelemetrySample
from cyberveil.storage import Database


def test_headless_monitor_records_read_only_session(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CYBERVEIL_DATA_DIR", str(tmp_path))
    clock = [0.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(cli.PsutilCollector, "collect", lambda _, session: [TelemetrySample(
        session_id=session, pid=200, process_started_at=1, name="test-process",
        cpu_percent=0, rss_bytes=1, thread_count=1, child_count=0,
    )])
    assert cli.main(["monitor", "--seconds", "15", "--output", str(tmp_path / "result.json")]) == 0
    assert '"actions_taken": 0' in capsys.readouterr().out
    database = Database(tmp_path / "cyberveil.db")
    assert database.list_scans()[0].sample_count == 15
    assert database.list_actions() == []
    database.close()


def test_no_visible_processes_is_not_clean_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CYBERVEIL_DATA_DIR", str(tmp_path))
    clock = [0.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(cli.PsutilCollector, "collect", lambda *_: [])
    assert cli.main(["monitor", "--seconds", "15"]) == 1
    assert '"status": "failed"' in capsys.readouterr().out


def test_invalid_monitor_duration(capsys):
    assert cli.main(["monitor", "--seconds", "1"]) == 1
    assert "15 and 3600" in capsys.readouterr().err
