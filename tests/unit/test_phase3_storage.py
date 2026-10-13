from datetime import timedelta

from cyberveil.domain import LogRecord, ScanRecord, ScanSource, ScanStatus, utc_now


def scan(identifier, *, age=0, status=ScanStatus.COMPLETED, source=ScanSource.REPLAY):
    return ScanRecord(
        session_id=identifier,
        source=source,
        status=status,
        started_at=utc_now() - timedelta(days=age),
        operating_system="test",
    )


def test_filters_search_literal_wildcards_and_paging(database):
    database.create_scan(scan("literal_%"))
    database.create_scan(scan("ordinary", source=ScanSource.LIVE))
    assert len(database.list_scans(search="%")) == 1
    assert len(database.list_scans(source=ScanSource.LIVE)) == 1
    assert not database.list_scans(status=ScanStatus.FAILED)
    assert len(database.list_scans(limit=1)) == 1
    assert database.list_scans(search="ordinary")[0].source == ScanSource.LIVE


def test_retention_keeps_recent_and_running_sessions(database):
    database.create_scan(scan("old", age=100))
    database.create_scan(scan("recent", age=1))
    database.create_scan(scan("active", age=100, status=ScanStatus.RUNNING))
    database.log(LogRecord(occurred_at=utc_now() - timedelta(days=100), event="old", message="old"))
    database.log(
        LogRecord(
            occurred_at=utc_now() - timedelta(days=100),
            event="active",
            message="keep",
            context={"session_id": "active"},
        )
    )
    assert database.purge_history(30) == (1, 1)
    assert {s.session_id for s in database.list_scans()} == {"recent", "active"}
    assert {log.event for log in database.list_logs()} == {"active", "history.retention"}
