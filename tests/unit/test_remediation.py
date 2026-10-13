import os

from cyberveil.domain import RemediationAction, RemediationRequest, RemediationStatus
from cyberveil.remediation import ProcessRemediator


def request(**changes: object) -> RemediationRequest:
    values = {
        "detection_id": "d-1",
        "pid": 999_999,
        "process_started_at": 1.0,
        "process_name": "safe-lab",
        "action": RemediationAction.TERMINATE,
        "simulation": True,
    }
    values.update(changes)
    return RemediationRequest(**values)


def test_simulation_never_touches_os_process() -> None:
    result = ProcessRemediator().execute(request())
    assert result.status == RemediationStatus.SUCCEEDED
    assert "no operating-system process" in result.message


def test_current_process_is_protected() -> None:
    import psutil

    process = psutil.Process(os.getpid())
    result = ProcessRemediator().execute(
        request(pid=process.pid, process_started_at=process.create_time(), simulation=False)
    )
    assert result.status == RemediationStatus.REFUSED


def test_ignore_is_audited_success() -> None:
    result = ProcessRemediator().execute(request(action=RemediationAction.IGNORE))
    assert result.status == RemediationStatus.SUCCEEDED
