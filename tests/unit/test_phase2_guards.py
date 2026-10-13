import os
from unittest.mock import Mock, patch

import psutil
import pytest

from cyberveil.domain import RemediationAction, RemediationRequest, RemediationStatus
from cyberveil.remediation.process import ProcessRemediator, ProtectedProcessPolicy


def request(**changes):
    values = dict(
        detection_id="guard-test",
        pid=999_999,
        process_started_at=10.0,
        process_name="safe-child",
        action=RemediationAction.TERMINATE,
        confirmed_by="user",
    )
    return RemediationRequest(**(values | changes))


@pytest.mark.parametrize(
    "case, status",
    [
        ("reused", RemediationStatus.STALE_PROCESS),
        ("denied", RemediationStatus.REFUSED),
        ("exited", RemediationStatus.STALE_PROCESS),
        ("renamed", RemediationStatus.STALE_PROCESS),
        ("timeout", RemediationStatus.FAILED),
        ("late_reuse", RemediationStatus.STALE_PROCESS),
    ],
)
def test_process_failure_guards(case, status):
    process = Mock(pid=999_999)
    process.create_time.return_value = 10.0
    process.name.return_value = "safe-child"
    process.is_running.return_value = True
    policy = Mock()
    policy.refusal_reason.return_value = None
    if case == "reused":
        process.create_time.return_value = 11.0
    elif case == "denied":
        process.create_time.side_effect = psutil.AccessDenied(process.pid)
    elif case == "exited":
        process.create_time.side_effect = psutil.NoSuchProcess(process.pid)
    elif case == "renamed":
        process.name.return_value = "changed"
    elif case == "timeout":
        process.wait.side_effect = psutil.TimeoutExpired(3)
    elif case == "late_reuse":
        process.create_time.side_effect = [10.0, 11.0]
    with patch("cyberveil.remediation.process.psutil.Process", return_value=process):
        result = ProcessRemediator(policy).execute(request())
    assert result.status == status
    if case != "timeout":
        process.terminate.assert_not_called()
    process.kill.assert_not_called()


def test_unconfirmed_live_or_force_actions_are_refused():
    for action in (RemediationAction.TERMINATE, RemediationAction.FORCE_KILL):
        with patch("cyberveil.remediation.process.psutil.Process") as factory:
            result = ProcessRemediator().execute(request(action=action, confirmed_by="auto-policy"))
        assert result.status == RemediationStatus.REFUSED
        factory.assert_not_called()


def test_system_name_and_other_user_are_protected():
    process = Mock(pid=999_999)
    process.name.return_value = "lsass.exe"
    assert "protected" in ProtectedProcessPolicy().refusal_reason(process)
    process.name.return_value = "ordinary"
    process.username.return_value = "some-other-account"
    assert "another account" in ProtectedProcessPolicy().refusal_reason(process)


def test_parent_is_protected():
    parent = psutil.Process(os.getpid()).parent()
    if parent is not None:
        assert ProtectedProcessPolicy().refusal_reason(parent)
