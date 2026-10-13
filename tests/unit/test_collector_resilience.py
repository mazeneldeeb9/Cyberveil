from unittest.mock import MagicMock

import psutil
import pytest

from cyberveil.collectors import PsutilCollector

ERROR = "proc_pidinfo(PROC_PIDLISTFDS) 2/2 syscall failed"


def process(pid=42, ppid=1):
    proc = MagicMock()
    proc.pid = pid
    proc.info = {"pid": pid, "ppid": ppid}
    proc.ppid.return_value = ppid
    proc.name.return_value = "benign-test"
    proc.create_time.return_value = 1000.0
    proc.username.return_value = "test-user"
    proc.cpu_percent.return_value = 0.0
    proc.memory_info.return_value.rss = 1024
    proc.num_threads.return_value = 1
    proc.open_files.return_value = []
    proc.net_connections.return_value = []
    proc.cmdline.return_value = ["/usr/bin/benign-test"]
    proc.io_counters.return_value.read_bytes = 0
    proc.io_counters.return_value.write_bytes = 0
    return proc


@pytest.mark.parametrize(
    "field,method,attribute",
    [
        ("open_files", "open_files", "open_file_count"),
        ("network_connections", "net_connections", "connection_count"),
    ],
)
def test_failed_optional_syscall_preserves_process(monkeypatch, field, method, attribute):
    proc = process()
    getattr(proc, method).side_effect = RuntimeError(ERROR)
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [proc])
    collector = PsutilCollector()
    samples = collector.collect("test")
    assert len(samples) == 1
    assert getattr(samples[0], attribute) is None
    assert samples[0].rss_bytes == 1024
    assert field in collector.capabilities.unavailable
    assert collector.capabilities.is_degraded
    assert collector.capabilities.notes


def test_unexpected_runtime_errors_are_not_hidden(monkeypatch):
    proc = process()
    proc.open_files.side_effect = RuntimeError("programming bug")
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [proc])
    with pytest.raises(RuntimeError, match="programming bug"):
        PsutilCollector().collect("test")


def test_children_index_includes_unselected_children(monkeypatch):
    parent, child = process(), process(43, 42)
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [parent, child])
    samples = PsutilCollector(max_processes=1).collect("test")
    assert samples[0].child_count == 1
    parent.children.assert_not_called()


def test_failed_required_syscall_skips_only_affected_process(monkeypatch):
    bad, good = process(), process(43)
    bad.name.side_effect = RuntimeError(ERROR)
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [bad, good])
    samples = PsutilCollector().collect("test")
    assert [sample.pid for sample in samples] == [43]
