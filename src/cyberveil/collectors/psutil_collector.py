from __future__ import annotations

import platform
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import psutil

from cyberveil.domain import CapabilityReport, ScanSource, TelemetrySample

T = TypeVar("T")


class PsutilCollector:
    """Best-effort portable collector that never fails a scan for one inaccessible process."""

    def __init__(self, *, include_network: bool = True, max_processes: int | None = None) -> None:
        self.include_network = include_network
        self.max_processes = max_processes
        self._permission_denied: set[str] = set()
        self._unavailable: set[str] = set()

    @property
    def capabilities(self) -> CapabilityReport:
        fields = {
            "processes",
            "cpu",
            "memory",
            "threads",
            "parent_child",
            "io",
            "open_files",
        }
        if self.include_network:
            fields.add("network_connections")
        fields -= self._unavailable
        notes: list[str] = []
        if self._permission_denied:
            notes.append("Some process fields require elevated operating-system permissions.")
        return CapabilityReport(
            operating_system=platform.system(),
            available=tuple(sorted(fields)),
            unavailable=tuple(sorted(self._unavailable)),
            permission_denied=tuple(sorted(self._permission_denied)),
            notes=tuple(notes),
        )

    def collect(self, session_id: str) -> list[TelemetrySample]:
        samples: list[TelemetrySample] = []
        processes = list(psutil.process_iter())
        if self.max_processes is not None:
            processes = processes[: self.max_processes]
        for proc in processes:
            sample = self._sample_process(proc, session_id)
            if sample is not None:
                samples.append(sample)
        return samples

    def _sample_process(self, proc: psutil.Process, session_id: str) -> TelemetrySample | None:
        try:
            with proc.oneshot():
                pid = proc.pid
                started = proc.create_time()
                name = proc.name() or f"process-{pid}"
                parent_pid = proc.ppid()
                username = self._optional(proc.username, "username")
                cpu = proc.cpu_percent(interval=None)
                memory = proc.memory_info().rss
                threads = proc.num_threads()
                child_default: list[psutil.Process] = []
                children = self._optional(
                    lambda: proc.children(),
                    "parent_child",
                    default=child_default,
                )
                child_count = len(children or [])
                open_files = self._optional_count(proc.open_files, "open_files")
                io_method = getattr(proc, "io_counters", None)
                io = self._optional(io_method, "io") if callable(io_method) else None
                if io_method is None:
                    self._unavailable.add("io")
                read_bytes = getattr(io, "read_bytes", None) if io else None
                write_bytes = getattr(io, "write_bytes", None) if io else None
                connections = self._connections(proc) if self.include_network else None
                command_hint = self._command_hint(proc)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except psutil.AccessDenied:
            self._permission_denied.add("processes")
            return None
        return TelemetrySample(
            session_id=session_id,
            source=ScanSource.LIVE,
            pid=pid,
            process_started_at=started,
            name=name,
            parent_pid=parent_pid,
            username=username,
            cpu_percent=max(0.0, float(cpu)),
            rss_bytes=max(0, int(memory)),
            thread_count=max(0, int(threads)),
            child_count=max(0, int(child_count)),
            connection_count=len(connections) if connections is not None else None,
            listening_port_count=(
                sum(1 for item in connections if item.status == psutil.CONN_LISTEN) if connections is not None else None
            ),
            open_file_count=open_files,
            read_bytes=read_bytes,
            write_bytes=write_bytes,
            command_hint=command_hint,
        )

    def _connections(self, proc: psutil.Process) -> list[Any] | None:
        try:
            return list(proc.net_connections(kind="inet"))
        except psutil.AccessDenied:
            self._permission_denied.add("network_connections")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except (AttributeError, NotImplementedError):
            self._unavailable.add("network_connections")
        return None

    def _command_hint(self, proc: psutil.Process) -> str | None:
        try:
            command = proc.cmdline()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            self._permission_denied.add("command_hint")
            return None
        if not command:
            return None
        executable = Path(command[0]).name
        flags = [item for item in command[1:4] if item.startswith("-") and len(item) <= 24]
        return " ".join((executable, *flags))[:160]

    def _optional(self, function: Callable[[], T], field: str, default: T | None = None) -> T | None:
        try:
            return function()
        except psutil.AccessDenied:
            self._permission_denied.add(field)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return default
        except (AttributeError, NotImplementedError):
            self._unavailable.add(field)
        return default

    def _optional_count(self, function: Callable[[], list[Any]], field: str) -> int | None:
        value = self._optional(function, field)
        return len(value) if value is not None else None
