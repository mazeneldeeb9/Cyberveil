from __future__ import annotations

import os
import platform

import psutil

from cyberveil.domain import (
    RemediationAction,
    RemediationRequest,
    RemediationResult,
    RemediationStatus,
)


class ProtectedProcessPolicy:
    COMMON_PROTECTED = {
        "cyberveil",
        "cyberveil.exe",
        "init",
        "kernel_task",
        "launchd",
        "loginwindow",
        "services.exe",
        "smss.exe",
        "system",
        "systemd",
        "wininit.exe",
        "winlogon.exe",
        "lsass.exe",
        "csrss.exe",
        "svchost.exe",
        "registry",
        "secure system",
        "windowserver",
        "logind",
        "sshd",
    }

    def __init__(self, additional_names: set[str] | None = None) -> None:
        self.names = self.COMMON_PROTECTED | {item.lower() for item in (additional_names or set())}

    def refusal_reason(self, process: psutil.Process) -> str | None:
        if process.pid in {0, 1, os.getpid()}:
            return "This process is protected by CYBERVEIL."
        try:
            name = process.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "The process identity cannot be safely verified."
        if name in self.names:
            return f"{name} is on the protected-process list."
        if platform.system() == "Windows" and process.pid <= 4:
            return "Core Windows processes cannot be terminated."
        try:
            current = psutil.Process(os.getpid())
            ancestors = {item.pid for item in current.parents()}
            if process.pid in ancestors:
                return "A parent of CYBERVEIL cannot be terminated."
            owner = process.username()
            if owner != current.username():
                return "Processes owned by another account cannot be terminated."
            if owner.lower() in {"root", "system", "nt authority\\system", "local service", "network service"}:
                return "System-owned processes cannot be terminated."
            executable = process.exe()
            if not executable:
                return "The process executable could not be verified."
            normalized = executable.replace("\\", "/").lower()
            if normalized.startswith(("/system/", "/sbin/", "/usr/sbin/")) or "/windows/system32/" in normalized:
                return "System executables cannot be terminated."
        except (psutil.Error, RuntimeError, OSError):
            return "CYBERVEIL could not verify its process ancestry."
        return None


class ProcessRemediator:
    def __init__(self, policy: ProtectedProcessPolicy | None = None) -> None:
        self.policy = policy or ProtectedProcessPolicy()

    def execute(self, request: RemediationRequest) -> RemediationResult:
        if request.action == RemediationAction.IGNORE:
            return RemediationResult(
                detection_id=request.detection_id,
                action=request.action,
                status=RemediationStatus.SUCCEEDED,
                message="Detection ignored and recorded for this incident.",
            )
        if request.simulation:
            return RemediationResult(
                detection_id=request.detection_id,
                action=request.action,
                status=RemediationStatus.SUCCEEDED,
                message="Safe replay containment recorded; no operating-system process was touched.",
            )
        if request.confirmed_by != "user":
            return self._result(
                request, RemediationStatus.REFUSED, "Live termination requires explicit user confirmation."
            )
        try:
            process = psutil.Process(request.pid)
            actual_start = process.create_time()
            actual_name = process.name()
        except psutil.NoSuchProcess:
            return self._result(request, RemediationStatus.STALE_PROCESS, "Process has exited.")
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError, RuntimeError) as exc:
            return self._result(request, RemediationStatus.REFUSED, f"Identity check failed: {exc}")
        if abs(actual_start - request.process_started_at) > 0.01:
            return self._result(
                request,
                RemediationStatus.STALE_PROCESS,
                "PID was reused; no action was taken.",
            )
        reason = self.policy.refusal_reason(process)
        if reason:
            return self._result(request, RemediationStatus.REFUSED, reason)
        if actual_name != request.process_name:
            return self._result(request, RemediationStatus.STALE_PROCESS, "Process name changed; no action was taken.")
        try:
            if not process.is_running() or abs(process.create_time() - request.process_started_at) > 0.01:
                return self._result(request, RemediationStatus.STALE_PROCESS, "Process identity changed before action.")
            if request.action == RemediationAction.FORCE_KILL:
                process.kill()
                process.wait(timeout=3)
                message = "Process force-terminated after explicit confirmation."
            else:
                process.terminate()
                process.wait(timeout=3)
                message = "Process terminated successfully."
            return self._result(request, RemediationStatus.SUCCEEDED, message)
        except psutil.TimeoutExpired:
            return self._result(
                request,
                RemediationStatus.FAILED,
                "Process did not stop in three seconds; force termination requires confirmation.",
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError, RuntimeError) as exc:
            return self._result(request, RemediationStatus.FAILED, str(exc))

    @staticmethod
    def _result(request: RemediationRequest, status: RemediationStatus, message: str) -> RemediationResult:
        return RemediationResult(
            detection_id=request.detection_id,
            action=request.action,
            status=status,
            message=message,
        )
