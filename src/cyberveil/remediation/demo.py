"""A bounded, harmless child used to exercise the real process-termination path."""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
from pathlib import Path

import psutil

from cyberveil.domain import DetectionResult, ScanSource, Severity


class HarmlessDemo:
    def __init__(self) -> None:
        # The child only sleeps and exits after two minutes even if the UI is closed unexpectedly.
        helper = Path(sys.executable).with_name("CYBERVEIL-demo.exe" if sys.platform == "win32" else "CYBERVEIL-demo")
        command = ([str(helper)] if getattr(sys, "frozen", False) else
                   [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(120)"])
        self.child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        # Wait for the child to finish exec/startup before capturing its name.
        # macOS initially reports the launcher name, which otherwise triggers the identity guard.
        ready: queue.Queue[str] = queue.Queue()
        stream = self.child.stdout
        assert stream is not None
        threading.Thread(target=lambda: ready.put(stream.readline()), daemon=True).start()
        try:
            if ready.get(timeout=5).strip() != "ready":
                raise RuntimeError("The harmless demo child did not start")
        except queue.Empty as exc:
            self.close()
            raise RuntimeError("The harmless demo child timed out during startup") from exc
        except RuntimeError:
            self.close()
            raise
        finally:
            stream.close()
        process = psutil.Process(self.child.pid)
        self.started_at = process.create_time()
        self.name = process.name()

    def detection(self, session_id: str) -> DetectionResult:
        return DetectionResult(
            session_id=session_id,
            pid=self.child.pid,
            process_started_at=self.started_at,
            process_name=self.name,
            model_version="manual-containment-demo",
            score=1.0,
            severity=Severity.HIGH,
            label="harmless-demo",
            threshold=0.85,
            reasons=("Harmless child launched by CYBERVEIL to demonstrate confirmed process termination.",),
            source=ScanSource.DEMO_PROCESS,
        )

    def close(self) -> None:
        if self.child.poll() is None:
            try:
                self.child.terminate()
                self.child.wait(timeout=3)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=3)

    def __enter__(self) -> HarmlessDemo:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
