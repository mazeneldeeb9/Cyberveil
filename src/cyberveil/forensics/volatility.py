from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from cyberveil.domain import ForensicFinding, Severity


class VolatilityUnavailable(RuntimeError):
    pass


PLUGIN_SETS = {
    "windows": ("windows.pslist.PsList", "windows.pstree.PsTree", "windows.malfind.Malfind"),
    "linux": ("linux.pslist.PsList", "linux.pstree.PsTree"),
    "mac": ("mac.pslist.PsList", "mac.pstree.PsTree"),
}


class VolatilityAnalyzer:
    def __init__(self, executable: str | None = None) -> None:
        local = Path(sys.executable).parent / ("vol.exe" if sys.platform == "win32" else "vol")
        self.executable = (
            executable or (str(local) if local.is_file() else None) or shutil.which("vol") or shutil.which("vol.py")
        )

    @property
    def available(self) -> bool:
        return bool(self.executable)

    def analyze(self, image_path: Path, operating_system: str) -> tuple[ForensicFinding, ...]:
        if not self.executable:
            raise VolatilityUnavailable("Volatility 3 is not installed. Install CYBERVEIL with the forensics extra.")
        if not image_path.is_file():
            raise ValueError("The selected memory image does not exist")
        os_key = operating_system.lower()
        if os_key not in PLUGIN_SETS:
            raise ValueError("Operating system must be windows, linux, or mac")
        findings: list[ForensicFinding] = []
        for plugin in PLUGIN_SETS[os_key]:
            command = [self.executable, "--offline", "-q", "-r", "json", "-f", str(image_path.resolve()), plugin]
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                findings.append(self._error(plugin, str(exc)))
                continue
            if completed.returncode != 0:
                message = (completed.stderr or completed.stdout).strip()[-800:]
                findings.append(
                    ForensicFinding(
                        plugin=plugin,
                        category="analysis_error",
                        severity=Severity.LOW,
                        title="Volatility plugin could not complete",
                        details={"message": message},
                    )
                )
                continue
            try:
                rows = self._rows(completed.stdout)
            except ValueError:
                findings.append(
                    self._error(plugin, "Volatility returned invalid JSON; check plugin and symbol compatibility.")
                )
                continue
            severity = Severity.MEDIUM if "malfind" in plugin.lower() and rows else Severity.LOW
            findings.append(
                ForensicFinding(
                    plugin=plugin,
                    category="memory_analysis",
                    severity=severity,
                    title=f"{plugin.rsplit('.', 1)[-1]} returned {len(rows)} row(s)",
                    details={"rows": rows[:100], "truncated": len(rows) > 100},
                )
            )
        return tuple(findings)

    @staticmethod
    def _error(plugin: str, message: str) -> ForensicFinding:
        return ForensicFinding(
            plugin=plugin,
            category="analysis_error",
            title="Volatility plugin could not complete",
            details={"message": message[-800:]},
        )

    @staticmethod
    def _rows(output: str) -> list[object]:
        payload = json.loads(output)
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("rows", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
            return [payload]
        raise ValueError("Expected Volatility JSON rows")
