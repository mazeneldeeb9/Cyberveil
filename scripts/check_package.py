"""Smoke-test the actual frozen artifact with fresh, isolated user data."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    executable = root / "dist" / "CYBERVEIL" / ("CYBERVEIL.exe" if sys.platform == "win32" else "CYBERVEIL")
    if sys.platform == "darwin":
        executable = root / "dist" / "CYBERVEIL.app" / "Contents" / "MacOS" / "CYBERVEIL"
    with tempfile.TemporaryDirectory(prefix="cyberveil-package-") as work:
        env = {**os.environ, "CYBERVEIL_DATA_DIR": work, "QT_QPA_PLATFORM": "offscreen"}

        def run(*args: str) -> str:
            result = subprocess.run(
                [str(executable), *args], env=env, cwd=work, text=True, capture_output=True, check=True, timeout=90
            )
            return result.stdout

        doctor = json.loads(run("doctor"))
        assert doctor["model_load_error"] is None
        replay = json.loads(run("replay"))
        assert replay["detections"]
        for language in ("en", "ar"):
            for extension in ("json", "csv", "pdf"):
                path = Path(work) / f"report-{language}.{extension}"
                run(
                    "export-report",
                    replay["session_id"],
                    "--format",
                    extension,
                    "--language",
                    language,
                    "--output",
                    str(path),
                )
                assert path.stat().st_size > 100
        demo = json.loads(run("demo-remediation", "--confirm"))
        assert demo["result"]["status"] == "succeeded"
        run("gui", "--smoke-test")
        print(json.dumps({"package": str(executable), "model": doctor["model"], "checks": "passed"}, indent=2))


if __name__ == "__main__":
    main()
