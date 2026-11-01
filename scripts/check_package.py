"""Smoke-test the actual frozen artifact with fresh, isolated user data."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=root / "dist")
    dist = parser.parse_args().dist.resolve()
    executable = dist / "CYBERVEIL" / ("CYBERVEIL.exe" if sys.platform == "win32" else "CYBERVEIL")
    if sys.platform == "darwin":
        executable = dist / "CYBERVEIL.app" / "Contents" / "MacOS" / "CYBERVEIL"
    with tempfile.TemporaryDirectory(prefix="cyberveil-package-") as work:
        env = {**os.environ, "CYBERVEIL_DATA_DIR": work, "QT_QPA_PLATFORM": "offscreen"}

        def run(*args: str) -> str:
            result = subprocess.run(
                [str(executable), *args], env=env, cwd=work, text=True, capture_output=True, check=True, timeout=90
            )
            return result.stdout

        doctor = json.loads(run("doctor"))
        assert doctor["model_load_error"] is None
        assert doctor["windows_api_detector"]["load_error"] is None
        assert doctor["windows_api_detector"]["mode"] == "recorded_sandbox_report"
        # A synthetic schema fixture checks frozen import wiring, not detection
        # accuracy. Real-trace evaluation is recorded separately in docs/evidence.
        from cyberveil.detection.api_model import ApiBehaviorClassifier

        api_fixture = Path(work) / "schema-fixture.json"
        api_fixture.write_text(json.dumps({
            "target": {"file": {"sha256": "e" * 64}},
            "behavior": {"processes": [{"process_id": 42, "calls": [
                {"api": api} for api in ApiBehaviorClassifier().vocabulary[:40]
            ]}]},
        }))
        imported = json.loads(run("analyze-sandbox", str(api_fixture)))
        assert imported["source"] == "sandbox_report" and imported["actions_taken"] == 0
        assert imported["model"] == doctor["windows_api_detector"]["model"]
        for language in ("en", "ar"):
            run("export-report", imported["session_id"], "--format", "pdf", "--language", language,
                "--output", str(Path(work) / f"sandbox-{language}.pdf"))
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
        print(json.dumps({"package": str(executable), "model": doctor["model"],
                          "windows_api_model": imported["model"], "checks": "passed"}, indent=2))


if __name__ == "__main__":
    main()
