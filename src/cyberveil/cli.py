from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from cyberveil import __version__
from cyberveil.collectors import PsutilCollector, ReplayScenario, available_scenarios
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import CompositeClassifier, FeatureExtractor
from cyberveil.detection.runtime import FEATURE_NAMES
from cyberveil.domain import (
    RemediationAction,
    RemediationRequest,
    RemediationStatus,
    ScanRecord,
    ScanSource,
    ScanStatus,
    utc_now,
)
from cyberveil.engine import MonitoringEngine
from cyberveil.forensics.service import ForensicService
from cyberveil.paths import bundled_model_path, database_path, report_dir
from cyberveil.remediation import ProcessRemediator
from cyberveil.remediation.demo import HarmlessDemo
from cyberveil.storage import Database


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberveil",
        description="CYBERVEIL safe behavior-monitoring academic demonstrator",
    )
    subparsers = parser.add_subparsers(dest="command")
    parser.add_argument("--version", action="version", version=f"CYBERVEIL {__version__}")
    gui = subparsers.add_parser("gui", help="Launch the desktop application")
    gui.add_argument("--smoke-test", action="store_true", help="Open the UI and close after three seconds")
    subparsers.add_parser("doctor", help="Report local runtime and bundled model availability")

    replay = subparsers.add_parser("replay", help="Run a deterministic safe replay")
    replay.add_argument("--scenario", choices=available_scenarios(), default="suspicious-burst")
    demo = subparsers.add_parser("demo-remediation", help="Launch and terminate a harmless sleeping child process")
    demo.add_argument("--confirm", action="store_true", required=True, help="Confirm termination of the demo child")

    collect = subparsers.add_parser("collect-benign", help="Collect labeled benign feature rows")
    collect.add_argument("--seconds", type=int, default=30)
    collect.add_argument("--output", type=Path, default=Path("data/benign-features.csv"))

    monitor = subparsers.add_parser("monitor", help="Run read-only live monitoring without a desktop")
    monitor.add_argument("--seconds", type=int, default=30)
    monitor.add_argument("--output", type=Path, help="Write the session result as JSON")

    dataset = subparsers.add_parser("build-demo-dataset", help="Build a synthetic lab dataset")
    dataset.add_argument("--output", type=Path, default=Path("data/demo-dataset.csv"))

    train = subparsers.add_parser("train", help="Train and compare the approved classifiers")
    train.add_argument("dataset", type=Path)
    train.add_argument("--output", type=Path, default=bundled_model_path())

    memory = subparsers.add_parser("analyze-memory", help="Analyze an acquired memory image")
    memory.add_argument("image", type=Path)
    memory.add_argument("--os", choices=("windows", "linux", "mac"), required=True)

    export = subparsers.add_parser("export-report", help="Export a stored scan report")
    export.add_argument("session_id")
    export.add_argument("--format", choices=("json", "csv", "pdf"), default="json")
    export.add_argument("--output", type=Path)
    export.add_argument("--language", choices=("en", "ar"), default="en")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"CYBERVEIL: {exc}", file=sys.stderr)
        return 1


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "gui"
    if command == "gui":
        from cyberveil.ui.app import run

        return run(smoke_test=getattr(args, "smoke_test", False))
    if command == "doctor":
        classifier = CompositeClassifier(bundled_model_path())
        print(json.dumps({"version": __version__, "platform": platform.platform(),
                          "model": classifier.version, "model_load_error": classifier.load_error,
                          "lab_only": True, "data_directory": str(database_path().parent)}, indent=2))
        return int(classifier.load_error is not None)
    if command == "replay":
        return _replay(ReplayScenario(args.scenario))
    if command == "demo-remediation":
        return _demo_remediation()
    if command == "collect-benign":
        return _collect_benign(args.seconds, args.output)
    if command == "monitor":
        return _monitor(args.seconds, args.output)
    if command == "build-demo-dataset":
        from cyberveil.training import build_demo_dataset

        output = build_demo_dataset(args.output)
        print(output)
        return 0
    if command == "train":
        from cyberveil.training import train_model

        result = train_model(args.dataset, args.output)
        print(
            json.dumps(
                asdict(result),
                indent=2,
            )
        )
        return 0
    if command == "analyze-memory":
        database = Database(database_path())
        try:
            analysis = ForensicService(database).analyze(args.image, args.os)
            print(analysis.model_dump_json(indent=2))
            return int(any(f.category == "analysis_error" for f in analysis.findings))
        finally:
            database.close()
    if command == "export-report":
        return _export_report(args.session_id, args.format, args.output, args.language)
    return 2


def _demo_remediation() -> int:
    database = Database(database_path())
    try:
        with HarmlessDemo() as demo:
            session_id = str(uuid4())
            database.create_scan(
                ScanRecord(
                    session_id=session_id,
                    source=ScanSource.DEMO_PROCESS,
                    status=ScanStatus.RUNNING,
                    started_at=utc_now(),
                    operating_system=platform.system(),
                    model_version="manual-containment-demo",
                )
            )
            detection = demo.detection(session_id)
            database.save_detection(detection)
            result = ProcessRemediator().execute(
                RemediationRequest(
                    detection_id=detection.detection_id,
                    pid=detection.pid,
                    process_started_at=detection.process_started_at,
                    process_name=detection.process_name,
                    action=RemediationAction.TERMINATE,
                    confirmed_by="user",
                )
            )
            database.record_remediation(result)
            database.finish_scan(session_id, ScanStatus.COMPLETED, 0, 1)
            print(json.dumps({"session_id": session_id, "result": result.model_dump(mode="json")}, indent=2))
            return 0 if result.status == RemediationStatus.SUCCEEDED else 1
    finally:
        database.close()


def _replay(scenario: ReplayScenario) -> int:
    database = Database(database_path())
    try:
        settings = database.load_settings()
        engine = MonitoringEngine(
            database,
            CompositeClassifier(bundled_model_path()),
            settings,
            source=ScanSource.REPLAY,
        )
        engine.start()
        detections = []
        for batch in replay_samples(scenario, engine.session_id):
            detections.extend(engine.ingest(batch))
        engine.finish()
        print(
            json.dumps(
                {
                    "session_id": engine.session_id,
                    "scenario": scenario.value,
                    "samples": engine.sample_count,
                    "detections": [item.model_dump(mode="json") for item in detections],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    finally:
        database.close()


def _collect_benign(seconds: int, output: Path) -> int:
    import pandas as pd

    if seconds < 15:
        raise ValueError("Collect for at least fifteen seconds")
    session_id = f"benign-live-{int(time.time())}"
    collector = PsutilCollector()
    extractor = FeatureExtractor()
    rows: list[dict[str, float | int | str]] = []
    for _ in range(seconds):
        for sample in collector.collect(session_id):
            window = extractor.ingest(sample)
            if window:
                row: dict[str, float | int | str] = {name: window.values[name] for name in FEATURE_NAMES}
                row.update({"session_id": session_id, "scenario": "benign-live", "label": 0, "lab_only": 1})
                rows.append(row)
        time.sleep(1)
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output, index=False)
    print(
        json.dumps(
            {
                "output": str(output),
                "rows": len(rows),
                "capabilities": collector.capabilities.model_dump(mode="json"),
            },
            indent=2,
        )
    )
    return 0


def _monitor(seconds: int, output: Path | None) -> int:
    if not 15 <= seconds <= 3600:
        raise ValueError("Monitoring duration must be between 15 and 3600 seconds")
    database = Database(database_path())
    collector = PsutilCollector()
    engine = MonitoringEngine(
        database, CompositeClassifier(bundled_model_path()), database.load_settings(), source=ScanSource.LIVE,
    )
    status, error = ScanStatus.COMPLETED, None
    try:
        engine.start()
        next_sample = time.monotonic()
        deadline = next_sample + seconds
        try:
            while time.monotonic() < deadline:
                batch = collector.collect(engine.session_id)
                for detection in engine.ingest(batch):
                    print(detection.model_dump_json(), file=sys.stderr, flush=True)
                next_sample = max(next_sample + 1, time.monotonic())
                time.sleep(max(0, min(next_sample, deadline) - time.monotonic()))
            if not engine.sample_count:
                status, error = ScanStatus.FAILED, "No processes could be observed; check OS permissions."
        except KeyboardInterrupt:
            status = ScanStatus.STOPPED
        except Exception as exc:
            status, error = ScanStatus.FAILED, str(exc)
        engine.finish(status, error)
        payload = {
            "session_id": engine.session_id, "status": status.value, "error": error,
            "samples": engine.sample_count, "detections": engine.detection_count,
            "model": engine.classifier.version, "model_load_error": engine.classifier.load_error,
            "capabilities": collector.capabilities.model_dump(mode="json"),
            "actions_taken": 0, "lab_only": True,
        }
        serialized = json.dumps(payload, indent=2)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(serialized, encoding="utf-8")
        print(serialized, flush=True)
        return int(status == ScanStatus.FAILED)
    finally:
        database.close()


def _export_report(session_id: str, format_name: str, output: Path | None, language: str) -> int:
    from cyberveil.reports import ReportService

    database = Database(database_path())
    try:
        service = ReportService(database)
        report = service.build(session_id)
        destination = output or report_dir() / f"cyberveil-{session_id[:8]}.{format_name}"
        if format_name == "json":
            service.export_json(report, destination, language=language)
        elif format_name == "csv":
            service.export_csv(report, destination, language=language)
        else:
            service.export_pdf(report, destination, language=language)
        print(destination)
        return 0
    finally:
        database.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
