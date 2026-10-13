"""Repeatable acceptance check using an isolated database and the bundled model."""

from __future__ import annotations

import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np

from cyberveil.collectors import ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import CompositeClassifier
from cyberveil.domain import AppSettings, ScanSource, Severity
from cyberveil.engine import MonitoringEngine
from cyberveil.paths import bundled_model_path
from cyberveil.reports import ReportService
from cyberveil.storage import Database


def main() -> None:
    classifier = CompositeClassifier(bundled_model_path())
    if classifier.load_error or not classifier.version.startswith("sklearn-"):
        raise RuntimeError(f"Bundled model did not load: {classifier.load_error}")
    results = {}
    durations = []
    with TemporaryDirectory(prefix="cyberveil-phase2-") as folder:
        database = Database(Path(folder) / "acceptance.db")
        for scenario in ReplayScenario:
            engine = MonitoringEngine(database, classifier, AppSettings(), source=ScanSource.REPLAY)
            engine.start()
            detections = []
            for batch in replay_samples(scenario, engine.session_id, steps=40):
                started = time.perf_counter()
                detections.extend(engine.ingest(batch))
                durations.append((time.perf_counter() - started) * 1000)
            engine.finish()
            if scenario == ReplayScenario.BENIGN_BROWSE:
                assert not detections, "Benign scenario generated an alert"
            else:
                assert any(item.severity == Severity.HIGH for item in detections)
            report = ReportService(database).build(engine.session_id)
            assert len(report.detections) == len(detections)
            destination = Path(folder) / f"{scenario.value}.json"
            ReportService(database).export_json(report, destination)
            assert json.loads(destination.read_text())["scan"]["sample_count"] == 40
            results[scenario.value] = {"samples": 40, "detections": len(detections)}
        database.close()
    print(
        json.dumps(
            {
                "model": classifier.version,
                "scenarios": results,
                "feature_inference_and_storage_p95_ms": float(np.percentile(durations, 95)),
                "lab_only": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
