"""Generate bilingual release evidence from safe replay, using isolated data."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from cyberveil.collectors import ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import CompositeClassifier
from cyberveil.domain import AppSettings, ForensicFinding, ScanSource
from cyberveil.engine import MonitoringEngine
from cyberveil.integrations import OllamaExplainer
from cyberveil.paths import bundled_model_path
from cyberveil.reports import ReportService
from cyberveil.storage import Database
from cyberveil.ui.app import create_application
from cyberveil.ui.main_window import MainWindow


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("tmp/phase3-checks"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    app = create_application()
    with TemporaryDirectory(prefix="cyberveil-phase3-") as folder:
        database = Database(Path(folder) / "acceptance.db")
        classifier = CompositeClassifier(bundled_model_path())
        assert classifier.load_error is None
        engine = MonitoringEngine(database, classifier, AppSettings(), source=ScanSource.REPLAY)
        engine.start()
        for samples in replay_samples(ReplayScenario.SUSPICIOUS_BURST, engine.session_id):
            engine.ingest(samples)
        engine.finish()
        service = ReportService(database)
        report = service.build(engine.session_id)
        assert report.detections
        window = MainWindow(database)
        window.show()
        for language in ("en", "ar"):
            window.save_settings(window.settings.model_copy(update={"language": language}))
            for fmt in ("json", "csv", "pdf"):
                getattr(service, f"export_{fmt}")(report, args.output / f"report-{language}.{fmt}", language=language)
            explanation = OllamaExplainer("").explain(report, language=language)
            assert explanation.generated_by == "CYBERVEIL template"
            for width, height in ((1024, 700), (1440, 900)):
                window.resize(width, height)
                for page in ("dashboard", "settings", "notifications", "report"):
                    if page == "report":
                        window.open_report(engine.session_id)
                    else:
                        window.navigate(page, remember=False)
                    app.processEvents()
                    target = args.output / f"{page}-{language}-{width}.png"
                    assert window.grab().save(str(target))
        # A separately labeled rendering fixture exercises pagination, not real forensic analysis.
        long_report = report.model_copy(
            update={
                "forensic_findings": (
                    ForensicFinding(
                        plugin="rendering.fixture",
                        category="rendering_test",
                        title="Pagination fixture - not forensic evidence",
                        details={"rows": [{"index": i, "example": "Synthetic rendering fixture"} for i in range(35)]},
                    ),
                )
            }
        )
        service.export_pdf(long_report, args.output / "pagination-fixture.pdf", redact_sensitive=False)
        window.close()
    (args.output / "checks.json").write_text(
        json.dumps(
            {
                "model": classifier.version,
                "safe_replay": True,
                "languages": ["en", "ar"],
                "exports": ["pdf", "json", "csv"],
                "screenshots": 16,
                "real_malware_tested": False,
                "real_memory_image_tested": False,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(args.output.resolve())


if __name__ == "__main__":
    main()
