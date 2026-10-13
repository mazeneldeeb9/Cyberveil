from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from cyberveil.collectors import ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import CompositeClassifier, FeatureExtractor
from cyberveil.domain import AppSettings, ScanSource, TelemetrySample
from cyberveil.engine import MonitoringEngine


def sample(second: int, **changes) -> TelemetrySample:
    values = dict(
        session_id="session",
        pid=10,
        name="demo",
        process_started_at=1,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=second),
        cpu_percent=second,
        rss_bytes=(100 + second) * 1024 * 1024,
    )
    values.update(changes)
    return TelemetrySample(**values)


def test_window_requires_fifteen_samples_and_drops_old_timestamps():
    extractor = FeatureExtractor()
    for second in range(14):
        assert extractor.ingest(sample(second)) is None
    window = extractor.ingest(sample(14))
    assert window.values["cpu_mean"] == 7
    assert window.values["rss_delta_mb"] == 14
    assert window.missing_fields == ("network_connections", "open_files", "io")
    window = extractor.ingest(sample(15))
    assert window.window_start == sample(1).observed_at
    assert extractor.ingest(sample(60)) is None
    assert extractor.ingest(sample(59)) is None


def test_windows_are_isolated_by_session_and_process_start():
    extractor = FeatureExtractor(min_samples=2)
    assert extractor.ingest(sample(0)) is None
    assert extractor.ingest(sample(1, session_id="another")) is None
    assert extractor.ingest(sample(2, process_started_at=2)) is None
    extractor.prune(sample(60).observed_at)
    assert not extractor._samples


def test_engine_scores_every_two_seconds_after_warmup(database):
    classifier = CompositeClassifier()
    classifier.score = Mock(wraps=classifier.score)
    engine = MonitoringEngine(database, classifier, AppSettings(), source=ScanSource.REPLAY)
    engine.start()
    for batch in replay_samples(ReplayScenario.SUSPICIOUS_BURST, engine.session_id, steps=20):
        engine.ingest(batch)
    assert classifier.score.call_count == 3  # t=14, 16, 18
    observed = [call.args[0].window_end for call in classifier.score.call_args_list]
    assert all((b - a).total_seconds() == 2 for a, b in zip(observed, observed[1:], strict=False))
    engine.finish()
    detection = database.list_detections(engine.session_id)[0]
    assert detection.feature_values and detection.reasons


def test_engine_rejects_foreign_session(database):
    engine = MonitoringEngine(database, CompositeClassifier(), AppSettings(), source=ScanSource.LIVE)
    engine.start()
    with pytest.raises(ValueError, match="different session"):
        engine.ingest([sample(0)])
    engine.finish()


def test_replays_have_repeatable_scores_and_benign_has_no_alert(database):
    signatures = []
    for scenario in (ReplayScenario.SUSPICIOUS_BURST, ReplayScenario.SUSPICIOUS_BURST, ReplayScenario.BENIGN_BROWSE):
        engine = MonitoringEngine(database, CompositeClassifier(), AppSettings(), source=ScanSource.REPLAY)
        engine.start()
        results = []
        for batch in replay_samples(scenario, engine.session_id):
            results.extend(engine.ingest(batch))
        engine.finish()
        signatures.append([(item.score, item.severity, item.reasons) for item in results])
    assert signatures[0] == signatures[1] and signatures[0]
    assert signatures[2] == []
