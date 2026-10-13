from cyberveil.collectors import ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import FeatureExtractor, RuleBasedClassifier
from cyberveil.domain import ScanSource, Severity


def _detections(scenario: ReplayScenario):
    extractor = FeatureExtractor()
    classifier = RuleBasedClassifier()
    results = []
    for batch in replay_samples(scenario, "session"):
        for sample in batch:
            window = extractor.ingest(sample)
            if window:
                results.append(classifier.score(window, threshold=0.85, source=ScanSource.REPLAY))
    return results


def test_benign_replay_stays_below_medium() -> None:
    assert all(item.severity in (Severity.NORMAL, Severity.LOW) for item in _detections(ReplayScenario.BENIGN_BROWSE))


def test_suspicious_replay_reaches_high_and_explains_score() -> None:
    detections = _detections(ReplayScenario.SUSPICIOUS_BURST)
    assert any(item.severity == Severity.HIGH for item in detections)
    assert any(
        "memory" in reason.lower() or "child" in reason.lower() for item in detections for reason in item.reasons
    )


def test_feature_extractor_rejects_invalid_window() -> None:
    try:
        FeatureExtractor(window_samples=2, min_samples=4)
    except ValueError as exc:
        assert "window_samples" in str(exc)
    else:
        raise AssertionError("Expected invalid window configuration to fail")
