from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Protocol

from cyberveil.domain import DetectionResult, FeatureWindow, ScanSource, Severity

FEATURE_NAMES = (
    "cpu_mean",
    "cpu_max",
    "cpu_std",
    "rss_mean_mb",
    "rss_max_mb",
    "rss_growth_ratio",
    "rss_delta_mb",
    "thread_mean",
    "thread_max",
    "thread_delta",
    "child_max",
    "child_delta",
    "connection_mean",
    "connection_max",
    "connection_delta",
    "open_file_max",
    "read_delta_mb",
    "write_delta_mb",
    "encoded_command_hint",
    "process_age_seconds",
)


class ThreatClassifier(Protocol):
    @property
    def version(self) -> str: ...

    def score(self, window: FeatureWindow, *, threshold: float, source: ScanSource) -> DetectionResult: ...


def severity_for(score: float, high_threshold: float) -> Severity:
    if score >= high_threshold:
        return Severity.HIGH
    if score >= 0.65:
        return Severity.MEDIUM
    if score >= 0.40:
        return Severity.LOW
    return Severity.NORMAL


class RuleBasedClassifier:
    """Transparent fallback and demo classifier; never represented as trained ML."""

    version = "rules-v1"

    def score(
        self,
        window: FeatureWindow,
        *,
        threshold: float = 0.85,
        source: ScanSource = ScanSource.LIVE,
    ) -> DetectionResult:
        features = window.values
        score = 0.05
        reasons: list[str] = []
        checks = (
            (features["cpu_max"] >= 80, 0.12, "Sustained high CPU activity"),
            (features["rss_growth_ratio"] >= 0.60, 0.22, "Rapid memory growth"),
            (features["rss_delta_mb"] >= 180, 0.10, "Large memory delta"),
            (features["child_max"] >= 8, 0.18, "Unusual child-process burst"),
            (features["connection_delta"] >= 5, 0.16, "Rapid network-connection growth"),
            (features["thread_delta"] >= 8, 0.08, "Rapid thread creation"),
            (features["write_delta_mb"] >= 60, 0.08, "High write activity"),
            (features["encoded_command_hint"] > 0, 0.28, "Encoded-command indicator"),
        )
        for matched, weight, reason in checks:
            if matched:
                score += weight
                reasons.append(reason)
        score = min(1.0, score)
        severity = severity_for(score, threshold)
        return DetectionResult(
            session_id=window.session_id,
            observed_at=window.window_end,
            pid=window.pid,
            process_started_at=window.started_at,
            process_name=window.process_name,
            model_version=self.version,
            score=score,
            severity=severity,
            label="suspicious" if severity in (Severity.MEDIUM, Severity.HIGH) else "normal",
            threshold=threshold,
            reasons=tuple(reasons[:4]),
            feature_values=window.values,
            missing_fields=window.missing_fields,
            source=source,
        )


class SklearnClassifier:
    def __init__(self, model_path: Path) -> None:
        from skops.io import get_untrusted_types, load

        metadata = _verified_metadata(model_path)
        unknown = set(get_untrusted_types(file=model_path))
        safe_internal_types = {"numpy.dtype"}
        unsafe = unknown - safe_internal_types
        if unsafe:
            raise ValueError(f"Model contains untrusted types: {', '.join(sorted(unsafe))}")
        self._model = load(model_path, trusted=sorted(unknown))
        if list(getattr(self._model, "classes_", [])) != [0, 1]:
            raise ValueError("Model must have binary classes [0, 1]")
        self._version = str(metadata.get("model_version", "sklearn-unknown"))

    @property
    def version(self) -> str:
        return self._version

    def _probability(self, values: list[float]) -> float:
        import numpy as np

        return float(self._model.predict_proba(np.asarray([values], dtype=float))[0, 1])

    def score(
        self,
        window: FeatureWindow,
        *,
        threshold: float = 0.85,
        source: ScanSource = ScanSource.LIVE,
    ) -> DetectionResult:
        if window.schema_version != "1":
            raise ValueError("Feature window schema is incompatible")
        values = [window.values[name] for name in FEATURE_NAMES]
        if not all(math.isfinite(value) for value in values):
            raise ValueError("Feature values must be finite")
        probability = self._probability(values)
        severity = severity_for(probability, threshold)
        reasons = _feature_reasons(window.values)
        return DetectionResult(
            session_id=window.session_id,
            observed_at=window.window_end,
            pid=window.pid,
            process_started_at=window.started_at,
            process_name=window.process_name,
            model_version=self.version,
            score=probability,
            severity=severity,
            label="suspicious" if severity in (Severity.MEDIUM, Severity.HIGH) else "normal",
            threshold=threshold,
            reasons=reasons,
            feature_values=window.values,
            missing_fields=window.missing_fields,
            source=source,
        )


def _verified_metadata(model_path: Path) -> dict[str, object]:
    metadata_path = model_path.with_suffix(".json")
    if not metadata_path.exists():
        raise ValueError("Model metadata is missing")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict) or metadata.get("feature_schema_version") != "1":
        raise ValueError("Model metadata schema is incompatible")
    if metadata.get("sha256") != hashlib.sha256(model_path.read_bytes()).hexdigest():
        raise ValueError("Model checksum does not match metadata")
    if tuple(metadata.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("Model feature schema is incompatible")
    return metadata


class PortableLogisticClassifier(SklearnClassifier):
    """The fitted scaler/logistic equation, with no training libraries in the hot path.

    Numeric parameters are exported from the checked skops artifact, not re-trained.
    Artifact and parameter hashes detect corruption, not a malicious replacement of both.
    """

    def __init__(self, model_path: Path) -> None:
        metadata = _verified_metadata(model_path)
        runtime = metadata.get("portable_runtime")
        if not isinstance(runtime, dict) or runtime.get("kind") != "standard-scaler-logistic-v1":
            raise ValueError("Portable model schema is incompatible")
        digest = hashlib.sha256(json.dumps(runtime, sort_keys=True, allow_nan=False).encode()).hexdigest()
        if digest != metadata.get("portable_runtime_sha256"):
            raise ValueError("Portable model checksum does not match metadata")
        if runtime.get("source_sha256") != metadata["sha256"] or runtime.get("classes") != [0, 1]:
            raise ValueError("Portable model source or classes are incompatible")

        def vector(name: str) -> list[float]:
            raw = runtime.get(name)
            if not isinstance(raw, list) or len(raw) != len(FEATURE_NAMES):
                raise ValueError(f"Portable model {name} shape is incompatible")
            if any(type(x) not in (int, float) or not math.isfinite(x) for x in raw):
                raise ValueError("Portable model parameters must be finite numbers")
            return [float(x) for x in raw]

        self._means = vector("means")
        self._scales = vector("scales")
        self._weights = vector("weights")
        if any(value <= 0 for value in self._scales):
            raise ValueError("Portable model scales must be positive")
        intercept = runtime.get("intercept")
        if not isinstance(intercept, (int, float)) or isinstance(intercept, bool) or not math.isfinite(intercept):
            raise ValueError("Portable model intercept must be finite")
        self._intercept = float(intercept)
        self._version = str(metadata["model_version"])

    def _probability(self, values: list[float]) -> float:
        linear = self._intercept + sum(
            ((value - mean) / scale) * weight
            for value, mean, scale, weight in zip(values, self._means, self._scales, self._weights, strict=True)
        )
        if linear >= 0:
            return 1.0 / (1.0 + math.exp(-linear))
        exponential = math.exp(linear)
        return exponential / (1.0 + exponential)


class CompositeClassifier:
    def __init__(self, model_path: Path | None = None) -> None:
        self.load_error: str | None = None
        self._classifier: ThreatClassifier = RuleBasedClassifier()
        if model_path:
            try:
                metadata = _verified_metadata(model_path)
                self._classifier = (
                    PortableLogisticClassifier(model_path)
                    if "portable_runtime" in metadata
                    else SklearnClassifier(model_path)
                )
            except Exception as exc:  # model-file boundary: corrupt or incompatible artifacts fall back safely
                self.load_error = str(exc)

    @property
    def version(self) -> str:
        return self._classifier.version

    @property
    def auto_block_allowed(self) -> bool:
        # All Phase 2 models are experimental: synthetic validation cannot authorize live auto-blocking.
        return False

    def score(
        self,
        window: FeatureWindow,
        *,
        threshold: float = 0.85,
        source: ScanSource = ScanSource.LIVE,
    ) -> DetectionResult:
        return self._classifier.score(window, threshold=threshold, source=source)


def _feature_reasons(features: dict[str, float]) -> tuple[str, ...]:
    ranked: list[tuple[float, str]] = [
        (features["rss_growth_ratio"] / 2, "Memory growth deviates from the process baseline"),
        (features["child_max"] / 16, "Elevated child-process activity"),
        (features["connection_delta"] / 20, "Network connections increased rapidly"),
        (features["cpu_max"] / 100, "High peak CPU activity"),
        (features["encoded_command_hint"], "Encoded-command indicator observed"),
    ]
    return tuple(text for value, text in sorted(ranked, reverse=True) if value >= 0.35)[:4]
