from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupKFold, cross_val_predict, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from skops.io import dump

from cyberveil.collectors.replay import ReplayScenario, replay_samples
from cyberveil.detection.features import FeatureExtractor
from cyberveil.detection.runtime import FEATURE_NAMES
from cyberveil.training.portable import portable_metadata

SEED = 42
PROMOTION_RULE = "Promote gradient boosting only if CV macro F1 improves by >=0.01 and inference p95 is <100 ms."


@dataclass(frozen=True)
class CandidateMetrics:
    name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    threshold: float
    inference_p95_ms: float


@dataclass(frozen=True)
class TrainingResult:
    selected_model: str
    model_path: str
    model_version: str
    lab_only: bool
    candidates: tuple[CandidateMetrics, ...]
    held_out: CandidateMetrics
    quality_passed: bool


def build_demo_dataset(path: Path, sessions_per_scenario: int = 12) -> Path:
    if sessions_per_scenario < 4:
        raise ValueError("Use at least four sessions per scenario for grouped training and holdout evaluation")
    rows: list[dict[str, float | int | str]] = []
    anchor = datetime(2026, 1, 1, tzinfo=UTC)
    for scenario_index, scenario in enumerate(ReplayScenario):
        for session_number in range(sessions_per_scenario):
            session_id = f"synthetic-{scenario.value}-{session_number}"
            extractor = FeatureExtractor()
            for batch in replay_samples(
                scenario,
                session_id,
                steps=40,
                seed=SEED + scenario_index * 1000 + session_number,
                start_time=anchor,
            ):
                for sample in batch:
                    window = extractor.ingest(sample)
                    if window is None:
                        continue
                    # The first six seconds of every scenario are a benign baseline.
                    label = int(
                        scenario != ReplayScenario.BENIGN_BROWSE and sample.observed_at > anchor.replace(second=5)
                    )
                    row: dict[str, float | int | str] = {name: window.values[name] for name in FEATURE_NAMES}
                    row.update(session_id=session_id, scenario=scenario.value, label=label, lab_only=1)
                    rows.append(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def _metrics(
    name: str,
    y: NDArray[np.int64],
    probabilities: NDArray[np.float64],
    threshold: float,
    latency: float,
) -> CandidateMetrics:
    predicted = (probabilities >= threshold).astype(int)
    negatives = y == 0
    return CandidateMetrics(
        name=name,
        accuracy=float(accuracy_score(y, predicted)),
        precision=float(precision_score(y, predicted, zero_division=0)),
        recall=float(recall_score(y, predicted, zero_division=0)),
        f1=float(f1_score(y, predicted, average="macro", zero_division=0)),
        false_positive_rate=float(((predicted == 1) & negatives).sum() / max(1, negatives.sum())),
        threshold=threshold,
        inference_p95_ms=latency,
    )


def train_model(dataset_path: Path, output_path: Path) -> TrainingResult:
    frame = pd.read_csv(dataset_path)
    required = {*FEATURE_NAMES, "session_id", "label"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing columns: {', '.join(sorted(missing))}")
    if frame.empty or frame[list(required)].isna().any().any():
        raise ValueError("Training data cannot contain missing values")
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("Dataset labels must contain both binary classes 0 and 1")
    x = frame[list(FEATURE_NAMES)].to_numpy(dtype=np.float64)
    if not np.isfinite(x).all():
        raise ValueError("Features must be finite numbers")
    y = frame["label"].to_numpy(dtype=np.int64)
    groups = frame["session_id"].astype(str).to_numpy()
    sessions = frame.groupby("session_id")["label"].max()
    if sessions.size < 8 or sessions.value_counts().min() < 4:
        raise ValueError("Use at least four independent sessions per session class")
    # Set aside entire sessions before fitting, selecting candidates, or tuning thresholds.
    training_groups, test_groups = train_test_split(
        sessions.index.to_numpy(),
        test_size=0.25,
        stratify=sessions.to_numpy(),
        random_state=SEED,
    )
    train_mask = np.isin(groups, training_groups)
    test_mask = np.isin(groups, test_groups)
    x_train, y_train, group_train = x[train_mask], y[train_mask], groups[train_mask]
    splitter = GroupKFold(n_splits=min(5, len(training_groups)))
    folds = list(splitter.split(x_train, y_train, group_train))
    if any(len(set(y_train[train_indices])) != 2 for train_indices, _ in folds):
        raise ValueError("Each training fold must contain both classes; add more independent sessions")

    candidates: dict[str, Pipeline] = {
        "logistic-regression": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)),
            ]
        ),
        "hist-gradient-boosting": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    HistGradientBoostingClassifier(
                        max_iter=120,
                        learning_rate=0.08,
                        max_leaf_nodes=15,
                        l2_regularization=0.1,
                        random_state=SEED,
                    ),
                ),
            ]
        ),
    }
    metrics: list[CandidateMetrics] = []
    for name, pipeline in candidates.items():
        probs = cross_val_predict(pipeline, x_train, y_train, cv=folds, method="predict_proba")[:, 1]
        threshold = _select_threshold(y_train, probs)
        pipeline.fit(x_train, y_train)
        pipeline.predict_proba(x_train[:1])  # warm-up outside the measured loop
        timings: list[float] = []
        for row in x_train[: min(100, len(x_train))]:
            started = time.perf_counter()
            pipeline.predict_proba(row.reshape(1, -1))
            timings.append((time.perf_counter() - started) * 1000)
        metrics.append(_metrics(name, y_train, probs, threshold, float(np.percentile(timings, 95))))

    logistic, gradient = metrics
    selected = gradient if gradient.f1 >= logistic.f1 + 0.01 and gradient.inference_p95_ms < 100 else logistic
    selected_model = candidates[selected.name]
    held_out_probs = selected_model.predict_proba(x[test_mask])[:, 1]
    held_out = _metrics(selected.name, y[test_mask], held_out_probs, selected.threshold, selected.inference_p95_ms)
    runtime_high = _metrics(selected.name, y[test_mask], held_out_probs, 0.85, selected.inference_p95_ms)
    runtime_alert = _metrics(selected.name, y[test_mask], held_out_probs, 0.65, selected.inference_p95_ms)
    passed = (
        min(held_out.precision, held_out.recall, held_out.f1) >= 0.80
        and min(runtime_high.precision, runtime_high.recall, runtime_high.f1) >= 0.80
        and held_out.false_positive_rate <= 0.05
        and runtime_alert.false_positive_rate <= 0.05
        and held_out.inference_p95_ms < 100
    )
    # Keep held-out sessions out of the published model as well.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dump(selected_model, output_path)
    dataset_digest = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    version = f"sklearn-{selected.name}-{dataset_digest[:8]}"
    metadata = {
        "model_version": version,
        "selected_model": selected.name,
        "threshold": selected.threshold,
        "feature_names": list(FEATURE_NAMES),
        "feature_schema_version": "1",
        "dataset_sha256": dataset_digest,
        "sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
        "lab_only": True,
        "experimental": True,
        "quality_passed": passed,
        "promotion_rule": PROMOTION_RULE,
        "metric": "macro F1",
        "random_seed": SEED,
        "training_sessions": sorted(training_groups.tolist()),
        "held_out_sessions": sorted(test_groups.tolist()),
        "folds": [{"train": sorted(set(group_train[a])), "validation": sorted(set(group_train[b]))} for a, b in folds],
        "candidates": [asdict(item) for item in metrics],
        "held_out": asdict(held_out),
        "held_out_default_high_threshold": asdict(runtime_high),
        "held_out_medium_alert_threshold": asdict(runtime_alert),
        "confusion_matrix_labels": [0, 1],
        "held_out_confusion_matrix": confusion_matrix(
            y[test_mask],
            (held_out_probs >= selected.threshold).astype(int),
            labels=[0, 1],
        ).tolist(),
        "limitation": "Seeded synthetic scenarios only; this does not measure real-world malware detection.",
    }
    if selected.name == "logistic-regression":
        metadata.update(portable_metadata(selected_model, str(metadata["sha256"])))
    output_path.with_suffix(".json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    return TrainingResult(selected.name, str(output_path), version, True, tuple(metrics), held_out, passed)


def _select_threshold(y: NDArray[np.int64], probabilities: NDArray[np.float64]) -> float:
    best_threshold, best_f1 = 0.95, -1.0
    for threshold in np.arange(0.50, 0.951, 0.01):
        measured = _metrics("threshold", y, probabilities, float(round(threshold, 2)), 0)
        if measured.false_positive_rate <= 0.05 and measured.f1 > best_f1:
            best_threshold, best_f1 = measured.threshold, measured.f1
    return best_threshold
