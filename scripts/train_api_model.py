"""Train/evaluate the real-trace API detector without executing malware.

Input is the pinned, feature-only MalBehavD-V1 CSV. Identical API sets and
identical sample hashes stay in one partition; conflicting groups are excluded.
The test partition is opened only after model/threshold selection on development.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from cyberveil.detection.api_model import SCHEMA, ApiBehaviorClassifier, api_fingerprint, normalize_api

DATA_SHA256 = "1e39c43a014e9b4ee56766ad6bb367ffe8ec4316eb0be75eb182c3b2d15f6364"
REVISION = "6aac5027635ac3d2832d323a873fccd7cdd89a5e"


def metrics(y: Any, scores: Any, threshold: float) -> dict[str, Any]:
    predicted = np.asarray(scores) >= threshold
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "samples": len(y), "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "macro_f1": float(f1_score(y, predicted, average="macro", zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)), "roc_auc": float(roc_auc_score(y, scores)),
    }


def train(dataset: Path, output: Path, evidence: Path) -> None:
    raw = dataset.read_bytes()
    if hashlib.sha256(raw).hexdigest() != DATA_SHA256:
        raise ValueError("Dataset differs from the reviewed upstream revision")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_hashes: dict[str, set[str]] = defaultdict(set)
    for row in list(csv.reader(raw.decode().splitlines()))[1:]:
        sha, label = row[:2]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha) or label not in ("0", "1"):
            raise ValueError("Malformed training identity or label")
        apis = {normalize_api(value.strip()) for value in row[2:] if value.strip()}
        fingerprint = api_fingerprint(apis)
        seen_hashes[sha].add(fingerprint)
        groups[fingerprint].append({"sha256": sha, "label": int(label), "apis": apis})
    # The upstream table repeats some hashes with differing traces. Exclude every
    # row for those ambiguous identities instead of leaking them between splits.
    ambiguous_hashes = {sha for sha, fingerprints in seen_hashes.items() if len(fingerprints) > 1}
    groups = defaultdict(list, {k: [r for r in rows if r["sha256"] not in ambiguous_hashes]
                                for k, rows in groups.items()})
    groups = defaultdict(list, {k: rows for k, rows in groups.items() if rows})
    conflicts = {k for k, rows in groups.items() if len({row["label"] for row in rows}) > 1}
    insufficient = {k for k, rows in groups.items() if len(rows[0]["apis"]) < 10}
    # One row per unique feature set avoids weighting near-identical repeated traces.
    usable = sorted(set(groups) - conflicts - insufficient)
    labels = [groups[k][0]["label"] for k in usable]
    development, test = train_test_split(usable, test_size=0.20, random_state=20261101, stratify=labels)
    fit, validation = train_test_split(
        development, test_size=0.25, random_state=20261102,
        stratify=[groups[k][0]["label"] for k in development],
    )
    vocabulary = sorted(set().union(*(groups[k][0]["apis"] for k in fit)))

    def matrix(keys: list[str]) -> tuple[Any, Any]:
        x = np.asarray([[int(api in groups[k][0]["apis"]) for api in vocabulary] for k in keys], dtype=np.float64)
        return x, np.asarray([groups[k][0]["label"] for k in keys])

    x_fit, y_fit = matrix(fit)
    x_val, y_val = matrix(validation)
    candidates = {
        "logistic": LogisticRegression(C=1, max_iter=2000, random_state=42),
        "random_forest": RandomForestClassifier(
            n_estimators=192, max_depth=16, min_samples_leaf=2, random_state=42, n_jobs=2,
        ),
        "random_forest_deep": RandomForestClassifier(
            n_estimators=192, max_depth=None, min_samples_leaf=1, random_state=42, n_jobs=2,
        ),
        "random_forest_wide": RandomForestClassifier(
            n_estimators=192, max_depth=16, min_samples_leaf=1, max_features=0.5, random_state=42, n_jobs=2,
        ),
        "random_forest_all": RandomForestClassifier(
            n_estimators=192, max_depth=16, min_samples_leaf=2, max_features=1.0, random_state=42, n_jobs=2,
        ),
    }
    selection = []
    for name, estimator in candidates.items():
        estimator.fit(x_fit, y_fit)
        probabilities = estimator.predict_proba(x_val)[:, 1]
        options = []
        # Search the entire useful operating range on validation only. The pilot
        # wrongly constrained this to >= .50, which is not a calibrated boundary
        # for a forest score. Never pick a threshold from a demonstration report.
        for threshold in np.arange(0.05, 0.951, 0.01):
            measured = metrics(y_val, probabilities, float(threshold))
            if measured["false_positive_rate"] <= 0.05:
                options.append((measured["macro_f1"], float(threshold), measured))
        if not options:
            raise ValueError(f"No validation threshold met the FPR constraint for {name}")
        _, threshold, measured = max(options, key=lambda item: (item[0], -item[1]))
        selection.append({"candidate": name, "threshold": threshold, "validation": measured})
    selected = max(selection, key=lambda result: result["validation"]["macro_f1"])
    estimator = candidates[selected["candidate"]]
    runtime: dict[str, Any] = {"vocabulary": vocabulary}
    if isinstance(estimator, LogisticRegression):
        runtime.update(kind="binary-api-logistic-v1", weights=estimator.coef_[0].tolist(),
                       intercept=float(estimator.intercept_[0]))
    else:
        trees = []
        for decision in estimator.estimators_:
            tree = decision.tree_
            if any(not np.isclose(t, 0.5) for f, t in zip(tree.feature, tree.threshold, strict=True) if f >= 0):
                raise ValueError("Portable forest requires binary-presence splits")
            counts = tree.value[:, 0, :]
            trees.append({"features": tree.feature.tolist(), "left": tree.children_left.tolist(),
                          "right": tree.children_right.tolist(),
                          "probabilities": (counts[:, 1] / counts.sum(axis=1)).tolist()})
        runtime.update(kind="binary-api-forest-v1", trees=trees)
    digest = hashlib.sha256(json.dumps(runtime, sort_keys=True, allow_nan=False).encode()).hexdigest()
    partitions = {"fit": fit, "validation": validation, "test": test}
    hashes = {split: sorted({row["sha256"] for k in keys for row in groups[k]}) for split, keys in partitions.items()}
    assert not (set(hashes["fit"]) & set(hashes["test"]) or set(development) & set(test)
                or set(hashes["fit"]) & set(hashes["validation"]) or set(hashes["validation"]) & set(hashes["test"]))
    model: dict[str, Any] = {
        "schema": SCHEMA,
        "model_version": f"windows-api-{selected['candidate']}-{digest[:12]}-t{round(selected['threshold'] * 100)}",
        "threshold": selected["threshold"], "experimental": True, "auto_block_allowed": False,
        "dataset_sha256": DATA_SHA256, "dataset_revision": REVISION,
        "dataset_url": f"https://github.com/mpasco/MalbehavD-V1/tree/{REVISION}",
        "runtime": runtime, "runtime_sha256": digest,
        "development_sample_sha256": sorted(set(hashes["fit"]) | set(hashes["validation"])),
        "development_api_fingerprints": sorted(development), "holdout_sample_sha256": hashes["test"],
        "selection": selection,
        "exclusions": {"ambiguous_sample_hashes": len(ambiguous_hashes),
                       "conflicting_feature_groups": len(conflicts), "insufficient_feature_groups": len(insufficient),
                       "original_rows": 2570, "unique_usable_feature_groups": len(usable)},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(model, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    portable = ApiBehaviorClassifier(output)
    x_test, y_test = matrix(test)
    scores = [portable.predict(groups[k][0]["apis"])[0] for k in test]
    np.testing.assert_allclose(scores, estimator.predict_proba(x_test)[:, 1], rtol=1e-12, atol=1e-12)
    timings = []
    for k in test[:100]:
        start = time.perf_counter()
        portable.predict(groups[k][0]["apis"])
        timings.append((time.perf_counter() - start) * 1000)
    test_metrics = metrics(y_test, scores, portable.threshold)
    quality = (
        test_metrics["macro_f1"] >= 0.8 and test_metrics["recall"] >= 0.8
        and test_metrics["precision"] >= 0.8 and test_metrics["false_positive_rate"] <= 0.05
    )
    result = {
        **{k: v for k, v in model.items() if k != "runtime"},
        "partition_fingerprints": partitions, "partition_sample_hashes": hashes,
        "selection_rule": "Max validation macro F1 subject to validation FPR <= 5%; no test-driven tuning or refit",
        "evaluation_history": (
            "Pilot with a threshold-search floor of .50 was inspected first. "
            "A baseline then expanded threshold selection and tested 20 external reports. "
            "The final pass compares three additional forest configurations on validation only. "
            "Repeated corpus-test metrics and the first external set are exploratory, not untouched tests. "
            "A new external selection must be frozen after the final model; prior evidence is retained."
        ),
        "holdout": test_metrics, "holdout_quality_gate_passed": bool(quality),
        "inference_p95_ms": float(np.percentile(timings, 95)),
        "holdout_predictions": [{"fingerprint": k, "label": int(label), "score": score}
                                for k, label, score in zip(test, y_test, scores, strict=True)],
        "limits": ["API-set grouping is not family-held-out or temporal evaluation",
                   "Corpus is historical and vendor-labelled; no new Windows specimen was executed by training",
                   "10-known-API minimum; import must abstain on insufficient evidence",
                   "Imported sandbox traces do not validate the separate live psutil detector"],
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"model": portable.version, "selection": selection, "holdout": test_metrics,
                      "gate_passed": bool(quality), "exclusions": model["exclusions"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("src/cyberveil/data/models/windows-api-model.json"))
    parser.add_argument("--evidence", type=Path, default=Path("docs/evidence/windows-api-evaluation.json"))
    args = parser.parse_args()
    train(args.dataset, args.output, args.evidence)
