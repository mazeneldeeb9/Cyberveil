"""Export a fitted logistic pipeline's equation; no fitting or deserialization here."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def portable_metadata(model: Pipeline, source_sha256: str) -> dict[str, Any]:
    if list(model.named_steps) != ["imputer", "scaler", "classifier"]:
        raise ValueError("Only the approved logistic pipeline can be exported")
    imputer, scaler, classifier = (model.named_steps[key] for key in ("imputer", "scaler", "classifier"))
    if not (
        type(imputer) is SimpleImputer and not imputer.add_indicator
        and type(scaler) is StandardScaler and scaler.with_mean and scaler.with_std
        and type(classifier) is LogisticRegression and list(classifier.classes_) == [0, 1]
    ):
        raise ValueError("Unsupported portable pipeline configuration")
    runtime = {
        "kind": "standard-scaler-logistic-v1",
        "source_sha256": source_sha256,
        "classes": [0, 1],
        "means": scaler.mean_.tolist(),
        "scales": scaler.scale_.tolist(),
        "weights": classifier.coef_[0].tolist(),
        "intercept": float(classifier.intercept_[0]),
    }
    digest = hashlib.sha256(json.dumps(runtime, sort_keys=True, allow_nan=False).encode()).hexdigest()
    return {"portable_runtime": runtime, "portable_runtime_sha256": digest}
