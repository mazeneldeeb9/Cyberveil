"""Portable, data-only classifier for API sets recorded by a Windows sandbox.

This is independent of the synthetic psutil model. It never executes a sample,
uses file hashes as predictors, or reads a sandbox's verdict to make a prediction.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

API_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,127}\Z")
SCHEMA = "windows-api-presence-v1"


def normalize_api(value: str) -> str:
    if not API_PATTERN.fullmatch(value):
        raise ValueError("Invalid Windows API name")
    return value.lower()


def api_fingerprint(apis: set[str]) -> str:
    return hashlib.sha256("\n".join(sorted(apis)).encode()).hexdigest()


def bundled_api_model_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "models" / "windows-api-model.json"


class ApiBehaviorClassifier:
    def __init__(self, path: Path | None = None) -> None:
        path = path or bundled_api_model_path()
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("API model exceeds size limit")
        model = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(model, dict) or not isinstance(model.get("runtime"), dict):
            raise ValueError("API model must contain a runtime object")
        runtime = model.get("runtime", {})
        digest = hashlib.sha256(json.dumps(runtime, sort_keys=True, allow_nan=False).encode()).hexdigest()
        if digest != model.get("runtime_sha256") or model.get("schema") != SCHEMA:
            raise ValueError("API model checksum or schema mismatch")
        self.version = str(model["model_version"])
        self.threshold = float(model["threshold"])
        if not math.isfinite(self.threshold) or not 0 < self.threshold < 1:
            raise ValueError("Invalid API model threshold")
        vocabulary = runtime.get("vocabulary")
        if not isinstance(vocabulary, list) or not 1 <= len(vocabulary) <= 10000:
            raise ValueError("Invalid API vocabulary")
        if any(not isinstance(api, str) or normalize_api(api) != api for api in vocabulary):
            raise ValueError("Invalid API vocabulary entry")
        if len(set(vocabulary)) != len(vocabulary):
            raise ValueError("Duplicate API vocabulary entry")
        self.vocabulary = tuple(vocabulary)
        self._indices = {name: i for i, name in enumerate(vocabulary)}
        self._runtime: dict[str, Any] = runtime
        self._validate_runtime()
        self.training_hashes = frozenset(model.get("development_sample_sha256", []))
        self.training_fingerprints = frozenset(model.get("development_api_fingerprints", []))
        self.holdout_hashes = frozenset(model.get("holdout_sample_sha256", []))

    def _validate_runtime(self) -> None:
        n = len(self.vocabulary)
        if self._runtime.get("kind") == "binary-api-logistic-v1":
            weights = self._runtime.get("weights", [])
            numbers = [*weights, self._runtime.get("intercept")]
            if len(weights) != n or any(type(x) not in (int, float) or not math.isfinite(x) for x in numbers):
                raise ValueError("Invalid API logistic parameters")
        elif self._runtime.get("kind") == "binary-api-forest-v1":
            trees = self._runtime.get("trees", [])
            if not isinstance(trees, list) or not 1 <= len(trees) <= 512:
                raise ValueError("Invalid API forest")
            for tree in trees:
                size = len(tree["features"])
                if not 1 <= size <= 10000 or any(len(tree[k]) != size for k in ("left", "right", "probabilities")):
                    raise ValueError("Invalid API tree shape")
                for i, (feature, left, right, probability) in enumerate(zip(
                    tree["features"], tree["left"], tree["right"], tree["probabilities"], strict=True,
                )):
                    if type(feature) is not int or not -2 <= feature < n:
                        raise ValueError("Invalid API tree feature")
                    if (type(probability) not in (int, float) or not math.isfinite(probability)
                            or not 0 <= probability <= 1):
                        raise ValueError("Invalid API tree probability")
                    if feature < 0:
                        if left != -1 or right != -1:
                            raise ValueError("Invalid API leaf")
                    elif type(left) is not int or type(right) is not int or not (i < left < size and i < right < size):
                        raise ValueError("Invalid API tree edges")
        else:
            raise ValueError("Unknown API runtime kind")

    def predict(self, apis: set[str]) -> tuple[float, tuple[str, ...]]:
        normalized = {normalize_api(api) for api in apis}
        present = {self._indices[api] for api in normalized if api in self._indices}
        known = tuple(sorted(api for api in normalized if api in self._indices))
        if len(known) < 10:
            raise ValueError("Insufficient supported API evidence: at least 10 distinct known APIs are required")
        runtime = self._runtime
        if runtime["kind"] == "binary-api-logistic-v1":
            linear = float(runtime["intercept"]) + sum(runtime["weights"][i] for i in present)
            score = 1 / (1 + math.exp(-linear)) if linear >= 0 else math.exp(linear) / (1 + math.exp(linear))
        else:
            predictions = []
            for tree in runtime["trees"]:
                node = 0
                while tree["features"][node] >= 0:
                    node = tree["right"][node] if tree["features"][node] in present else tree["left"][node]
                predictions.append(tree["probabilities"][node])
            score = sum(predictions) / len(predictions)
        return float(score), known
