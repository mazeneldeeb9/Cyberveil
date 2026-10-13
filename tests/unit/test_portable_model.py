import hashlib
import json
import shutil
import subprocess
import sys

import numpy as np
import pytest

from cyberveil.detection.runtime import (
    FEATURE_NAMES,
    CompositeClassifier,
    PortableLogisticClassifier,
    SklearnClassifier,
)
from cyberveil.paths import bundled_model_path


def test_portable_equation_matches_verified_sklearn_pipeline():
    path = bundled_model_path()
    original = SklearnClassifier(path)
    portable = PortableLogisticClassifier(path)
    rng = np.random.default_rng(42)
    # Typical, extreme and boundary-probability feature vectors.
    vectors = rng.normal(size=(1000, len(FEATURE_NAMES))) * np.asarray(portable._scales) + portable._means
    vectors = np.vstack([vectors, np.zeros(len(FEATURE_NAMES)), np.full(len(FEATURE_NAMES), 1e9)])
    expected = original._model.predict_proba(vectors)[:, 1]
    actual = [portable._probability(row.tolist()) for row in vectors]
    np.testing.assert_allclose(actual, expected, rtol=1e-12, atol=1e-12)


@pytest.mark.parametrize("damage", ["hash", "shape", "scale", "source", "classes", "nonfinite"])
def test_corrupted_portable_parameters_fail_closed(tmp_path, damage):
    path = tmp_path / "model.skops"
    shutil.copyfile(bundled_model_path(), path)
    metadata = json.loads(bundled_model_path().with_suffix(".json").read_text())
    runtime = metadata["portable_runtime"]
    if damage == "hash":
        metadata["portable_runtime_sha256"] = "bad"
    elif damage == "shape":
        runtime["means"] = [0]
    elif damage == "scale":
        runtime["scales"][0] = 0
    elif damage == "source":
        runtime["source_sha256"] = "wrong-source"
    elif damage == "classes":
        runtime["classes"] = [1, 0]
    else:
        runtime["intercept"] = float("inf")
    if damage not in ("hash", "nonfinite"):
        metadata["portable_runtime_sha256"] = hashlib.sha256(json.dumps(runtime, sort_keys=True).encode()).hexdigest()
    path.with_suffix(".json").write_text(json.dumps(metadata))
    classifier = CompositeClassifier(path)
    assert classifier.load_error
    assert classifier.version == "rules-v1"
    assert not classifier.auto_block_allowed


def test_missing_model_is_reported(tmp_path):
    assert CompositeClassifier(tmp_path / "absent.skops").load_error


def test_bundled_runtime_does_not_import_training_libraries():
    result = subprocess.run([sys.executable, "-c", (
        "import sys; from cyberveil.detection import CompositeClassifier; "
        "from cyberveil.paths import bundled_model_path; "
        "c=CompositeClassifier(bundled_model_path()); assert not c.load_error; "
        "assert not {'sklearn','skops','pandas','numpy'}.intersection(sys.modules)"
    )], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
