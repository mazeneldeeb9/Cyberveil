import json

from cyberveil.detection.runtime import CompositeClassifier
from cyberveil.training import build_demo_dataset, train_model


def test_demo_dataset_trains_a_verified_model(tmp_path) -> None:
    dataset = build_demo_dataset(tmp_path / "dataset.csv", sessions_per_scenario=4)
    output = tmp_path / "model.skops"
    result = train_model(dataset, output)
    assert result.lab_only is True
    metadata = json.loads(output.with_suffix(".json").read_text())
    assert metadata["sha256"]
    assert set(metadata["training_sessions"]).isdisjoint(metadata["held_out_sessions"])
    assert metadata["metric"] == "macro F1"
    for fold in metadata["folds"]:
        assert set(fold["train"]).isdisjoint(fold["validation"])
        assert set(fold["train"] + fold["validation"]).isdisjoint(metadata["held_out_sessions"])
    classifier = CompositeClassifier(output)
    assert classifier.load_error is None
    assert classifier.version == result.model_version
    assert not classifier.auto_block_allowed
    metadata["sha256"] = "invalid"
    output.with_suffix(".json").write_text(json.dumps(metadata))
    rejected = CompositeClassifier(output)
    assert "checksum" in rejected.load_error
    assert rejected.version == "rules-v1"


def test_seeded_dataset_is_reproducible_and_sessions_vary(tmp_path):
    import pandas as pd

    first = build_demo_dataset(tmp_path / "first.csv", sessions_per_scenario=4)
    second = build_demo_dataset(tmp_path / "second.csv", sessions_per_scenario=4)
    assert first.read_bytes() == second.read_bytes()
    frame = pd.read_csv(first)
    means = frame.groupby("session_id")["cpu_mean"].mean()
    assert means.nunique() == len(means)


def test_invalid_training_labels_are_rejected(tmp_path):
    import pandas as pd
    import pytest

    dataset = build_demo_dataset(tmp_path / "bad.csv", sessions_per_scenario=4)
    frame = pd.read_csv(dataset)
    frame["label"] = 2
    frame.to_csv(dataset, index=False)
    with pytest.raises(ValueError, match="binary"):
        train_model(dataset, tmp_path / "model.skops")
