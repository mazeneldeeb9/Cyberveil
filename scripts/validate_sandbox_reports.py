"""Score every preselected report, preserving misses and ground-truth provenance.

The selection manifest must be created before scoring. Report labels are read only
after model inference, from the separately downloaded WinMET author mapping.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from cyberveil.detection.api_model import ApiBehaviorClassifier, bundled_api_model_path
from cyberveil.domain import utc_now
from cyberveil.forensics.sandbox import SandboxAnalysisService
from cyberveil.storage import Database


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument(
        "--dataset", type=Path, required=True, help="Original feature-only CSV, for all-corpus overlap audit",
    )
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    model_hash = hashlib.sha256(bundled_api_model_path().read_bytes()).hexdigest()
    if model_hash != manifest["frozen_model_sha256"]:
        raise ValueError("Model changed after external selection was frozen")
    labels_bytes = args.labels.read_bytes()
    labels = json.loads(labels_bytes)
    dataset_bytes = args.dataset.read_bytes()
    if hashlib.sha256(dataset_bytes).hexdigest() != "1e39c43a014e9b4ee56766ad6bb367ffe8ec4316eb0be75eb182c3b2d15f6364":
        raise ValueError("Unexpected overlap-audit dataset")
    corpus_hashes = {row[0] for row in list(csv.reader(dataset_bytes.decode().splitlines()))[1:]}
    database = Database(args.database)
    try:
        classifier = ApiBehaviorClassifier()
        service = SandboxAnalysisService(database, classifier)
        results = []
        for name in manifest["reports"]:
            if Path(name).name != name or not name.endswith(".json"):
                raise ValueError("Invalid report name in selection manifest")
            try:
                result = service.analyze(args.report_directory / name)
                result["publisher_labels"] = labels.get(result["sample_sha256"], {})
                result["status"] = "completed"
                result["independent_of_development"] = not result["development_overlap"]
                result["independent_of_corpus_test"] = not result["dataset_holdout_member"]
                result["independent_of_entire_corpus"] = result["sample_sha256"] not in corpus_hashes
                result["publisher_label_available"] = any(
                    label not in ("(n/a)", "", None) for label in result["publisher_labels"].values()
                )
            except (ValueError, OSError, RuntimeError) as exc:
                result = {"status": "failed", "error": str(exc)}
            results.append({"report": name, **result})
        payload = {
            "evaluated_at": utc_now().isoformat(), "selection": manifest, "model_sha256": model_hash,
            "labels_sha256": hashlib.sha256(labels_bytes).hexdigest(), "results": results,
            "completed": sum(r["status"] == "completed" for r in results),
            "flagged": sum(r.get("verdict") == "suspicious" for r in results),
            "not_flagged": sum(r.get("verdict") == "not_flagged" for r in results),
            "failed": sum(r["status"] == "failed" for r in results),
            "publisher_label_available": sum(bool(r.get("publisher_label_available")) for r in results),
            "flagged_with_publisher_label": sum(
                r.get("verdict") == "suspicious" and bool(r.get("publisher_label_available")) for r in results
            ),
            "limitations": ["Published historical Windows executions; no new malware was executed here",
                            "Small malware-only external set cannot measure specificity or benign FPR",
                            "Publisher family labels are separate ground truth, never classifier inputs",
                            "Exact-hash/API-set separation does not establish unseen-family generalization"],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2) + "\n")
        print(json.dumps({k: payload[k] for k in ("completed", "flagged", "not_flagged", "failed")}, indent=2))
    finally:
        database.close()


if __name__ == "__main__":
    main()
