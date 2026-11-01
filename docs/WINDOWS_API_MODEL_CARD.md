# Windows API behavior model — 0.4.0

## Scope

This classifier answers a narrow question: does the set of Windows APIs in an imported execution trace resemble the malicious examples in its training corpus? It reads recorded behavior from CAPE/Cuckoo JSON; it does not execute files, inspect an executable's bytes, look up a hash reputation, or monitor APIs live. It does not establish that malware was fileless, that an infection is active, or that containment succeeded.

The existing psutil CPU/memory classifier remains separate and synthetic. Its original [model card](MODEL_CARD.md) and [Linux malware detection miss](VM_LAB_RESULT_20261013.md) remain applicable.

## Data and feature boundary

Training uses the author's feature-only [MalBehavD-V1 dataset](https://github.com/mpasco/MalbehavD-V1/tree/6aac5027635ac3d2832d323a873fccd7cdd89a5e), published with 1,285 malicious and 1,285 benign Windows execution traces. No malware executable was downloaded for this work. Attribution and the upstream MIT notice are in [API_DATA_ATTRIBUTION.md](API_DATA_ATTRIBUTION.md).

- Pinned revision: `6aac5027635ac3d2832d323a873fccd7cdd89a5e`.
- CSV SHA-256: `1e39c43a014e9b4ee56766ad6bb367ffe8ec4316eb0be75eb182c3b2d15f6364`.
- Predictor: binary presence of lowercased API names, with vocabulary fitted on the fitting partition only. Order, repetition, call arguments and unknown APIs do not change predictor values.
- Non-predictors: sample/report hash, filename, process name, PID, malware family, source label, sandbox score and sandbox signatures. Tests alter those fields and verify unchanged predictions.
- Import requires at least 10 distinct supported APIs; insufficient evidence fails the analysis rather than reporting a clean result. Unknown API names and coverage are recorded.

Six sample hashes had differing feature sets; all their rows were excluded to avoid identity leakage. One feature group had conflicting labels and 61 groups had fewer than 10 distinct APIs. Duplicate feature sets were collapsed, leaving 1,370 usable groups. This changes the original class balance: many malicious rows share an API set. The exclusion counts are group counts and must not be added as if they were row counts.

## Splitting, selection and evaluation history

The 1,370 unique feature groups were split 60% fitting / 20% validation / 20% corpus test, using seeds 20261101 and 20261102. The fitting set has 822 groups; validation and corpus test have 274 each. Identical sample hashes and identical API sets do not cross partitions. An additional audit found zero identical projected predictor vectors across those partitions.

Five candidates were compared on validation: logistic regression and four random-forest configurations. The decision threshold was selected by highest validation macro F1 subject to validation benign FPR at most 5%. Parameters and vocabulary are fitted on the fitting set only; the selected model was not refitted on validation or test. It is a 192-tree forest, maximum depth 16, minimum leaf size 2. Its selected decision threshold is 0.47. The live-monitoring Settings threshold does not control this separate classifier.

Evaluation was iterative and must be disclosed. A pilot restricted threshold search to 0.50–0.95 and had low recall. A second pass expanded the validation search to 0.05–0.95. After inspecting those results, three more forest configurations were compared on validation; the second-pass model remained selected. The corpus test was observed during this process, so its final numbers are **exploratory repeated-test results**, not an untouched confirmatory holdout. The pilot and intermediate evidence are preserved.

## Measured corpus result

The final corpus-test partition contains 211 benign and 63 malicious unique API sets:

| Measurement | Result |
| --- | ---: |
| True positives / false negatives | 48 / 15 |
| True negatives / false positives | 209 / 2 |
| Malicious precision | 96.0% |
| Malicious recall | 76.19% |
| Macro F1 | 0.90524 |
| Benign false-positive rate | 0.9479% |
| ROC AUC | 0.93530 |

The recall target of at least 80% was not met. The overall quality gate is **failed**. A score is not a calibrated probability that a file is malware, and these estimates are not production guarantees. Full predictions, partition membership, candidate results and inference timings are in [windows-api-evaluation.json](evidence/windows-api-evaluation.json).

## External recorded executions

Original JSON execution reports were acquired from the authors' [WinMET dataset, pinned version 3](https://zenodo.org/records/16414116). The API model cannot read WinMET's CAPE/AVClass verdict fields. Its predictions were made before joining the separately acquired publisher label mapping.

Five reports informed the initial pilot investigation; another 20 were assessed with the baseline model. A final selection of the next 20 reports, each at most 32 MiB, was frozen before scoring, including the final model file's SHA-256. No parameters or thresholds were adapted after opening this final set.

The final selection produced 7 flagged and 13 unflagged reports, with no import failures. Nineteen have a publisher CAPE or AVClass family label: 7 were flagged and 12 were missed. One unflagged report has no consensus family label and is inconclusive as ground truth. All 20 target hashes are absent from the entire original training corpus, and no exact development API-set overlap was found. This does not prove family independence.

This is a small, lexicographically selected, size-filtered external set. It is not random, balanced or representative. It contains no verified benign execution reports and therefore cannot measure external specificity/FPR. The low external detection rate demonstrates substantial distribution shift between the training corpus and these CAPE traces. See [every external result](evidence/windows-api-external-evaluation.json), including misses; the earlier [baseline external results](evidence/windows-api-baseline-external.json) remain available.

## Runtime and evidence handling

Model: `windows-api-random_forest-393cdbed9bde-t47`. The bundled artifact is data-only JSON with a verified runtime checksum, bounded vocabulary/tree dimensions, finite probabilities and forward-only tree edges. Tests reject corruption and cyclic trees. Portable predictions matched scikit-learn to `1e-12` tolerance on every corpus-test case. The checksum detects corruption; it does not authenticate an attacker replacing both model and checksum.

The importer bounds input size to 128 MiB, process count to 10,000 and recorded call count to 2,000,000. It never follows paths or opens external call files named inside a report. Missing API evidence, malformed schemas and insufficient supported APIs fail the stored scan. Report timestamps are retained when supplied; missing original execution times are explicitly `unknown`. Import time is distinct from execution time.

Classification applies to the whole recorded execution. A stored detection uses PID 0 as a non-actionable sentinel, with the historical PIDs recorded separately. UI and remediation service both refuse local termination from sandbox evidence. PDF, JSON and CSV preserve source/model/threshold and evidence; privacy redaction hides free-text provenance by default. Review a deliberately unredacted evidence export before sharing it.

## Reproduction

Download the pinned feature-only CSV from the upstream repository; verify its SHA-256 above. From the source checkout:

```bash
.venv/bin/python scripts/train_api_model.py /path/to/MalBehavD-V1-dataset.csv
.venv/bin/cyberveil doctor
.venv/bin/cyberveil analyze-sandbox /path/to/original-report.json --output result.json
```

Use the selection manifest embedded in the external evidence JSON, the original WinMET reports and its `reports_consensus_label.json` to reproduce external scoring:

```bash
.venv/bin/python scripts/validate_sandbox_reports.py selection.json \
  --labels reports_consensus_label.json \
  --dataset MalBehavD-V1-dataset.csv \
  --report-directory original-reports \
  --database tmp/reproduction.db \
  --output tmp/reproduction-results.json
```

The manifest's model-file checksum must match. Training timings can differ by machine; predictions should not. Native Windows build/smoke validation is a separate packaging check and is not a new malware execution experiment.
