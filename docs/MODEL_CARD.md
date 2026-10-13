# CYBERVEIL model card

## Scope and provenance

The bundled model is an academic demonstration trained exclusively on seeded synthetic process telemetry. No real-malware or production-incident corpus was used for training or the reported quality metrics. A separately requested single-specimen VM experiment does not change that provenance or validate production endpoint protection.

`data/demo-dataset.csv` contains 936 feature rows from 36 generated sessions: 12 benign browsing sessions, 12 suspicious-burst sessions, and 12 memory-surge sessions. Session-specific seeds vary CPU and memory scale. All scenarios share a small authored generator, so holding out sessions tests that generator's variations, not unfamiliar attack families or real-world workloads.

Generation uses seed 42 and a fixed UTC anchor. Schema version 1 has 20 numeric features, extracted from a rolling 15-sample window limited to the last 15 seconds. The live collector targets one-second intervals; inference runs at most once every two seconds per process identity. Missing network, file, or I/O fields are recorded alongside detection evidence; numeric features use zero for unavailable counters. This simplification is a model limitation.

## Evaluation and selection

Nine whole sessions (25%) are reserved before model selection. The remaining 27 sessions use five-fold GroupKFold, with preprocessing fitted inside each fold. Threshold tuning uses out-of-fold probabilities on those development sessions only. Both fold membership and the untouched holdout session IDs are recorded in the model JSON.

Logistic regression is the default candidate. Histogram gradient boosting is promoted only when its development macro F1 improves by at least 0.01 and its measured single-row inference p95 is below 100 ms. The selected estimator is fitted on development sessions only; the published model is not refitted on the holdout.

Measured on the development Mac on 2026-09-28:

| Candidate | Development macro F1 | Development FPR | Inference p95 |
| --- | ---: | ---: | ---: |
| Logistic regression | 1.000 | 0.000 | 0.166 ms |
| Histogram gradient boosting | 0.957 | 0.111 | 19.63 ms |

Logistic regression was selected. On the nine reserved synthetic sessions, precision, recall, and macro F1 were 1.000; benign false-positive rate was 0.000. The tuned binary evaluation threshold is 0.50. Runtime medium alerts begin at 0.65 and the default high-risk threshold is 0.85; holdout metrics for both runtime thresholds are also included in the JSON artifact. User threshold changes are not a new validation result.

The measurements above are lab results on a deliberately small, easy dataset. They do not establish accuracy against real malware or ordinary workloads outside the generator. Phase 3 measured native macOS monitoring overhead; see [PHASE3_COMPLETION.md](../PHASE3_COMPLETION.md). Cross-platform overhead remains unverified.

## Runtime and safety

The artifact is `src/cyberveil/data/models/behavior-model.skops`; its adjacent JSON contains the dataset digest, artifact checksum, schema, split membership, selection rule, and measured metrics. Loading checks the checksum, feature order/schema, binary classes, and skops type allowlist. This detects incompatibility/corruption, not authenticity of an attacker-replaced artifact and sidecar.

Phase 3 exports the fitted StandardScaler and logistic coefficients into the same metadata for lightweight inference. It does not retrain the model or change its version or thresholds. The portable loader checks both hashes, source binding, feature shape, binary classes, and finite parameters; corrupt data falls back to rules with a visible load error. Probability equivalence to the verified original pipeline is tested on 1,002 seeded typical/extreme vectors with a tolerance of `1e-12`. All runtime features are finite; missing telemetry uses the existing zero-value convention, not a new imputation policy.

The model remains marked `lab_only` and `experimental` even when synthetic quality gates pass. Live automatic termination remains disabled. Observed signals are human-readable threshold descriptions, not causal feature attribution or proof of malware. Detections preserve their numeric window values and missing-field notes for review.

## Reproduce

```bash
.venv/bin/cyberveil build-demo-dataset --output data/demo-dataset.csv
.venv/bin/cyberveil train data/demo-dataset.csv
.venv/bin/python scripts/verify_phase2.py
```

Dataset content and splits are deterministic; runtime timings depend on the machine and current load.

The split strategy follows scikit-learn's [grouped cross-validation guidance](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data).
