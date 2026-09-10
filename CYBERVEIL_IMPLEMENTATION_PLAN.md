# CYBERVEIL Implementation Plan

## Delivery contract

Build a cross-platform academic MVP in three two-week phases. The application uses real local telemetry and safe deterministic replay, an explainable scikit-learn classifier, guarded remediation, bilingual reporting, optional offline Volatility analysis, and optional local Ollama explanations. It must never execute malware or represent lab results as production protection.

## Phase 1 - Foundation, telemetry, and UI shell

- Establish the Python/PySide6 project, typed domain contracts, SQLite migrations, structured logging, settings, and CLI.
- Implement capability-aware psutil sampling and deterministic synthetic replay.
- Build the branded application shell, dashboard, scan controls, notifications, history, and log viewer.
- Add complete English/Arabic copy, RTL behavior, keyboard navigation, degraded-permission states, and baseline tests.

**Acceptance:** A user can start and stop a live session, run a safe demo, browse persisted events after restart, switch languages, and understand unavailable telemetry.

## Phase 2 - Detection, alerts, remediation, and forensics

- Create versioned rolling features from one-second samples and run inference every two seconds over fifteen-second windows.
- Train and compare logistic regression and histogram gradient boosting with GroupKFold split by session; promote the model using the documented F1/latency rule.
- Integrate scores, severity, contributing signals, alert details, audit history, and guarded termination of eligible processes.
- Add user-supplied memory-image analysis through optional Volatility 3 integration.

**Acceptance:** Replays produce deterministic detections and reports; a bundled harmless demo process can be terminated; protected-process and PID-reuse guards prevent unsafe actions.

## Phase 3 - Reports, local AI, packaging, and hardening

- Complete summary/full reports, search/filter behavior, settings, notifications, bilingual PDF/JSON/CSV exports, and responsive desktop layouts.
- Add an optional localhost-only Ollama structured report explanation with deterministic fallback.
- Measure model quality and runtime overhead, finish accessibility/visual QA, package on each target OS, and document limitations and demonstrations.

**Acceptance:** Clean installs complete the English and Arabic demo flows on Windows, macOS, and Linux; optional integrations fail gracefully; tests and release checks pass.

## Architecture

- `domain.py`: immutable telemetry, feature, detection, remediation, report, settings, and capability models.
- `collectors/`: live psutil collector and safe synthetic replay.
- `detection/` and `training/`: feature windows, model runtime, training, evaluation, metadata, and trusted persistence.
- `storage/`: versioned SQLite repositories.
- `remediation/`: identity validation, protected-process policy, and guarded termination.
- `forensics/`: memory-image-only Volatility adapter.
- `reports/` and `integrations/`: exports and optional Ollama.
- `ui/`: PySide6 pages, view models, workers, localization, and visual resources.

## Quality gates

- Precision, recall, and macro F1 target: at least 0.80 on the labeled lab set.
- Held-out benign false-positive rate: at most 5%.
- Feature plus inference p95: below 100 ms; average monitoring CPU: below 5%; application memory: below 300 MB on reference hardware.
- If model targets fail, label the build experimental and keep auto-block disabled.
- Tests cover calculations, storage, model metadata, redaction, permissions, PID reuse, optional-service failures, UI navigation, RTL, accessibility, and deterministic end-to-end replay.
