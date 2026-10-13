# Phase 2 completion record

Implemented on the local `phase2` branch, 2026-09-28. The published `phase1` branch is unchanged.

## Delivered

- Versioned rolling features with timestamp expiry, process/session isolation, 15-sample warm-up, two-second inference cadence, stale-buffer pruning, and immediate medium-to-high escalation through the alert cooldown.
- Reproducible seeded training data; logistic regression and histogram gradient boosting comparison; session-grouped cross-validation, untouched holdout sessions, documented promotion rule, model checksum/type/schema checks, and a bundled classifier.
- Scored alerts, English/Arabic severity and observed signals, preserved numeric evidence, missing-telemetry notes, notification history, and reports.
- Confirmed termination with PID/start-time/name checks, current-user ownership and protected-process/path/ancestry guards, timeout handling, and no automatic force-kill escalation. A bundled sleeping-child demo exercises the real process path without a payload.
- Atomic, idempotent action/disposition/counter/audit persistence. Empty report action lists cannot include actions from unrelated sessions.
- Offline Volatility 3 analysis for Windows, Linux, and macOS plugin sets, bounded per-plugin timeouts, partial-error handling, SQLite storage, and report visibility. Schema v1 databases migrate without losing Phase 1 history.
- Worker results are dispatched to UI-thread slots; closing during active work is deferred and scans stop safely.

## Acceptance evidence

- Final local checks: **42 tests passed**, Ruff passed, strict MyPy passed for 35 source files, and `git diff --check` passed.
- Automated coverage includes calculation/window timing, grouped training, holdout isolation, artifact rejection/fallback, deterministic replay, migration, audit idempotency, real harmless-child termination, PID reuse, permission errors, protected processes, stale names, cancellation/confirmation in the UI, RTL, and forensic timeout/invalid-output persistence.
- `scripts/verify_phase2.py` exercised the bundled model over 40 samples per scenario: benign browsing produced zero detections; suspicious burst and memory surge each produced three detections with high-severity events and persisted reports.
- Measured feature extraction + inference + persistence p95 for those replay batches: approximately 0.31 ms on the development Mac.
- The CLI sleeping-child demo terminated its own child successfully and saved the audit result.
- The UI demo verified cancel followed by confirmation, actual child exit, and exactly one blocked counter increment. A startup readiness handshake ensures macOS process identity is captured after Python finishes launching.
- Installed Volatility 3 version 2.28.2 was tested against an intentionally invalid image: it produced three plugin errors, a failed scan status, and saved diagnostics. Mocked valid plugin output verified successful finding persistence and partial-result handling.
- Arabic alert and settings screens and English report output were rendered and inspected at desktop and minimum supported window sizes. Arabic alert evidence and severity are translated.

## Demonstration

```bash
.venv/bin/cyberveil gui
.venv/bin/cyberveil replay --scenario suspicious-burst
.venv/bin/cyberveil demo-remediation --confirm
.venv/bin/python scripts/verify_phase2.py
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/mypy src/cyberveil
```

In the UI, **Run safe demo** generates scored replay alerts; containment there is simulated. **Settings → Try harmless process termination** launches a real sleeping child and asks for confirmation before stopping it. **Settings → Offline memory analysis** accepts a user-supplied image and target OS. History/Reports retain the result across restarts.

## Validation limits and Phase 3 boundary

No valid acquired memory image or matching symbol bundle was supplied, so successful extraction from a real memory image is not claimed. Offline symbol prerequisites follow the [Volatility CLI documentation](https://volatility3.readthedocs.io/en/latest/vol-cli.html). Windows/Linux execution, clean installer testing, comprehensive export/AI hardening, and total monitoring CPU/memory profiling remain Phase 3 work. Model quality is measured only on synthetic lab data; see [MODEL_CARD.md](docs/MODEL_CARD.md).
