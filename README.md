# CYBERVEIL Phase 3

CYBERVEIL is a safe academic desktop demonstrator for behavior-based detection of fileless-malware-like activity. It combines local process telemetry, deterministic replay scenarios, an explainable scikit-learn classifier, guarded remediation, bilingual reports, optional memory-image analysis, and an optional local Ollama explainer.

The software is not a replacement for production endpoint protection. It never ships or executes malware, and its bundled demonstrations use generated telemetry and a harmless child process.

## Quick start

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cyberveil gui
```

On Windows activate the environment with `.venv\Scripts\activate`.

Run a deterministic demonstration from the UI using **Run safe demo**, or from the terminal:

```bash
cyberveil replay --scenario suspicious-burst
```

Phase 2 includes a bundled experimental model, 15-sample rolling windows at a one-second sampling target, inference every two seconds, scored alerts with observed signals, confirmed process termination, and persisted offline forensic results. Model files and feature schemas are verified before loading; unavailable or invalid models fall back to transparent rules.

To demonstrate actual process termination, open **Settings → Try harmless process termination**. The child only sleeps; its displayed score is explicitly a demonstration value. Cancel preserves it, and confirmed termination passes through the same identity and protected-process checks as a live action. Closing the demo cleans up the child.

The equivalent CLI demo terminates only the child it launches:

```bash
cyberveil demo-remediation --confirm
```

Rebuild the seeded synthetic lab data and bundled classifier:

```bash
cyberveil build-demo-dataset --output data/demo-dataset.csv
cyberveil train data/demo-dataset.csv
python scripts/verify_phase2.py
```

Phase 3 adds summary/full reports, search and filters, English/Arabic PDF/JSON/CSV exports, export redaction, confirmed retention cleanup, structured local explanations with a deterministic fallback, resilient macOS collection, and native packaging. See [PHASE3_COMPLETION.md](PHASE3_COMPLETION.md) for measured results and outstanding release gates. Earlier detection evidence remains in [PHASE2_COMPLETION.md](PHASE2_COMPLETION.md); model limitations are in [docs/MODEL_CARD.md](docs/MODEL_CARD.md).

Read-only headless monitoring is available for servers and isolated guest environments. It never terminates processes:

```bash
cyberveil doctor
cyberveil monitor --seconds 60 --output monitoring-result.json
cyberveil export-report SESSION_ID --format pdf --language ar --output report.pdf
```

The [13 October real-malware VM test](docs/VM_LAB_RESULT_20261013.md) collected specimen-linked telemetry but produced zero alerts. The bundled model missed that sample under the recorded test conditions.

The bundled logistic model uses a verified numeric export of the fitted equation, avoiding training-library imports during monitoring. Tests compare its probabilities with the original pipeline. Training and non-portable model loading still use scikit-learn/skops.

## Reports and local explanations

History, notifications, and reports have text search and structured filters. Report details offer a summary or complete numeric evidence. Exports include scan status, detections, action audit entries, and available forensic findings. Interrupted or failed scans are not presented as clean results.

Privacy redaction defaults on for exports and local explanation requests. It replaces process names and free-text action/forensic details; it does not anonymize timestamps, PIDs, scores, session IDs, or the local SQLite audit database. Review an export before sharing it.

Ollama is optional and disabled by default. Enable a locally installed model under Settings to request an explanation. CYBERVEIL connects only to `127.0.0.1:11434`, ignores proxy environment settings, refuses redirects/cloud models, and validates bounded structured responses. A missing service, invalid response, or timeout produces a clearly labelled local template. Explanations never control detection or remediation.

Retention cleanup requires explicit confirmation and preserves active sessions. Saving a retention period alone does not delete history.

## Build and verify

```bash
python -m pip install -c constraints-release.txt '.[dev]'
python scripts/verify_phase3.py
python scripts/profile_runtime.py --seconds 30
python -m build --no-isolation
python -m PyInstaller --noconfirm packaging/cyberveil.spec
python scripts/check_package.py
```

Build on the target OS. The local macOS artifact is `dist/CYBERVEIL.app`; Windows/Linux produce a portable `dist/CYBERVEIL/` directory that must be kept intact. The macOS build has no Developer ID notarization; Windows signing and installer distribution are not validated. Do not bypass OS security policy to distribute it as a trusted production product.

The CI workflow defines native Windows, Linux, and macOS checks, but its presence is not evidence that those remote jobs ran. The source distribution includes test, packaging, and verification scripts. Volatility remains an optional separately installed tool.

To record an actual app-window walkthrough with Arabic captions and fresh data, install FFmpeg and run:

```bash
python scripts/record_demo.py /path/to/new-demo.mp4
```

The recorder excludes the rest of the desktop and refuses to overwrite an existing video. Its optional VM-log view is read-only; it does not provision a VM, acquire specimens, or launch malware. An external research experiment is separate from the shipped application's safe demos.

## Development

```bash
pytest
ruff check .
mypy src/cyberveil
```

Optional offline memory-image support:

```bash
python -m pip install -e '.[forensics]'
cyberveil analyze-memory /path/to/acquired-memory-image --os windows
```

Volatility analyzes an existing image; CYBERVEIL does not acquire RAM. Analysis runs with `--offline`, so the appropriate symbols must already be installed in Volatility's symbol cache. Completed plugin results and errors appear in History and Reports. A partial or failed analysis is never presented as a clean result.

## Safety and privacy

- Telemetry and reports remain local.
- Full command-line arguments and environment variables are not stored.
- Automatic live blocking is disabled for the experimental bundled model; explicit confirmation is required.
- Protected/system processes and CYBERVEIL itself cannot be terminated.
- Ollama is optional, localhost-only, and never affects detection decisions.

See [PRODUCT.md](PRODUCT.md) and [CYBERVEIL_IMPLEMENTATION_PLAN.md](CYBERVEIL_IMPLEMENTATION_PLAN.md) for the confirmed product contract and delivery plan.
