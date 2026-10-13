# CYBERVEIL Phase 3 handoff

Version 0.3.0 implements the Phase 3 application features locally. The macOS bundle passes its functional smoke checks, but the complete cross-platform release acceptance is not signed off. This document records what was implemented, what was measured on 2026-10-05, and which gates remain open.

## Implemented features

- Summary/full report views and complete English/Arabic PDF, JSON, and CSV exports, including action audits and available forensic findings. Arabic PDF shaping and right alignment were rendered and inspected; multi-page output was checked.
- Debounced text search, source/severity filters, and bounded result paging in history, notifications, and reports.
- Default export/local-AI redaction, atomic export writes, CSV formula neutralization, and escaped report/explanation text. Local audit records remain unchanged.
- Explicit retention confirmation, validation messages, accessible form names, keyboard table activation, reduced motion, and scrollable layouts at 1024×700 and 1440×900.
- Optional bounded structured Ollama explanations over localhost only, with cloud/redirect/proxy rejection and an honest deterministic fallback for failed or disabled service.
- Resilient handling of known macOS `proc_pidinfo` read failures without hiding unrelated programming errors. Capability limits remain visible and logged.
- A lightweight numeric runtime for the existing trained logistic model, a read-only headless monitoring command, model diagnostics, native packaging, a separately named harmless helper, and reproducible verification/recording scripts.

The UI hardening preserved the supplied navy/teal design while addressing small-window scrolling, Arabic reports, safe text rendering, accessibility, and error states. The documentation distinguishes measured evidence from unverified claims.

## Verification evidence

| Check | Observed result |
| --- | --- |
| Automated suite | 96 tests passed, including model parity, corruption guards, export privacy, Ollama failure paths, filters, retention, CLI monitoring, and UI lifecycle checks |
| Ruff and mypy | Passed; 38 application modules type-checked |
| Safe replay | 40 samples per scenario; benign replay 0 detections, suspicious burst 3, memory surge 3 |
| Feature, inference and storage p95 | 0.094 ms on the short seeded replay check; not a real-malware accuracy measure |
| Bilingual report output | English/Arabic PDF, JSON and CSV generated; two-page incident PDFs and six-page pagination fixture inspected |
| Native macOS bundle | Model load, safe replay, six bilingual exports, confirmed harmless-child termination, and fresh-data GUI smoke checks passed |
| Linux guest | Headless wheel/runtime installed in a fresh Ubuntu 24.04 x86_64 VM; this is not native Linux GUI installer certification |

The source/wheel build and macOS `.app` are in `dist/`. Reports and screenshots are in `tmp/phase3-final-checks/`. At the original 5 October handoff, the work remained on the existing local branch and no Phase 3 push or remote CI run had occurred.

## Measured runtime limits

The reference measurement ran the native development GUI plus live worker for approximately 30 seconds on macOS 26.5 ARM64, with automatic remediation disabled. The optimized run collected 17,497 process samples and performed no process actions. Average CPU was **33.78% of one logical core**, and peak RSS was **246.20 MB**. The preceding measurement used roughly 449 MB. The memory target of less than 300 MB now passes; the CPU target of less than 5% does not.

Files `tmp/phase3-runtime.json`, `tmp/phase3-runtime-ui-optimized.json`, and `tmp/phase3-runtime-portable.json` preserve the measurements. CPU is not silently divided by the host's core count to declare a pass. These short runs are not a prolonged soak test or a cross-platform benchmark.

## External VM experiment

The user requested a real specimen test separately from the safe application demos. Its VM, encrypted research archives, and disposable execution overlay were isolated in `/Volumes/External/CYBERVEIL-Lab-20261005/`, not in the app or source release. The guest had no network device, host filesystem shares, clipboard, or guest-agent channel during execution. A separate lab harness verified those conditions and used an unprivileged sample account with resource limits. No automatic app remediation was enabled. Only the clean base image, provisioning seed, and text/JSON evidence remain in that SSD folder after cleanup.

The completed [VM result](docs/VM_LAB_RESULT.md) records 7,589 telemetry samples, 99 specimen-linked records across its launcher and descendant, and **zero detections**. The real specimen was executed, but CYBERVEIL missed it under these conditions. One historical disk-backed specimen in an offline guest cannot establish fileless-malware accuracy, production safety, or a general detection rate. An initial ARM-only Mirai archive was inspected but not executed. The disposable working disks were removed after shutdown and evidence export.

## Demo video

`/Users/mazeneldeeb/Desktop/CYBERVEIL_Full_Demo.mp4` is a 5 minute 19 second H.264 recording at 1600×1000, with Arabic captions and chapter markers, without narration. It joins two actual app/lab recording segments: monitoring, replay, filters, bilingual settings, harmless-child containment, reports, local-template fallback, exports, and the real offline VM result. It does not show a successful real-malware detection.

The first recorder segment stopped at an export-filename assertion: Qt retained its suggested basenames while using the requested destination folder. All three exports were present and subsequently verified. The final segment continues from the same persisted demo data, verifies those files, and records the VM experiment live. Raw segments and evidence are retained under `tmp/phase3-video-9g5nezud/` and `tmp/phase3-video-final/`; the unrelated desktop was not captured.

## Remaining release gates

- Reduce and remeasure CPU overhead without reducing the promised monitoring coverage; run longer-duration soak tests.
- Build and test clean native Windows and Linux GUI installations in both languages. The CI matrix is defined locally but has not run remotely.
- Verify Volatility against a real compatible memory image and required offline symbols. No acquisition capability is claimed.
- Exercise a real installed local Ollama model. Structured success/failure paths are tested with mocks; disabled-service fallback is exercised live.
- Complete signing/notarization and trusted distribution for client delivery. No production-security claim is appropriate.

## Reproduction

Use Python 3.13 with `constraints-release.txt` for the tested native build environment. Follow the build/check commands in README. Normal macOS process visibility is required for the real-child tests; sandbox-denied telemetry is a capability limit, not a reason to weaken protection checks. The application and recorder do not download or execute malware.

## 13 October GitHub handoff checks

Before preparing the GitHub publication, the local suite again passed all 96 tests, Ruff, mypy across 38 source files, and the existing native macOS package smoke checks. The macOS package is ARM64 and remains unsigned by a Developer ID and unnotarized. It is an academic prerelease.

The [repeat malware experiment](docs/VM_LAB_RESULT_20261013.md) completed a 30-second baseline and 120-second specimen observation, collecting 16,380 process records and 239 specimen-linked records. It produced zero detections and zero application actions. Its evidence accompanies the source handoff; the external lab disks and research archive are not application release assets.

The `phase3` branch contains the Phase 2 dependencies and Phase 3 application work on top of the original Phase 1 commit. The native CI workflow defines checks and build artifacts for macOS, Windows, and Linux; each run's actual result is available in GitHub Actions and must be distinguished from these local verification results.
