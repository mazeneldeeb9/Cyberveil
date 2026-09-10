# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

## Stack

Delegated and confirmed: Python 3.12, PySide6/Qt desktop UI, SQLite, psutil, pandas, NumPy, scikit-learn, optional Volatility 3, and optional local Ollama. The same product targets Windows 11, macOS 14+, and Ubuntu 24.04 while exposing platform capability differences honestly.

## Users

Students, evaluators, and technically capable personal-computer users who need to demonstrate and understand behavior-based detection of fileless-malware-like activity without executing live malware.

## Product Purpose

CYBERVEIL continuously samples process and system behavior, turns observations into rolling feature windows, scores them with an explainable machine-learning classifier, alerts the user to suspicious activity, supports guarded process termination, and records evidence in searchable local reports. Success is a complete, reproducible academic demonstration with measurable lab results and safe failure behavior.

## Positioning

The product demonstrates local, behavior-based detection of activity that may leave little disk evidence. It prioritizes observable behavior, transparent confidence and evidence, and safe replay instead of signature scanning or opaque security claims.

## Operating Context

Users run the native desktop application locally, start or stop monitoring, inspect live status, review detections and logs, export reports, and optionally import a memory image for offline Volatility analysis. Development and evaluation use benign telemetry plus deterministic synthetic/replayed threat scenarios. Each of the three implementation phases lasts two weeks.

## Capabilities and Constraints

- Cross-platform process, CPU, memory, relationship, I/O, and best-effort network telemetry through psutil.
- Scikit-learn tabular behavior classifier; the product must not call it a CNN.
- Guarded blocking defaults to confirmation and refuses protected/system processes.
- Complete English and Arabic UI with right-to-left layout support.
- SQLite storage, local report export, and optional local-only Ollama explanations.
- Volatility analyzes user-supplied memory images; CYBERVEIL does not acquire memory.
- No mobile app, enterprise network management, cloud service, live-malware execution, kernel driver, or production endpoint-security claim.

## Brand Commitments

Preserve the CYBERVEIL name, shield/circuit motif, dark navy environment, teal operating accent, restrained luminous depth, direct security language, and the core screen family shown in the supplied reference images. The application must feel like a focused operating console, not a marketing dashboard or game.

## Evidence on Hand

- `CYBERVEIL Project Brief EN AR.pdf`: bilingual product brief.
- Nine `WhatsApp Image 2026-09-02 ...` JPEG files: visual and screen-flow references.
- No dataset, source code, verified benchmark, customer claim, or production detection evidence was supplied; future work must not fabricate them.

## Product Principles

- Show what the detector observed and why it scored the activity.
- Fail safely when permissions, models, optional tools, or data are unavailable.
- Keep monitoring and analysis local by default.
- Separate measured lab results from real-world security claims.
- Make every consequential action visible, guarded, and auditable.

## Accessibility & Inclusion

All workflows must support keyboard operation, visible focus, screen-reader names, reduced motion, non-color status cues, high-DPI scaling, English left-to-right presentation, and Arabic right-to-left presentation.
