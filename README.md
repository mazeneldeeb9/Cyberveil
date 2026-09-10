# CYBERVEIL — Phase 1

CYBERVEIL is a safe academic desktop demonstrator for local process telemetry. Phase 1 delivers the cross-platform application foundation, capability-aware live sampling, deterministic replay, persisted session history and logs, and a bilingual English/Arabic interface.

It is not endpoint protection and does not execute malware. The safe demo generates telemetry records only.

## Run

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cyberveil gui
```

From the dashboard, choose **Start live monitoring** or **Run safe demo**. The application stores session summaries and audit events locally in SQLite.

The CLI can also preview the deterministic replay:

```bash
cyberveil replay --scenario suspicious-burst
```

## Phase 1 checks

```bash
pytest
ruff check .
mypy src/cyberveil
```

Telemetry collection is best-effort. CYBERVEIL continues with available fields when the operating system denies access to a process or capability.

See `CYBERVEIL_IMPLEMENTATION_PLAN.md` for the three-phase delivery plan.
