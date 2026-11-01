# Real execution-report detection — 1 November 2026

CYBERVEIL 0.4.0 now classifies actual recorded Windows API behavior through a separate trained model. This implements the user-approved sandbox-report workflow. **The model remains experimental: it missed most reports in the external set, so the project cannot be declared reliable malware protection or fully quality-gated.**

## What changed

- A random forest trained on published malicious/benign API traces; the old live CPU/memory model was not relabelled as a real-data detector.
- Dashboard **Analyze sandbox report / تحليل تقرير بيئة معزولة**, asynchronous import, clear loading/error states, and a new source in History/Reports.
- CAPE/Cuckoo inline API extraction, score/model/threshold, sample and report SHA-256, coverage, process evidence and development-overlap checks.
- Recorded evidence cannot trigger local process blocking. No malware binary was acquired or executed in this work.
- English/Arabic PDF, JSON and CSV evidence exports, plus a video captured from the actual Qt application.

## Results that must be disclosed

| Evaluation | Result |
| --- | --- |
| Repeated corpus test | 48/63 malicious API sets flagged; 15 missed |
| Benign corpus test | 209/211 not flagged; 2 false positives |
| Fresh external WinMET selection | 7/20 flagged; 13 not flagged; no import failures |
| External label availability | 19 have a publisher family label: 7 flagged, 12 missed; 1 other report has no consensus family label |
| Quality gate | Failed: corpus recall is below 80%, and external generalization is weak |
| New local specimen execution | None; these are published historical Windows executions |
| Containment actions | None |

The model was frozen before scoring the final 20 reports. The selection rule, exact hashes, all predictions and publisher labels are in [external evidence](evidence/windows-api-external-evaluation.json). Corpus-test numbers were observed during model development and must be described as exploratory. See [the model card](WINDOWS_API_MODEL_CARD.md) for the complete method, exclusions and failed gates.

## Demonstration case and independent provenance

The recording uses the first flagged case in the final external selection, chosen afterwards **to illustrate an observed detection**, not to estimate accuracy:

| Item | Value |
| --- | --- |
| Publisher | [WinMET v3, Universidad de Zaragoza](https://zenodo.org/records/16414116) |
| Publisher family labels | AVClass: Berbew; CAPE: Padodor |
| Sample SHA-256 | `0030eba0afa77ea8bcc69d88fef59b1669504139780afcb86ec44ec21341568a` |
| Original JSON SHA-256 | `f27800601d11822dbcafa0bdb3c44617d9c20a2bc5909b4d1f7ddcbe8031eb76` |
| Recorded format | PE32 executable, Intel 80386, Windows GUI |
| Recorded processes / calls | 2 / 242 |
| Distinct / supported APIs | 34 / 20 |
| Model score / decision threshold | 0.5927186482 / 0.47 |
| Verdict | Flagged as suspicious |
| Training-corpus target overlap | None |

The original report does not include an `info.started`/`info.ended` timestamp. Those execution dates remain unknown; the import date must not be presented as the detonation date. Family labels are independent publisher evidence; the binary classifier does not itself identify Berbew or Padodor.

The same video imports an actual missed report, sample `00325bb93c8e3cbafecf9f1810abb3a1f5976c3267dadd3fd094b20bf42eaf33`, original JSON SHA-256 `d25c73528d7fcc8df0584ba28904c17721d278008fdedcaee66af51464a8d590`. Its score is 0.3460810392, below the same unchanged threshold. Both cases and their report sources appear in the same history.

## Run the demonstration

Use the new 0.4.0 source/build. The published 0.3.0 release predates this feature. On Windows extract the entire build archive; keep `CYBERVEIL.exe`, `CYBERVEIL-demo.exe` and `_internal` together. Python is unnecessary for the packaged app.

1. Start CYBERVEIL, select **Analyze sandbox report**, and open the original JSON. It is execution evidence, not the EXE specimen.
2. Review the resulting report's source, model, threshold, score and evidence. An alert means this trace crossed the model's decision threshold; it is not proof of current infection or a probability of maliciousness.
3. Open its detection from Notifications to inspect evidence. Blocking is disabled because the PIDs belong to a past external guest.
4. Export PDF/JSON/CSV. Default redaction hides text fields, including provenance strings; preserve a reviewed unredacted copy where verification requires the hashes.
5. Import the missed report as well. Show its result and the full external evaluation rather than presenting a selected positive as general accuracy.

PowerShell inside a Windows VM or an ordinary clean Windows environment can analyze the JSON without launching a specimen:

```powershell
& '.\CYBERVEIL\CYBERVEIL.exe' doctor
& '.\CYBERVEIL\CYBERVEIL.exe' analyze-sandbox '.\reports\detected-original.json' --output '.\result.json'
& '.\CYBERVEIL\CYBERVEIL.exe' export-report SESSION_ID --format pdf --language ar --output '.\report-ar.pdf'
```

Replace `SESSION_ID` with the ID printed by `analyze-sandbox`. Import is local and does not download/upload reports or execute the malware referenced by a report. Treat third-party JSON as untrusted input. The malware EXE is not needed for this approved demonstration workflow.

## Local delivery and further work

The Desktop folder `CYBERVEIL-Real-Detection-Demo` contains the 66-second actual-UI video, reviewed report inputs, provenance, bilingual exports and Arabic operating notes. Original research reports and download material remain on the external SSD under `/Volumes/External/CYBERVEIL-Validation-20261101/`; no raw malware or bulk report archive is committed to Git.

The next scientific requirement is broader matched malicious/benign CAPE data with reliable labels and collection provenance, family/temporal separation, richer API semantics/arguments and a fresh confirmation set. The current weak external sensitivity must be addressed before claiming the original quality target. Live Windows API acquisition and live fileless detection are separate unimplemented capabilities; importing reports does not establish either.
