"""Analyze recorded execution behavior. Import is data-only and never detonates files."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from cyberveil.detection.api_model import ApiBehaviorClassifier, api_fingerprint, normalize_api
from cyberveil.domain import (
    DetectionResult,
    ForensicFinding,
    LogRecord,
    ScanRecord,
    ScanSource,
    ScanStatus,
    Severity,
    utc_now,
)
from cyberveil.storage import Database

MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_CALLS = 2_000_000


@dataclass(frozen=True)
class SandboxTrace:
    report_sha256: str
    sample_sha256: str
    apis: frozenset[str]
    call_count: int
    process_count: int
    process_ids: tuple[int, ...]
    analysis_started: str
    analysis_ended: str


def read_sandbox_report(path: Path) -> SandboxTrace:
    # A bound applies to the actual read as well as stat, including special files
    # and files replaced while import is running. No report-supplied paths open.
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Choose a CAPE/Cuckoo JSON report no larger than 128 MiB")
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Sandbox report exceeds 128 MiB")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Expected a CAPE/Cuckoo report object")
    target = payload.get("target")
    behavior = payload.get("behavior")
    if not isinstance(target, dict) or not isinstance(target.get("file"), dict) or not isinstance(behavior, dict):
        raise ValueError("Report must contain target.file.sha256 and behavior.processes")
    sample_hash = target["file"].get("sha256", "")
    if not isinstance(sample_hash, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", sample_hash):
        raise ValueError("Report target SHA-256 is missing or malformed")
    processes = behavior.get("processes")
    if not isinstance(processes, list) or not processes or len(processes) > 10000:
        raise ValueError("Report has no supported process-level API evidence")
    apis: set[str] = set()
    count = 0
    ids: set[int] = set()
    for process in processes:
        if not isinstance(process, dict) or not isinstance(process.get("calls"), list):
            raise ValueError("Each reported process must contain an inline calls array")
        pid = process.get("process_id", process.get("pid"))
        if type(pid) is int and pid >= 0:
            ids.add(pid)
        for call in process["calls"]:
            if not isinstance(call, dict) or not isinstance(call.get("api"), str):
                raise ValueError("Malformed API call record")
            api = normalize_api(call["api"])
            repeats = call.get("repeated", 0)
            if type(repeats) is not int or not 0 <= repeats <= 1_000_000:
                raise ValueError("Invalid API repetition count")
            count += 1 + repeats
            if count > MAX_CALLS:
                raise ValueError("API call count exceeds the supported report limit")
            apis.add(api)
    if not apis:
        raise ValueError("Report contains no API calls; cannot classify an unobserved execution")
    info = payload.get("info", {})
    if not isinstance(info, dict):
        info = {}
    return SandboxTrace(
        report_sha256=hashlib.sha256(raw).hexdigest(), sample_sha256=sample_hash.lower(),
        apis=frozenset(apis), call_count=count, process_count=len(processes), process_ids=tuple(sorted(ids)),
        analysis_started=str(info.get("started", "unknown"))[:100],
        analysis_ended=str(info.get("ended", "unknown"))[:100],
    )


class SandboxAnalysisService:
    def __init__(self, database: Database, classifier: ApiBehaviorClassifier | None = None) -> None:
        self.database = database
        self.classifier = classifier or ApiBehaviorClassifier()

    def analyze(self, report_path: Path) -> dict[str, Any]:
        session_id = str(uuid4())
        self.database.create_scan(ScanRecord(
            session_id=session_id, source=ScanSource.SANDBOX, status=ScanStatus.RUNNING,
            started_at=utc_now(), operating_system="Windows (recorded sandbox execution)",
            model_version=self.classifier.version,
        ))
        try:
            trace = read_sandbox_report(report_path)
            score, known = self.classifier.predict(set(trace.apis))
            fingerprint = api_fingerprint(set(trace.apis))
            overlap = (trace.sample_sha256 in self.classifier.training_hashes
                       or fingerprint in self.classifier.training_fingerprints)
            suspicious = score >= self.classifier.threshold
            evidence: dict[str, Any] = {
                "session_id": session_id, "source": ScanSource.SANDBOX.value,
                "model": self.classifier.version, "threshold": self.classifier.threshold,
                "score": score, "verdict": "suspicious" if suspicious else "not_flagged",
                "classification_unit": "whole recorded execution, not an individual current process",
                "report_sha256": trace.report_sha256, "sample_sha256": trace.sample_sha256,
                "api_fingerprint": fingerprint, "api_call_count": trace.call_count,
                "distinct_api_count": len(trace.apis), "known_api_count": len(known),
                "known_api_fraction": len(known) / len(trace.apis),
                "unknown_apis": sorted(trace.apis - set(known)), "process_count": trace.process_count,
                "recorded_process_ids": trace.process_ids,
                "analysis_started": trace.analysis_started, "analysis_ended": trace.analysis_ended,
                "development_overlap": overlap,
                "dataset_holdout_member": trace.sample_sha256 in self.classifier.holdout_hashes,
                "actions_taken": 0, "lab_only": True,
                "limitations": ["Historical report analysis, not a new local malware execution",
                                "Report source and ground truth require independent verification",
                                "Sandbox scores, signatures, names and labels are not model inputs",
                                "API presence alone does not prove fileless infection or successful containment",
                                "Not flagged is not a clean or safe verdict"],
            }
            if suspicious:
                # PID 0 is deliberately not a claimed live target. This is a trace-level
                # finding and remediation is forbidden for this source at every entry.
                self.database.save_detection(DetectionResult(
                    session_id=session_id, pid=0, process_started_at=0,
                    process_name="Recorded sandbox execution", model_version=self.classifier.version,
                    score=score, severity=Severity.HIGH, label="suspicious_sandbox_behavior",
                    threshold=self.classifier.threshold,
                    reasons=("Windows API behavior model exceeded its validated selection threshold",
                             "Offline execution evidence; no local process was blocked"),
                    feature_values={f"api:{api}": 1.0 for api in known}, source=ScanSource.SANDBOX,
                ))
            self.database.save_forensic_findings(session_id, (ForensicFinding(
                plugin="cyberveil.windows_api", category="sandbox_behavior",
                severity=Severity.HIGH if suspicious else Severity.LOW,
                title="Recorded Windows API behavior classified", details=evidence,
            ),))
            self.database.finish_scan(session_id, ScanStatus.COMPLETED, trace.call_count, int(suspicious))
            self.database.log(LogRecord(
                event="sandbox.classified", message="Recorded sandbox behavior classified",
                context={"session_id": session_id, "score": score, "verdict": evidence["verdict"],
                         "sample_sha256": trace.sample_sha256, "development_overlap": overlap},
            ))
            return evidence
        except Exception as exc:
            self.database.finish_scan(session_id, ScanStatus.FAILED, 0, 0, str(exc))
            self.database.log(LogRecord(level="ERROR", event="sandbox.failed", message=str(exc),
                                        context={"session_id": session_id}))
            raise
