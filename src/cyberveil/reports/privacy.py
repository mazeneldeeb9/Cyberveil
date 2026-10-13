"""Conservative redaction for shared reports and local explanation inputs."""

from __future__ import annotations

from typing import Any

from cyberveil.domain import IncidentReport


def redact_report(report: IncidentReport) -> IncidentReport:
    def details(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: details(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [details(item) for item in value]
        return "[redacted]" if isinstance(value, str) else value

    return report.model_copy(
        update={
            "scan": report.scan.model_copy(update={"error": "[redacted]" if report.scan.error else None}),
            "detections": tuple(
                item.model_copy(update={"process_name": f"process-{index + 1}"})
                for index, item in enumerate(report.detections)
            ),
            "actions": tuple(item.model_copy(update={"message": "[redacted]"}) for item in report.actions),
            "forensic_findings": tuple(
                item.model_copy(
                    update={
                        "title": item.category,
                        "details": details(item.details),
                    }
                )
                for item in report.forensic_findings
            ),
        }
    )
