from __future__ import annotations

import csv
import html
import io
import json
import os
import tempfile
from pathlib import Path

from cyberveil.domain import IncidentReport, ScanStatus
from cyberveil.reports.privacy import redact_report
from cyberveil.storage import Database
from cyberveil.ui.i18n import Translator


def _atomic_text(path: Path, content: str, *, encoding: str = "utf-8") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding=encoding, newline="", dir=path.parent, delete=False) as f:
            temporary = Path(f.name)
            f.write(content)
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return path


def _csv_cell(value: object) -> str:
    text = str(value)
    dangerous = text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n"))
    return "'" + text if dangerous else text


class ReportService:
    def __init__(self, database: Database) -> None:
        self.database = database

    def build(self, session_id: str) -> IncidentReport:
        scan = self.database.get_scan(session_id)
        if scan is None:
            raise ValueError(f"Unknown scan session: {session_id}")
        return IncidentReport(
            scan=scan,
            detections=tuple(self.database.list_detections(session_id=session_id, limit=None)),
            actions=tuple(self.database.list_actions_for_session(session_id)),
            forensic_findings=self.database.list_forensic_findings(session_id),
        )

    def _prepare(self, report: IncidentReport, redact_sensitive: bool | None) -> tuple[IncidentReport, bool]:
        enabled = self.database.load_settings().redact_sensitive if redact_sensitive is None else redact_sensitive
        return (redact_report(report) if enabled else report), enabled

    def export_json(
        self,
        report: IncidentReport,
        path: Path,
        *,
        language: str = "en",
        redact_sensitive: bool | None = None,
    ) -> Path:
        report, redacted = self._prepare(report, redact_sensitive)
        tr = Translator(language)
        payload = report.model_dump(mode="json")
        payload.update(
            {
                "schema_version": "1",
                "language": tr.language,
                "redacted": redacted,
                "display": {
                    "status": tr.observation(report.scan.status.value),
                    "source": tr.observation(report.scan.source.value),
                    "warning": tr("lab_warning"),
                    "detections": [
                        {
                            "detection_id": d.detection_id,
                            "severity": tr.observation(d.severity.value),
                            "disposition": tr.observation(d.disposition.value),
                            "reasons": [tr.observation(reason) for reason in d.reasons],
                        }
                        for d in report.detections
                    ],
                },
            }
        )
        return _atomic_text(path, json.dumps(payload, ensure_ascii=False, indent=2))

    def export_csv(
        self,
        report: IncidentReport,
        path: Path,
        *,
        language: str = "en",
        redact_sensitive: bool | None = None,
    ) -> Path:
        report, redacted = self._prepare(report, redact_sensitive)
        tr = Translator(language)
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        headers = [
            "record_type",
            "id",
            "observed_at",
            "process_name",
            "pid",
            "score",
            "severity",
            "status",
            "details",
            "lab_only",
            "session_id",
            "source",
            "model_version",
            "redacted",
        ]
        if tr.is_rtl:
            headers = [
                "نوع السجل",
                "المعرف",
                "التوقيت",
                "العملية",
                "معرف العملية",
                "الدرجة",
                "الخطورة",
                "الحالة",
                "التفاصيل",
                "مختبري فقط",
                "معرف الفحص",
                "المصدر",
                "إصدار النموذج",
                "محجوب",
            ]
        writer.writerow(headers)

        def row(
            kind: str,
            identifier: str,
            at: str,
            process: str,
            pid: object,
            score: object,
            severity: str,
            status: str,
            detail: object,
        ) -> None:
            values = [
                kind,
                identifier,
                at,
                process,
                pid,
                score,
                tr.observation(severity),
                tr.observation(status),
                json.dumps(detail, ensure_ascii=False),
                "true",
                report.scan.session_id,
                tr.observation(report.scan.source.value),
                report.scan.model_version,
                str(redacted).lower(),
            ]
            writer.writerow([_csv_cell(value) for value in values])

        row(
            "summary",
            report.report_id,
            report.generated_at.isoformat(),
            "",
            "",
            "",
            "",
            report.scan.status.value,
            {
                "samples": report.scan.sample_count,
                "detections": report.scan.detection_count,
                "blocked": report.scan.blocked_count,
                "error": report.scan.error,
                "warning": tr("lab_warning"),
            },
        )
        for item in report.detections:
            row(
                "detection",
                item.detection_id,
                item.observed_at.isoformat(),
                item.process_name,
                item.pid,
                f"{item.score:.4f}",
                item.severity.value,
                item.disposition.value,
                {
                    "reasons": [tr.observation(reason) for reason in item.reasons],
                    "features": item.feature_values,
                    "missing_fields": item.missing_fields,
                    "threshold": item.threshold,
                },
            )
        for action in report.actions:
            row(
                "action",
                action.action_id,
                action.occurred_at.isoformat(),
                "",
                "",
                "",
                "",
                action.status.value,
                {
                    "detection_id": action.detection_id,
                    "action": tr.observation(action.action.value),
                    "message": action.message,
                },
            )
        for finding in report.forensic_findings:
            row(
                "forensic",
                finding.plugin,
                "",
                "",
                "",
                "",
                finding.severity.value,
                finding.category,
                {"title": finding.title, "details": finding.details},
            )
        return _atomic_text(path, stream.getvalue(), encoding="utf-8-sig")

    def export_pdf(
        self,
        report: IncidentReport,
        path: Path,
        *,
        language: str = "en",
        redact_sensitive: bool | None = None,
    ) -> Path:
        # Retain Qt's native Arabic shaping and font embedding for the desktop exporter.
        from PySide6.QtCore import QMarginsF
        from PySide6.QtGui import QFont, QGuiApplication, QPageLayout, QPageSize, QTextDocument
        from PySide6.QtPrintSupport import QPrinter

        application = QGuiApplication.instance()
        if application is None:
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
            application = QGuiApplication([])
        report, redacted = self._prepare(report, redact_sensitive)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(suffix=".pdf", dir=path.parent)
        os.close(descriptor)
        temporary = Path(name)
        try:
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(str(temporary))
            printer.setDocName("CYBERVEIL Analysis Report")
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setPageMargins(QMarginsF(16, 16, 16, 16), QPageLayout.Unit.Millimeter)
            document = QTextDocument()
            document.setDefaultFont(QFont("Arial", 10))
            document.setHtml(self.to_html(report, language=language, redacted=redacted))
            document.print_(printer)
            if not temporary.is_file() or temporary.stat().st_size < 100:
                raise OSError("PDF renderer did not produce a complete file")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return path

    @staticmethod
    def to_html(
        report: IncidentReport,
        *,
        language: str = "en",
        full: bool = True,
        dark: bool = False,
        redacted: bool = False,
    ) -> str:
        tr = Translator(language)
        esc = html.escape
        scan = report.scan
        foreground, accent, border, surface = (
            ("#F3F8FA", "#90F4EA", "#284A61", "#10253A") if dark else ("#102235", "#087F79", "#B9C8D2", "#E9F8F6")
        )
        direction = "rtl" if tr.is_rtl else "ltr"
        alignment = "right" if tr.is_rtl else "left"
        block = f'dir="{direction}" align="{alignment}"'
        # QTextDocument supports HTML width/alignment attributes more reliably than CSS.
        table = f'<table width="100%" dir="{direction}" align="{alignment}" cellspacing="0">'
        metadata = (
            ("scan_id", scan.session_id),
            ("source", tr.observation(scan.source.value)),
            ("status", tr.observation(scan.status.value)),
            ("model", scan.model_version),
            ("started", tr.format_datetime(scan.started_at)),
            ("ended", tr.format_datetime(scan.ended_at)),
            ("samples", str(scan.sample_count)),
            ("detections", str(scan.detection_count)),
            ("blocked", str(scan.blocked_count)),
        )
        pieces = [
            f'''<!doctype html><html dir="{direction}"><head><meta charset="utf-8"><style>
        body {{font-family:Arial; color:{foreground}; font-size:{12 if dark else 10}pt;}}
        p,h1,h2,h3,li {{text-align:{alignment}; direction:{direction};}}
        h1,h2,h3 {{color:{accent};}} p {{line-height:1.4;}}
        table {{border-collapse:collapse; width:100%;}} td,th {{padding:6px; border:1px solid {border};}}
        th {{background:{surface};}} .warning {{background:{surface}; padding:8px;}}
        </style></head><body dir="{direction}"><h1 {block}>{tr("full_analysis") if full else tr("summary_report")}</h1>
        <p {block} class="warning">CYBERVEIL - {tr("lab_warning")}</p>'''
        ]
        if redacted:
            pieces.append(f"<p>{tr('redacted_report')}</p>")
        if scan.status != ScanStatus.COMPLETED:
            pieces.append(f"<p><b>{tr('incomplete_report')}</b></p>")
        if scan.error:
            pieces.append(f"<p>{tr('error')}: {esc(scan.error)}</p>")
        pieces.append(
            table
            + "".join(
                (f"<tr><td>{esc(value)}</td><td><b>{tr(key)}</b></td></tr>" if tr.is_rtl
                 else f"<tr><td><b>{tr(key)}</b></td><td>{esc(value)}</td></tr>")
                for key, value in metadata
            )
            + "</table>"
        )
        pieces.append(f"<h2>{tr('detections')}</h2>")
        if not report.detections:
            key = "no_threat" if scan.status == ScanStatus.COMPLETED else "no_detections_recorded"
            pieces.append(f"<p>{tr(key)}</p>")
        for item in report.detections:
            pieces.append(f"<h3>{esc(item.process_name)} - PID {item.pid}</h3>")
            pieces.append(
                f"<p>{tr('score')}: {item.score:.1%} | {tr('severity')}: "
                f"{tr.observation(item.severity.value)} | {tr('action')}: "
                f"{tr.observation(item.disposition.value)}</p>"
            )
            pieces.append("<ul>" + "".join(f"<li>{esc(tr.observation(r))}</li>" for r in item.reasons) + "</ul>")
            if full:
                pieces.append(f"<p>{tr('evidence_note')}</p>{table}")
                pieces.extend(
                    f"<tr><td>{esc(name)}</td><td>{value:.5g}</td></tr>" for name, value in item.feature_values.items()
                )
                pieces.append("</table>")
                if item.missing_fields:
                    pieces.append(f"<p>{tr('permission_title')}: {esc(', '.join(item.missing_fields))}</p>")
        if full:
            pieces.append(f"<h2>{tr('action_audit')}</h2>")
            if not report.actions:
                pieces.append(f"<p>{tr('no_actions')}</p>")
            for action in report.actions:
                pieces.append(
                    f"<p>{tr.format_datetime(action.occurred_at)} | "
                    f"{tr.observation(action.action.value)} | {tr.observation(action.status.value)}<br>"
                    f"{esc(action.message)}<br>{esc(action.detection_id)}</p>"
                )
            pieces.append(f"<h2>{tr('forensics')}</h2>")
            if not report.forensic_findings:
                pieces.append(f"<p>{tr('no_forensics')}</p>")
            for finding in report.forensic_findings:
                pieces.append(
                    f"<h3>{esc(finding.title)}</h3><p>{esc(finding.plugin)} | "
                    f"{esc(tr.observation(finding.category))}</p>"
                )
                for line in json.dumps(finding.details, ensure_ascii=False, indent=2).splitlines():
                    pieces.append(f'<p dir="ltr" style="margin:0; text-align:left;">{esc(line)}</p>')
        pieces.append("</body></html>")
        markup = "".join(pieces)
        # Qt rich text does not inherit body direction consistently for blocks.
        for tag in ("p", "h2", "h3", "ul", "li"):
            markup = markup.replace(f"<{tag}>", f"<{tag} {block}>")
        return markup
