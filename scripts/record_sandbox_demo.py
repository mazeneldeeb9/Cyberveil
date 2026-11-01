"""Capture actual UI import of published execution reports, including a miss.

No replay, seeded alert, sample execution or process termination is used. The
dialog selection is automated; classification and exports use production code.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QFileDialog, QLineEdit
from record_demo import Walkthrough

from cyberveil.domain import ScanSource
from cyberveil.reports import ReportService


class SandboxWalkthrough(Walkthrough):
    CAPTURE_TITLE = "CYBERVEIL 0.4.0 — Real Windows sandbox report analysis"
    HEADER_LABEL = "CYBERVEIL 0.4.0 / RECORDED WINDOWS EVIDENCE"
    CAPTURE_COMMENT = (
        "Actual Qt UI capture; automated file selection; original published WinMET execution reports. "
        "No new malware execution, safe replay, seeded detection or local process blocking. Includes a miss."
    )
    DURATION = 66

    def __init__(self, output: Path, work: Path, detected: Path, missed: Path) -> None:
        super().__init__(output, work)
        self.detected_path, self.missed_path = detected.resolve(), missed.resolve()
        self.positive_session: str | None = None
        self.negative_session: str | None = None
        self.active_report = self.detected_path
        self.title = "تحليل سلوك خبيث حقيقي مسجّل داخل Windows"
        self.detail = "تقارير تنفيذ منشورة من WinMET؛ هذا التسجيل لا يشغّل فيروساً جديداً."
        self.chapter = "01 / 08"

    def choose(self) -> None:
        dialogs = [w for w in self.app.topLevelWidgets() if isinstance(w, QFileDialog) and w.isVisible()]
        assert len(dialogs) == 1
        dialogs[0].setDirectory(str(self.active_report.parent))
        self.later(0.5, self.confirm_file)

    def confirm_file(self) -> None:
        dialogs = [w for w in self.app.topLevelWidgets() if isinstance(w, QFileDialog) and w.isVisible()]
        assert len(dialogs) == 1
        edit = dialogs[0].findChild(QLineEdit, "fileNameEdit")
        assert edit is not None
        edit.setText(self.active_report.name)
        dialogs[0].accept()

    def import_report(self, detected: bool) -> None:
        self.active_report = self.detected_path if detected else self.missed_path
        self.window.navigate("dashboard")
        self.caption(
            "02 / 08" if detected else "06 / 08",
            "استيراد التقرير الأصلي" if detected else "اختبار تقرير لم يكتشفه النموذج",
            "تُقرأ استدعاءات API فقط؛ أسماء الملفات وبصماتها وتصنيف CAPE ليست مدخلات للنموذج.",
        )
        self.click(self.window.dashboard.sandbox_button)

    def verify_result(self, detected: bool) -> None:
        assert not self.window._sandbox_running
        report = self.window.report_page.report
        assert report and report.scan.source == ScanSource.SANDBOX
        details = report.forensic_findings[0].details
        assert (details["verdict"] == "suspicious") == detected
        assert report.scan.blocked_count == 0 and not report.actions
        assert not details["development_overlap"]
        self.evidence["detected_report" if detected else "missed_report"] = details
        if detected:
            self.positive_session = report.scan.session_id
            self.caption(
                "03 / 08", "تنبيه محسوب من النموذج الفعلي",
                "سلوك Berbew / Padodor وفق مرجع الناشر؛ ليس تنبيهاً مزروعاً.",
            )
            self.snapshot("03-real-report")
        else:
            self.negative_session = report.scan.session_id
            self.caption(
                "06 / 08", "لم تُكتشف هذه العينة",
                "عدم ظهور تنبيه لا يثبت أن الملف سليم؛ تُحفظ النتيجة كما حدثت.",
            )
            self.snapshot("06-missed-report")

    def show_alert(self) -> None:
        assert self.positive_session
        detection = self.database.list_detections(session_id=self.positive_session)[0]
        self.window.show_detection(detection)
        self.caption(
            "04 / 08", "الدرجة وحد القرار والأدلة",
            "زر الإيقاف معطّل: التقرير تاريخي ولا يحدد عملية حية على هذا الجهاز.",
        )
        self.snapshot("04-real-alert")

    def close_alert(self) -> None:
        self.alert(ScanSource.SANDBOX).reject()

    def switch_arabic(self) -> None:
        self.window.save_settings(self.window.settings.model_copy(update={"language": "ar"}))
        assert self.positive_session
        self.window.open_report(self.positive_session)
        self.caption(
            "05 / 08", "عرض وتصدير التقرير بالعربية والإنجليزية",
            "تُحفظ بصمات التقرير والعينة، ومصدر الأدلة، ودرجة النموذج وحدوده.",
        )
        report = ReportService(self.database).build(self.positive_session)
        service = ReportService(self.database)
        for language in ("ar", "en"):
            for extension in ("pdf", "json", "csv"):
                path = self.work / f"real-detection-{language}.{extension}"
                getattr(service, f"export_{extension}")(report, path, language=language, redact_sensitive=False)
                assert path.stat().st_size > 100
        self.snapshot("05-arabic-report")

    def history(self) -> None:
        self.window.navigate("history")
        self.caption(
            "07 / 08", "النجاح والإخفاق في السجل نفسه",
            "نتيجة إيجابية ونتيجة لم تُكتشف؛ كلاهما من تقارير تنفيذ حقيقية منشورة.",
        )
        self.snapshot("07-history")

    def limits(self) -> None:
        assert self.positive_session
        self.window.open_report(self.positive_session)
        self.caption(
            "08 / 08", "النتيجة العامة وحدود المشروع",
            "رُصد 7 من 20 تقريراً خارجياً؛ بقي 13 دون تنبيه. النموذج تجريبي ويحتاج تحسيناً.",
        )
        self.snapshot("08-limits")

    def start(self) -> None:
        self.started = time.monotonic()
        self.capture_timer.start(round(1000 / self.FPS))
        actions = [
            (1, lambda: self.snapshot("01-dashboard")),
            (4, lambda: self.import_report(True)), (7, self.choose),
            (11, lambda: self.verify_result(True)), (17, self.show_alert), (24, self.close_alert),
            (27, self.switch_arabic), (35, lambda: self.import_report(False)), (38, self.choose),
            (43, lambda: self.verify_result(False)), (51, self.history), (58, self.limits), (66, self.finish),
        ]
        for seconds, action in actions:
            self.later(seconds, action)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--detected-report", type=Path, required=True)
    parser.add_argument("--missed-report", type=Path, required=True)
    args = parser.parse_args()
    if not args.detected_report.is_file() or not args.missed_report.is_file():
        parser.error("Both original sandbox report files must exist")
    if args.output.exists():
        parser.error("Choose a new output filename; recording never overwrites an existing video")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    work = Path(tempfile.mkdtemp(prefix="sandbox-video-", dir=Path(__file__).resolve().parents[1] / "tmp"))
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs)
    recording = SandboxWalkthrough(args.output, work, args.detected_report, args.missed_report)
    QTimer.singleShot(700, recording.start)
    status = recording.app.exec()
    print(json.dumps({"output": str(args.output), "work": str(work), "status": status}))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
