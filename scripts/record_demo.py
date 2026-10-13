"""Record the running Qt application, excluding all other desktop content.

Uses an isolated database and real UI handlers. Replay containment is simulated;
the separate process demo only terminates the sleeping child created by the app.
Captions are presentation overlays, not changes to the application itself.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import traceback
from pathlib import Path

from PySide6.QtCore import QPoint, QRect, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPen
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, QPlainTextEdit, QScrollArea

from cyberveil.domain import RemediationStatus, ScanSource, ScanStatus
from cyberveil.storage import Database
from cyberveil.ui.app import create_application
from cyberveil.ui.main_window import MainWindow
from cyberveil.ui.pages import DetectionDialog


class Walkthrough:
    WIDTH, HEIGHT, FPS = 1600, 1000, 10
    APP_X, APP_Y, APP_W, APP_H = 80, 54, 1440, 820
    DURATION = 320

    def __init__(self, output: Path, work: Path, vm_log: Path | None = None) -> None:
        self.output, self.work = output, work
        os.environ["CYBERVEIL_DATA_DIR"] = str(work / "app-data")
        self.vm_log = vm_log
        self.vm_position = 0
        self.vm_buffer = ""
        self.vm_console = None
        self.vm_result = None
        self.app = create_application()
        self.app.setQuitOnLastWindowClosed(False)
        self.database = Database(work / "walkthrough.db")
        self.window = MainWindow(self.database)
        self.window.resize(self.APP_W, self.APP_H)
        self.window.move(100, 80)
        self.window.show()
        self.window.raise_()
        self.title = "CYBERVEIL — العرض الكامل"
        self.detail = "مراقبة العمليات، كشف السلوك، الأدلة والتقارير، وتجربة إيقاف آمنة."
        self.chapter = "01 / 12"
        self.started = 0.0
        self.frames = 0
        self.failed = False
        self.child = None
        self.replay_session = None
        self.demo_session = None
        self.last_click: tuple[float, QPoint] | None = None
        self.evidence: dict[str, object] = {}
        self.encoder_log = (work / "ffmpeg.log").open("wb")
        self.encoder = subprocess.Popen(
            [
                shutil.which("ffmpeg") or "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "warning",
                "-n",
                "-f",
                "rawvideo",
                "-pixel_format",
                "rgba",
                "-video_size",
                f"{self.WIDTH}x{self.HEIGHT}",
                "-framerate",
                str(self.FPS),
                "-i",
                "pipe:0",
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-crf",
                "19",
                "-pix_fmt",
                "yuv420p",
                "-movflags",
                "+faststart",
                "-metadata",
                "title=CYBERVEIL — Full Phase 3 Demonstration",
                "-metadata",
                "comment=Actual Qt app capture with Arabic captions; isolated demo database. "
                "Safe replay, harmless child containment, and a labelled external VM experiment when supplied.",
                str(output),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=self.encoder_log,
        )
        self.capture_timer = QTimer()
        self.capture_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self.capture_timer.timeout.connect(self.capture)
        self.timers: list[QTimer] = []

    def later(self, seconds: float, callback) -> None:
        timer = QTimer()
        timer.setSingleShot(True)
        timer.setTimerType(Qt.TimerType.PreciseTimer)

        def run() -> None:
            if self.failed:
                return
            try:
                callback()
            except Exception:
                traceback.print_exc()
                self.failed = True
                self.finish()

        timer.timeout.connect(run)
        self.timers.append(timer)
        timer.start(round(seconds * 1000))

    def caption(self, chapter: str, title: str, detail: str) -> None:
        self.chapter, self.title, self.detail = chapter, title, detail
        print(f"{time.monotonic() - self.started:6.1f}s  {title}", flush=True)

    def click(self, widget) -> None:
        assert widget.isVisible() and widget.isEnabled(), f"Unavailable control: {widget}"
        self.last_click = (time.monotonic(), widget.mapToGlobal(widget.rect().center()))
        widget.click()

    def scroll_settings(self, bottom: bool = False) -> None:
        scroll = self.window.settings_page.findChild(QScrollArea)
        assert scroll is not None
        scroll.verticalScrollBar().setValue(scroll.verticalScrollBar().maximum() if bottom else 0)

    def alert(self, source: ScanSource) -> DetectionDialog:
        dialogs = [
            widget
            for widget in self.app.topLevelWidgets()
            if isinstance(widget, DetectionDialog) and widget.isVisible() and widget.detection.source == source
        ]
        assert len(dialogs) == 1, f"Expected one {source} alert, got {len(dialogs)}"
        return dialogs[0]

    def message(self) -> QMessageBox:
        boxes = [w for w in self.app.topLevelWidgets() if isinstance(w, QMessageBox) and w.isVisible()]
        assert len(boxes) == 1, f"Expected one message box, got {len(boxes)}"
        return boxes[0]

    def dismiss_success(self) -> None:
        box = self.message()
        assert box.icon() == QMessageBox.Icon.Information, box.informativeText()
        self.click(box.button(QMessageBox.StandardButton.Ok))

    def live_start(self) -> None:
        self.caption(
            "02 / 12",
            "المراقبة الحية — تشغيل فحص",
            "جمع فعلي لمؤشرات العمليات محلياً؛ لا ينفذ الفحص أي إجراء تلقائي على العمليات.",
        )
        self.click(self.window.dashboard.primary)

    def live_stop(self) -> None:
        if self.window.scan_thread and self.window.scan_thread.isRunning():
            self.click(self.window.dashboard.primary)

    def live_snapshot(self) -> None:
        scans = self.database.list_scans()
        if scans and scans[0].status == ScanStatus.FAILED:
            self.caption(
                "02 / 12",
                "قيد حالي على macOS",
                "تعذرت قراءة الملفات المفتوحة لإحدى العمليات؛ يحتاج هذا الخطأ إلى معالجة قبل اعتماد المراقبة الحية.",
            )
        self.snapshot("02-live")

    def live_history(self) -> None:
        scans = self.database.list_scans()
        assert len(scans) == 1 and scans[0].source == ScanSource.LIVE
        self.evidence["live_scan"] = scans[0].model_dump(mode="json")
        if scans[0].status == ScanStatus.FAILED:
            self.message().reject()
            self.caption(
                "02 / 12",
                "سجل الفحوصات وحالات التعثر",
                "حُفظ الفحص بحالة فشل، دون الإبلاغ عن نجاح غير مكتمل؛ ننتقل الآن إلى السيناريو المختبري.",
            )
        else:
            assert scans[0].status == ScanStatus.STOPPED and scans[0].sample_count > 0
            self.evidence["live_detections"] = scans[0].detection_count
            self.caption("02 / 12", "سجل الفحوصات", "حُفظ الفحص بعد إيقافه، مع عدد العينات وحالته وتوقيت تشغيله.")
        self.click(self.window.dashboard.history_button)

    def replay_start(self) -> None:
        self.window.navigate("dashboard")
        self.caption(
            "03 / 12",
            "كشف السلوك — سيناريو مختبري آمن",
            "بيانات مولدة تمر عبر النموذج الفعلي؛ ليست إصابة حقيقية على الجهاز.",
        )
        self.click(self.window.dashboard.demo)

    def replay_evidence(self) -> None:
        alert = self.alert(ScanSource.REPLAY)
        self.replay_session = alert.detection.session_id
        self.evidence["replay_score"] = alert.detection.score
        assert alert.detection.feature_values
        self.caption(
            "03 / 12",
            "تنبيه يوضح درجة الخطورة والأدلة",
            "يعرض اسم العملية، درجة التصنيف، الإشارات الملحوظة وحدود تفسير النتيجة.",
        )

    def replay_block(self) -> None:
        self.caption("03 / 12", "محاكاة الاحتواء", "في هذا السيناريو، يسجل التطبيق الإجراء دون إيقاف أي عملية حقيقية.")
        self.click(self.alert(ScanSource.REPLAY).block)

    def replay_report(self) -> None:
        assert self.replay_session
        report = self.window.report_service.build(self.replay_session)
        assert report.scan.blocked_count == 1
        assert len(report.actions) == 1 and report.actions[0].status == RemediationStatus.SUCCEEDED
        self.evidence["replay_simulated_action"] = report.actions[0].message
        self.window.open_report(self.replay_session)
        self.caption(
            "04 / 12", "تقرير الفحص والأدلة المسجلة", "ملخص العينات والكشوفات والإجراءات، مع أسباب التصنيف لكل عملية."
        )

    def notifications(self) -> None:
        self.click(self.window.header.notifications)
        self.caption("04 / 12", "سجل التنبيهات", "تظل التنبيهات ودرجاتها وحالة التعامل معها محفوظة للمراجعة.")

    def settings(self) -> None:
        self.click(self.window.header.settings)
        self.scroll_settings()
        self.caption(
            "05 / 12",
            "الإعدادات ودعم اللغتين",
            "حد الخطورة، الخصوصية والاحتفاظ بالسجل؛ الإيقاف التلقائي معطل للنموذج التجريبي.",
        )

    def arabic(self) -> None:
        self.window.settings_page.language.setCurrentIndex(1)
        self.click(self.window.settings_page.save_button)
        assert self.window.layoutDirection() == Qt.LayoutDirection.RightToLeft
        self.caption(
            "05 / 12",
            "واجهة عربية باتجاه من اليمين إلى اليسار",
            "تم حفظ اللغة وتحديث الواجهة؛ عرض الإعدادات متناسق مع النمط الداكن.",
        )

    def demo_start(self) -> None:
        self.scroll_settings(bottom=True)
        self.caption(
            "06 / 12",
            "تجربة إيقاف عملية آمنة",
            "ينشئ التطبيق عملية خاملة خاصة بالتجربة؛ التنبيه هنا يدوي وليس اكتشاف برمجية خبيثة.",
        )
        self.click(self.window.settings_page.demo_process_button)
        alert = self.alert(ScanSource.DEMO_PROCESS)
        demo, self.demo_session = self.window._demo_processes[alert.detection.detection_id]
        self.child = demo.child
        assert self.child.poll() is None
        self.evidence["harmless_child_pid"] = self.child.pid

    def demo_confirm_prompt(self) -> None:
        self.caption(
            "06 / 12",
            "التأكيد مطلوب قبل الإيقاف",
            "يعرض التطبيق اسم العملية ومعرّفها، ويتحقق من هويتها وصلاحية إيقافها.",
        )
        self.click(self.alert(ScanSource.DEMO_PROCESS).block)

    def demo_confirm(self) -> None:
        assert self.child is not None and self.child.poll() is None
        box = self.message()
        assert box.standardButtons() & QMessageBox.StandardButton.Yes
        self.click(box.button(QMessageBox.StandardButton.Yes))

    def demo_success(self) -> None:
        assert self.child is not None and self.child.poll() is not None
        assert self.demo_session
        report = self.window.report_service.build(self.demo_session)
        assert report.scan.blocked_count == 1
        assert len(report.actions) == 1 and report.actions[0].status == RemediationStatus.SUCCEEDED
        self.evidence["harmless_child_exit_code"] = self.child.returncode
        self.evidence["harmless_child_action"] = report.actions[0].model_dump(mode="json")
        self.caption(
            "06 / 12",
            "تم إيقاف العملية التجريبية فعلياً",
            "نجح الإيقاف بعد التأكيد، وحُفظت النتيجة في التقرير وسجل الأحداث.",
        )

    def demo_report(self) -> None:
        self.dismiss_success()
        assert self.demo_session
        self.window.open_report(self.demo_session)
        self.caption(
            "07 / 12",
            "نتيجة الإجراء في التقرير",
            "يظهر إجراء إيقاف واحد للعملية الخاملة، مع الاحتفاظ بسجل قابل للمراجعة.",
        )

    def logs(self) -> None:
        self.window.navigate("logs")
        self.caption(
            "07 / 12", "سجل الأحداث والتدقيق", "تسجيل بدء الفحوصات ونتائج الكشف والإجراءات، مع إمكانية البحث في السجل."
        )

    def forensics(self) -> None:
        self.window.navigate("settings")
        self.scroll_settings(bottom=True)
        self.click(self.window.settings_page.forensics_button)
        self.caption(
            "08 / 12",
            "تحليل الذاكرة دون اتصال",
            "تكامل Volatility 3 لصور Windows وLinux وmacOS؛ يلزم توفير صورة ذاكرة مناسبة.",
        )

    def forensic_limit(self) -> None:
        self.window.forensics_page.os.setCurrentIndex(2)
        self.caption(
            "08 / 12",
            "حدود التحقق الحالية",
            "لم تُقدَّم صورة ذاكرة حقيقية للتحقق النهائي؛ لا يعرض هذا الفيديو نتائج تحليل وهمية.",
        )

    def outro(self) -> None:
        self.window.navigate("dashboard")
        self.caption(
            "09 / 12",
            "نتائج العرض وحدود الاعتماد",
            "النموذج تجريبي؛ يلزم تحسين استهلاك المعالج والتحقق على Windows وبصورة ذاكرة حقيقية.",
        )

    def filter_history(self) -> None:
        self.caption(
            "02 / 12", "البحث والتصفية في الفحوصات", "نتائج محفوظة يمكن تصفيتها حسب المصدر والبحث بمعرّف الفحص."
        )
        filters = self.window.history_page.filters
        filters.choice.setCurrentIndex(filters.choice.findData("live"))
        filters.search.setText(self.database.list_scans()[0].session_id[:8])

    def filter_notifications(self) -> None:
        self.window.notifications_page.filters.search.setText("cyberveil")
        self.window.notifications_page.filters.choice.setCurrentIndex(1)
        self.caption("04 / 12", "بحث التنبيهات حسب العملية والخطورة", "تصفية النتائج المحفوظة دون تغيير سجل التدقيق.")

    def summary_mode(self) -> None:
        self.window.report_page.view_mode.setCurrentIndex(1)
        self.caption(
            "09 / 12",
            "تقرير مختصر أو تحليل كامل",
            "التبديل بين الملخص والأدلة الرقمية؛ تبقى النتائج موسومة بأنها مختبرية.",
        )

    def local_explanation(self) -> None:
        self.caption(
            "09 / 12",
            "الشرح المحلي والبديل الحتمي",
            "Ollama غير مفعّل في هذا العرض؛ يظهر شرح القالب المحلي بوضوح دون ادعاء توليد بالذكاء الاصطناعي.",
        )
        self.click(self.window.report_page.explain_button)

    def export(self, extension: str) -> None:
        self.caption(
            "10 / 12",
            "تصدير التقارير — " + extension.upper(),
            "حفظ فعلي لتقرير عربي مع حجب البيانات الحساسة؛ لا تتغير السجلات المحلية.",
        )
        self.click(getattr(self.window.report_page, extension + "_button"))

    def accept_export(self, extension: str) -> None:
        dialogs = [w for w in self.app.topLevelWidgets() if isinstance(w, QFileDialog) and w.isVisible()]
        assert len(dialogs) == 1
        dialogs[0].selectFile(str(self.work / ("demo-report." + extension)))
        dialogs[0].accept()

    def verify_exports(self) -> None:
        assert self.window.report_page.report
        stem = "cyberveil-" + self.window.report_page.report.scan.session_id[:8]
        outputs = {}
        for extension in ("pdf", "json", "csv"):
            path = self.work / ("demo-report." + extension)
            if not path.exists():
                path = self.work / (stem + "." + extension)
            assert path.stat().st_size > 100
            outputs[extension] = str(path)
        payload = json.loads(Path(outputs["json"]).read_text())
        assert payload["language"] == "ar" and payload["redacted"]
        self.evidence["exports"] = outputs
        self.caption(
            "10 / 12", "تم حفظ الملفات الثلاثة", "PDF وJSON وCSV باللغة العربية؛ تم التحقق من الملفات الناتجة فعلياً."
        )

    def vm_chapter(self) -> None:
        if not self.vm_log:
            self.caption(
                "11 / 12", "الاختبار المعزول غير مرفق بهذا التسجيل", "لا تُعرض نتيجة اختبار حقيقي دون سجل تجربة موثق."
            )
            self.later(7, self.outro)
            self.later(15, self.finish)
            return
        self.vm_console = QPlainTextEdit()
        self.vm_console.resize(self.APP_W, self.APP_H)
        self.vm_console.setReadOnly(True)
        self.vm_console.setFont(QFont("Menlo", 15))
        self.vm_console.setStyleSheet("background:#07131f;color:#d7edea;padding:24px;")
        self.vm_console.setPlainText(
            "CYBERVEIL / ISOLATED LINUX VM — LIVE SERIAL CONSOLE\n"
            "External SSD | no virtual NIC | no shared folders | no clipboard\n"
            "The app observes; this separate lab experiment is not a bundled demo.\n\n"
            "Waiting for the independently operated guest experiment..."
        )
        self.vm_console.show()
        self.vm_position = self.vm_log.stat().st_size
        self.caption(
            "11 / 12",
            "اختبار حقيقي داخل جهاز افتراضي معزول",
            "سجل مباشر من Linux؛ الشبكة ومشاركة ملفات المضيف معطلتان قبل تشغيل العينة.",
        )
        (self.work / "vm-chapter-ready").touch()
        print("VM_CHAPTER_READY", flush=True)
        self.later(160, self.vm_timeout)

    def poll_vm(self) -> None:
        if not self.vm_console or not self.vm_log or self.vm_result:
            return
        with self.vm_log.open("rb") as stream:
            stream.seek(self.vm_position)
            data = stream.read(1_000_000)
            self.vm_position = stream.tell()
        if not data:
            return
        self.vm_buffer += data.decode("utf-8", errors="replace").replace("\r", "")
        while "\n" in self.vm_buffer:
            line, self.vm_buffer = self.vm_buffer.split("\n", 1)
            line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
            if line.startswith("CVLAB_RESULT "):
                self.vm_result = json.loads(line[len("CVLAB_RESULT ") :])
                self.evidence["vm_test"] = {
                    key: self.vm_result[key]
                    for key in ("sample_sha256", "isolation", "specimen_pids", "actions_taken_by_cyberveil")
                }
                (self.work / "vm-result.json").write_text(json.dumps(self.vm_result, indent=2))
                detected = len(self.vm_result["specimen_detections"])
                observed = len(self.vm_result["specimen_observations"])
                self.vm_console.appendPlainText(
                    f"\nVERIFIED RESULT: {observed} specimen observations, {detected} specimen detections.\n"
                    "CYBERVEIL process actions: 0. Specimen UID cleanup performed separately by lab harness.\n"
                    "Single historical disk-backed specimen; no C2 network; not a fileless accuracy benchmark."
                )
                self.caption(
                    "11 / 12",
                    "نتيجة الاختبار كما حدثت",
                    f"رُصدت {observed} عينة قياس للعملية، وعدد تنبيهاتها {detected}. "
                    "هذه التجربة الواحدة ليست مقياساً للدقة العامة.",
                )
                self.snapshot("vm-result")
                self.later(12, self.vm_outro)
                self.later(25, self.finish)
            else:
                # Show transcript text, never render it as HTML or execute it.
                self.vm_console.appendPlainText(line[:500])
                if "REAL SAMPLE EXECUTED" in line:
                    self.caption(
                        "11 / 12",
                        "تشغيل العينة الحقيقية داخل Linux فقط",
                        "المراقبة تعمل بالنموذج نفسه؛ الإيقاف التلقائي معطل، ولا يوجد اتصال بالشبكة.",
                    )
            self.vm_console.verticalScrollBar().setValue(self.vm_console.verticalScrollBar().maximum())

    def vm_outro(self) -> None:
        if self.vm_console:
            self.vm_console.close()
            self.vm_console = None
        self.outro()
        self.snapshot("final-outro")

    def vm_timeout(self) -> None:
        if self.vm_console and not self.vm_result:
            self.evidence["vm_test"] = "No complete result received during the recording"
            self.caption(
                "11 / 12",
                "لم تكتمل نتيجة الاختبار في زمن التسجيل",
                "هذه حالة غير مكتملة، وليست نتيجة كشف أو حماية ناجحة.",
            )
            self.later(8, self.vm_outro)
            self.later(16, self.finish)

    def text(self, painter: QPainter, rect: QRect, value: str, size: int, color: str, bold=False, right=True) -> None:
        font = QFont("Arial")
        font.setPixelSize(size)
        font.setBold(bold)
        painter.setFont(font)
        painter.setPen(QColor(color))
        align = Qt.AlignmentFlag.AlignRight if right else Qt.AlignmentFlag.AlignLeft
        painter.drawText(rect, align | Qt.AlignmentFlag.AlignVCenter, value)

    def frame(self) -> QImage:
        frame = QImage(self.WIDTH, self.HEIGHT, QImage.Format.Format_RGBA8888)
        frame.fill(QColor("#030C15"))
        painter = QPainter(frame)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.text(painter, QRect(80, 10, 740, 32), "CYBERVEIL  /  PHASE 03", 18, "#90F4EA", bold=True, right=False)
        self.text(painter, QRect(900, 10, 620, 32), "عرض من التطبيق الفعلي  •  بيئة تجريبية مستقلة", 17, "#A9C0CC")
        app_rect = QRect(self.APP_X, self.APP_Y, self.APP_W, self.APP_H)
        painter.drawPixmap(app_rect, self.vm_console.grab() if self.vm_console else self.window.grab())
        origin = self.window.mapToGlobal(QPoint(0, 0))
        overlays = [
            w for w in self.app.topLevelWidgets() if w is not self.window and isinstance(w, QDialog) and w.isVisible()
        ]
        overlays.sort(key=lambda w: isinstance(w, QMessageBox))
        if overlays:
            painter.fillRect(app_rect, QColor(2, 7, 12, 130))
        for widget in overlays:
            widget.adjustSize()
            x = origin.x() + (self.APP_W - widget.width()) // 2
            y = origin.y() + (self.APP_H - widget.height()) // 2
            widget.move(x, y)
            pos = widget.mapToGlobal(QPoint(0, 0)) - origin + QPoint(self.APP_X, self.APP_Y)
            target = QRect(pos, widget.size())
            painter.fillRect(target.adjusted(-2, -2, 2, 2), QColor("#284A61"))
            painter.drawPixmap(target, widget.grab())
        if self.last_click:
            occurred, global_pos = self.last_click
            age = time.monotonic() - occurred
            if age < 0.7:
                pos = global_pos - origin + QPoint(self.APP_X, self.APP_Y)
                painter.setPen(QPen(QColor(34, 211, 197, round(240 * (1 - age / 0.7))), 3))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                radius = 12 + 20 * age / 0.7
                painter.drawEllipse(pos, radius, radius)
        self.text(painter, QRect(80, 891, 110, 44), self.chapter, 19, "#22D3C5", right=False)
        self.text(painter, QRect(205, 886, 1315, 44), self.title, 27, "#F3F8FA", bold=True)
        self.text(painter, QRect(80, 933, 1440, 36), self.detail, 21, "#A9C0CC")
        elapsed = max(0, time.monotonic() - self.started)
        painter.fillRect(QRect(80, 983, 1440, 3), QColor("#173149"))
        painter.fillRect(QRect(80, 983, round(1440 * min(1, elapsed / self.DURATION)), 3), QColor("#22D3C5"))
        painter.end()
        return frame

    def capture(self) -> None:
        try:
            self.poll_vm()
            frame = self.frame()
            # Repeat frames after any scheduling delay to preserve real elapsed time.
            target_frames = int((time.monotonic() - self.started) * self.FPS) + 1
            assert self.encoder.stdin is not None
            pixels = frame.constBits()
            while self.frames < target_frames:
                self.encoder.stdin.write(pixels)
                self.frames += 1
        except Exception:
            traceback.print_exc()
            self.failed = True
            self.finish()

    def snapshot(self, name: str) -> None:
        assert self.frame().save(str(self.work / f"{name}.png"))

    def start(self) -> None:
        self.started = time.monotonic()
        self.capture_timer.start(round(1000 / self.FPS))
        actions = [
            (1, lambda: self.snapshot("01-dashboard")),
            (5, self.live_start),
            (22, self.live_snapshot),
            (30, self.live_stop),
            (33, self.live_history),
            (38, self.filter_history),
            (44, self.replay_start),
            (49, self.replay_evidence),
            (52, lambda: self.snapshot("03-alert")),
            (55, self.replay_block),
            (58, self.dismiss_success),
            (60, self.replay_report),
            (65, lambda: self.window.report_page.browser.verticalScrollBar().setValue(350)),
            (70, self.summary_mode),
            (75, self.notifications),
            (78, self.filter_notifications),
            (82, self.settings),
            (87, self.arabic),
            (93, lambda: self.snapshot("05-settings-ar")),
            (96, self.demo_start),
            (102, self.demo_confirm_prompt),
            (105, lambda: self.snapshot("07-confirmation")),
            (109, self.demo_confirm),
            (112, self.demo_success),
            (116, self.demo_report),
            (122, self.logs),
            (128, self.forensics),
            (134, self.forensic_limit),
            (138, lambda: self.click(self.window.forensics_page.analyze)),
            (143, lambda: self.window.navigate("reports")),
            (149, self.replay_report),
            (152, self.summary_mode),
            (157, self.local_explanation),
            (
                163,
                lambda: self.window.report_page.browser.verticalScrollBar().setValue(
                    self.window.report_page.browser.verticalScrollBar().maximum()
                ),
            ),
            (168, lambda: self.snapshot("local-explanation")),
            (173, lambda: self.export("pdf")),
            (177, lambda: self.accept_export("pdf")),
            (181, self.dismiss_success),
            (184, lambda: self.export("json")),
            (188, lambda: self.accept_export("json")),
            (192, self.dismiss_success),
            (195, lambda: self.export("csv")),
            (199, lambda: self.accept_export("csv")),
            (203, self.dismiss_success),
            (205, self.verify_exports),
            (212, self.vm_chapter),
        ]
        for seconds, action in actions:
            self.later(seconds, action)

    def finish(self) -> None:
        self.capture_timer.stop()
        for timer in self.timers:
            timer.stop()
        self.evidence["frames"] = self.frames
        self.evidence["duration_seconds"] = self.frames / self.FPS
        self.evidence["capture_failed"] = self.failed
        (self.work / "evidence.json").write_text(json.dumps(self.evidence, ensure_ascii=False, indent=2))
        if self.encoder.stdin is not None:
            self.encoder.stdin.close()
        status = self.encoder.wait(timeout=30)
        self.encoder_log.close()
        if status:
            self.failed = True
        for widget in self.app.topLevelWidgets():
            if isinstance(widget, (QMessageBox, DetectionDialog)):
                widget.reject()
        self.window.close()
        print(
            json.dumps(
                {"output": str(self.output), "work": str(self.work), "success": not self.failed, **self.evidence}
            ),
            flush=True,
        )
        self.app.exit(1 if self.failed else 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--vm-log", type=Path, help="Read-only serial log from a separately operated isolated VM")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output exists; choose a new name to avoid overwriting it.")
    work = Path(tempfile.mkdtemp(prefix="phase3-video-", dir=Path(__file__).resolve().parents[1] / "tmp"))
    print(f"Recording evidence: {work}", flush=True)
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs)
    recording = Walkthrough(args.output, work, args.vm_log)
    QTimer.singleShot(700, recording.start)
    return recording.app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
