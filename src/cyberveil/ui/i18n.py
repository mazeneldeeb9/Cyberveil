from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QDateTime, QLocale

TEXT: dict[str, dict[str, str]] = {
    "en": {
        "back": "Back",
        "notifications": "Notifications",
        "settings": "Settings",
        "settings_phase1_detail": "Choose how local telemetry history and the interface behave.",
        "dashboard": "Protection console",
        "dashboard_subtitle": "Behavior telemetry for this computer",
        "idle": "Ready to observe",
        "idle_detail": "Start a live session or run the safe lab replay.",
        "scanning": "Monitoring system behavior",
        "scanning_detail": "Telemetry is sampled locally. No data leaves this computer.",
        "stopping": "Stopping safely…",
        "complete": "Scan complete",
        "start_scan": "Start live monitoring",
        "stop_scan": "Stop monitoring",
        "safe_demo": "Run safe demo",
        "safe_replay_note": "This demo uses generated telemetry and never runs a payload.",
        "lab_badge": "ACADEMIC LAB",
        "history": "History",
        "history_detail": "Review monitoring sessions and their outcomes.",
        "logs": "Event logs",
        "logs_detail": "Inspect the local audit trail and diagnostic events.",
        "view_history": "View history",
        "view_logs": "View logs",
        "processes": "Processes observed",
        "samples": "Telemetry samples",
        "detections": "Detections",
        "model": "Monitoring engine",
        "fallback_model": "Telemetry only",
        "trained_model": "Telemetry only",
        "full_visibility": "Available fields",
        "degraded": "Limited by permissions",
        "search_history": "Search by date, source, or status",
        "search_logs": "Search events, messages, or details",
        "date": "Date",
        "source": "Source",
        "status": "Status",
        "process": "Process",
        "score": "Score",
        "severity": "Severity",
        "action": "Action",
        "blocked": "Blocked",
        "duration": "Duration",
        "no_history": "No scans yet",
        "no_history_detail": "Start monitoring or run the safe demo to create the first record.",
        "no_logs": "No matching events",
        "no_logs_detail": "Try a different search or begin a monitoring session.",
        "no_notifications": "You’re all caught up",
        "no_notifications_detail": "Phase 1 records telemetry and capability notices here.",
        "save": "Save settings",
        "language": "Language",
        "retention": "History retention (days)",
        "redact": "Redact sensitive process and network details",
        "reduced_motion": "Reduce interface motion",
        "saved": "Settings saved",
        "error": "Something went wrong",
        "seconds": "s",
    },
    "ar": {
        "back": "رجوع",
        "notifications": "التنبيهات",
        "settings": "الإعدادات",
        "settings_phase1_detail": "اختر طريقة حفظ سجل القياس المحلي وسلوك الواجهة.",
        "dashboard": "وحدة الحماية",
        "dashboard_subtitle": "قياس سلوك العمليات على هذا الجهاز",
        "idle": "جاهز للمراقبة",
        "idle_detail": "ابدأ المراقبة المباشرة أو شغّل المحاكاة الآمنة.",
        "scanning": "تتم مراقبة سلوك النظام",
        "scanning_detail": "تُجمع البيانات محلياً ولا تغادر هذا الجهاز.",
        "stopping": "جارٍ الإيقاف بأمان…",
        "complete": "اكتمل الفحص",
        "start_scan": "بدء المراقبة المباشرة",
        "stop_scan": "إيقاف المراقبة",
        "safe_demo": "تشغيل المحاكاة الآمنة",
        "safe_replay_note": "تستخدم هذه المحاكاة بيانات مولدة ولا تشغّل أي حمولة.",
        "lab_badge": "مختبر أكاديمي",
        "history": "السجل",
        "history_detail": "راجع جلسات المراقبة ونتائجها.",
        "logs": "سجل الأحداث",
        "logs_detail": "افحص مسار التدقيق والأحداث التشخيصية المحلية.",
        "view_history": "عرض السجل",
        "view_logs": "عرض الأحداث",
        "processes": "العمليات المرصودة",
        "samples": "عينات القياس",
        "detections": "الاكتشافات",
        "model": "محرك المراقبة",
        "fallback_model": "قياس فقط",
        "trained_model": "قياس فقط",
        "full_visibility": "الحقول المتاحة",
        "degraded": "محدود بالصلاحيات",
        "search_history": "ابحث بالتاريخ أو المصدر أو الحالة",
        "search_logs": "ابحث في الأحداث أو الرسائل أو التفاصيل",
        "date": "التاريخ",
        "source": "المصدر",
        "status": "الحالة",
        "process": "العملية",
        "score": "الدرجة",
        "severity": "الخطورة",
        "action": "الإجراء",
        "blocked": "تم إيقافها",
        "duration": "المدة",
        "no_history": "لا توجد فحوصات بعد",
        "no_history_detail": "ابدأ المراقبة أو شغّل المحاكاة الآمنة لإنشاء أول سجل.",
        "no_logs": "لا توجد أحداث مطابقة",
        "no_logs_detail": "جرّب بحثاً مختلفاً أو ابدأ جلسة مراقبة.",
        "no_notifications": "لا توجد تنبيهات جديدة",
        "no_notifications_detail": "تسجّل المرحلة الأولى بيانات القياس وحالة الصلاحيات هنا.",
        "save": "حفظ الإعدادات",
        "language": "اللغة",
        "retention": "مدة الاحتفاظ بالسجل (بالأيام)",
        "redact": "حجب تفاصيل العمليات والشبكة الحساسة",
        "reduced_motion": "تقليل حركة الواجهة",
        "saved": "تم حفظ الإعدادات",
        "error": "حدث خطأ",
        "seconds": "ث",
    },
}


class Translator:
    def __init__(self, language: str = "en") -> None:
        self.language = language if language in TEXT else "en"

    @property
    def is_rtl(self) -> bool:
        return self.language == "ar"

    def set_language(self, language: str) -> None:
        self.language = language if language in TEXT else "en"

    def __call__(self, key: str) -> str:
        return TEXT[self.language].get(key, TEXT["en"].get(key, key))

    def format_datetime(self, value: datetime | None) -> str:
        if value is None:
            return "—"
        locale = QLocale(QLocale.Language.Arabic) if self.is_rtl else QLocale(QLocale.Language.English)
        qt_value = QDateTime.fromSecsSinceEpoch(int(value.timestamp()))
        return locale.toString(qt_value.toLocalTime(), QLocale.FormatType.ShortFormat)
