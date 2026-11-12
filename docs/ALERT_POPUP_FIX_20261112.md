# Automatic alert after sandbox report analysis

Version 0.4.1 fixes a missing UI notification step in the sandbox-report workflow.
Version 0.4.0 saved a flagged finding in Notifications and opened the analysis
report, but required opening Notifications and selecting the finding to see its
alert dialog.

After a successful import, CYBERVEIL now opens the report and displays the alert
for detections saved for that import's session. The alert remains available in
Notifications. Unflagged imports do not display an alert, and old notifications
are not reopened. Both English and Arabic use the existing translated dialog.
Process blocking remains disabled for recorded sandbox evidence.

The regression test exercises the asynchronous file-import workflow with an
existing historical notification, using flagged and unflagged classifier outputs
in both languages. Its controlled scores test UI wiring, not detection accuracy.
The recording script verifies the automatically displayed alert instead of
opening it manually. Published report inputs still reproduce their original
model scores; neither the model nor its threshold has changed.

The Windows user must extract and run the complete 0.4.1 application folder.
The earlier 0.4.0 EXE will retain its previous behavior even with the same JSON
input. Importing JSON does not execute a malware specimen.
