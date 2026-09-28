# ADR-0011: Alerts, reports and audit (Phase 6)

- Status: Accepted (2026-09-28).
- Builds on ADR-0005 (audit log) and ADR-0008/0009/0010 (the events computers send).

## Alerts

**How alerts are raised.**
- A background job on the server runs every 30 seconds.
- It reads the security events received since its previous run: events from agents, and those the server
  records itself (e.g. an unapproved program found).
- It then checks the current state: computers, and failed sign-ins in the audit log.
- On a new database, the first run starts from the events that arrive from then on, so an upgraded installation
  is not flooded with alerts for old events.

**Deduplication.**
- One alert per rule, computer and subject (for example the account name for failed sign-ins).
- Repeats while that alert is not resolved are added to it ("Times").
- After an administrator resolves it, the next occurrence opens a new alert.
- Events already covered by a resolved alert do not count towards a new one.

**Rules** (administrators can switch each one off and change its severity and numbers; changes are audited):

| Rule | Raised when | Default |
|---|---|---|
| Protection tampered with | the agent restored a changed protection (`PolicyTamperAttempt`) | Critical |
| Blocked USB drive or phone | a USB drive, memory card or phone was blocked | Warning |
| Blocked program | Application Control blocked a program (Enforce only; Audit-mode reports do not alert) | Warning |
| Ransomware protection blocked a program | Defender Controlled Folder Access blocked a change | Critical |
| Program installed that is not approved | inventory shows a new program not on the approved list | Warning |
| Agent stopped | the agent service was stopped while Windows kept running | Critical |
| Repeated failed Windows sign-ins | 5 failures on one computer within 15 minutes | Warning |
| Repeated failed sign-ins to this system | 5 failed dashboard/staff-app sign-ins (or set-ups) for one account name within 15 minutes | Warning |
| Computer not reporting | no contact for 60 minutes, **and it was not shut down normally** | Warning |
| Protection not working | the computer reports a required protection as FAILED | Warning |
| Computer waiting for approval | a computer registered and is waiting | Information |
| Audit log integrity problem | the automatic check (every 6 hours) finds the audit log altered | Critical |

The last four close by themselves ("Resolved by System") when the problem is gone. The audit-log alert is
raised once per broken entry.

**Computers that are switched off.**
- Office PCs are switched off at night, so "not reporting" alone would raise an alert every evening.
- The agent now tells the server when Windows shuts down (`SERVICE_CONTROL_SHUTDOWN`), and when the service
  is stopped by someone. It waits at most 5 seconds for the server; if it cannot reach it, the notice is sent
  at the next start.
- **Switched off normally:** no alert.
- **Agent stopped while Windows runs:** immediate Critical alert.
- **Silent without a notice** (power cut, crash, network cable, agent blocked or removed): "Computer not
  reporting" after the threshold.
- **Limitation:** a computer that is shut down normally and stays off for weeks raises no alert. The overview
  and the Computers page still show it as offline.

**Notification.**
- The dashboard shows the number of new alerts in the sidebar ("Security Alerts (3, 1 critical)") and on the
  Overview, refreshed every 30 seconds.
- Decision: polling instead of the live connection (SignalR) in the plan. It is simpler and needs no extra
  firewall rule; a delay of up to a minute is acceptable for this office.
- There is no e-mail or text message, because there is no mail server in the default deployment.

**Actions.**
- Acknowledge (someone is looking at it) and Resolve (with an optional note): administrators only.
- Auditors can see alerts and rules but not change them.
- Every action is recorded in the audit log.

## Reports

**Types:**
- Security summary (weekly/monthly totals)
- Blocked activity
- USB drives, phones and devices
- Sign-ins
- Company folder file access
- Installed software
- Software requests and installations
- Alerts
- Computers and protection status
- All security events
- Audit log (includes the result of an integrity check at export time)

**Where the numbers come from.** Reports read the same stored events, alerts, inventory and audit log that the
screens show. Nothing is estimated. An automated test checks that the report totals equal the stored events.

**Formats.**
- **CSV:** UTF-8 with a byte-order mark, so Excel shows accented characters correctly. Cells a spreadsheet would
  run as a formula (starting with `=`, `+`, `-`, `@`) get an apostrophe in front (protection against CSV
  injection).
- **PDF:** written by a small built-in writer (no third-party library and no licence question). It uses A4
  landscape and the standard Helvetica fonts that every PDF reader has, with wrapped table text, a repeated
  header row and page numbers.
  - **Limitation:** the standard fonts cover Western European characters only; other scripts appear as "?" in
    the PDF. Use CSV for those.
  - Checked with an independent PDF reader (pypdf, strict mode) and rendered to an image during development.

**Other rules.**
- **Time zone:** times are shown in the server's time zone, which is stated on each report.
- **Size limits:** at most 400 days per report and 20,000 rows per table; the report says so if rows were left
  out.
- **Access and audit:** administrators and auditors can create reports; staff cannot. Every export is written to
  the audit log (`report.export`) with the type, period, computer, format, row count and the file's SHA-256.

## Weekly and monthly summaries

- The server saves a security summary PDF for each completed week (Monday to Sunday) and each completed month,
  in `<data folder>\reports`.
- If the server was off, the latest missing week and month are created at the next run. Each saved summary is
  audited (`report.scheduled`).
- The dashboard lists them and can download them. Only file names from that list are accepted, so no path
  can be requested.
- No e-mail is sent; see above.

## Security events and audit log

- Events can now be filtered by severity, kind and date, and saved as CSV.
- The audit log's hash chain (ADR-0005) is now also verified automatically every 6 hours, with an alert if it
  is broken.
- **Limitation:** someone who can edit the database file could delete the newest audit entries without
  breaking the chain. Detecting that needs a copy of the chain's latest hash kept somewhere else. The audit-log
  report prints it ("Latest entry and its fingerprint"), so keeping those reports outside the server is enough
  to check later; the comparison is not automated.

## Not included

- E-mail/SMS notification
- Live push to the dashboard
- Reports in other languages
- Scheduled reports other than the security summary
- Charts in reports
