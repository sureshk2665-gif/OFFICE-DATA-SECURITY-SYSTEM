# Phase 6 test report — alerts, reports, audit

Date: 2026-09-28. Windows CI run with the results below:
https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36415262281 (commit `8f8f979`).

Every step passed:
- build and all test projects
- the Windows policy-definition check
- the screen self-test, which now also builds the Security Alerts, Reports and Security Events screens
- the server and agent start-up tests
- the service end-to-end test
- the secret scan

## Automated tests

| Test project | Passed (development machine, Linux; Windows-only tests skipped) |
|---|---|
| OfficeSecurity.Agent.UnitTests | 82 (9 skipped) |
| OfficeSecurity.Server.IntegrationTests | 77 (1 skipped: the Windows service test, which ran in its own CI step) |
| OfficeSecurity.Server.UnitTests | 52 |
| OfficeSecurity.Policy.Tests | 23 |
| OfficeSecurity.Client.Core.Tests | 17 (3 skipped) |

New tests cover:
- **Alerts:**
  - one alert per problem, with repeats counted on it
  - Audit-mode reports do not raise alerts
  - old events do not flood a new installation
  - the "5 failed sign-ins in 15 minutes" rule, where resolved failures and failures outside the window do not count
  - a normal Windows shutdown raises **no** alert; a stopped agent raises a Critical alert
  - "computer not reporting" after 60 minutes, closing by itself when the computer reports again
  - "protection not working" opening and closing
  - a computer waiting for approval
  - repeated failed dashboard sign-ins for one account name
  - an altered audit log, found by the automatic check and raised only once
  - acknowledge and resolve: administrators only (auditors get 403), with an audit log entry for each
  - rule changes: validation, switching a rule off, changing the severity, audited
- **Reports:**
  - The "Blocked activity" report has exactly the stored blocking events (5 of 8 test events).
  - The security summary's totals equal the stored events, and its per-computer counts are correct.
  - Every report type is created as CSV and as PDF, including by an auditor; staff get 403.
  - Wrong requests are rejected: unknown report, wrong format, end before start.
  - A formula-like cell (`=HYPERLINK(...)`) is neutralised in CSV.
  - Every export is in the audit log with the SHA-256 of exactly the file downloaded.
  - Weekly and monthly summaries are saved once and can be downloaded; a path such as `..\office-security.db`
    is refused (404).
- **PDF writer:**
  - The PDF's internal index points exactly at every object, and the stream lengths are right.
  - Long tables continue on more pages with the header repeated.
  - Special characters are handled correctly.
  - During development a 300-row report was also opened with an independent PDF reader (pypdf, strict mode:
    9–12 pages, all text extracted correctly) and rendered to an image to check the layout.
- **Events:** filters by severity, kind and time.

## The real agent service on Windows (end-to-end test)

All the Phase 3–5 checks passed again in the same run. New in Phase 6:

| Check | Result |
|---|---|
| Alerts raised from the real events of the test | 4 alerts |
| **"Security agent stopped"** (Critical) | Raised after the test stopped the real service with `sc stop`. The service sent its stop notice through Windows' service control manager before stopping. |
| **"Protection tampered with"** (Critical) | Raised; it counts the tampering the test did (a deleted USB setting and weakened service permissions). |
| **"Program blocked"** (Warning) | Raised ×3 for programs Application Control blocked |
| **"Protection not working"** (Warning) | Raised: BitLocker is not on, on the build machine |
| **Block reported to the server** (checked properly now; see below) | "Blocked by Application Control: …\probe.exe" arrived **12 s** after the block |
| **A program blocked just before the agent was stopped** | Reported **3 s** after the agent started again |
| Reports built from these events | security summary PDF (9.9 KB); blocked activity CSV (7 rows) and PDF; alerts PDF. Downloadable from the run's **sample-reports** artifact. |
| "Computer not reporting" | Correctly **not** raised (the computer kept reporting) |

## Defects found and fixed

1. **A wrong test in Phase 5 part 2.**
   - The check for "the block was reported to the server" also matched the earlier Audit-mode report ("would be
     blocked"). It therefore never proved that an enforced block reached the server.
   - The new "Program blocked" alert showed this: in one run (commit `91fdbae`) no such alert appeared.
   - The test now requires the real "Blocked by Application Control" event and records Windows' own Code
     Integrity log if the event is missing. The Phase 5 part 2 report has been corrected.
   - In the three runs since (`98aa5eb`, `fe1b5cd`, `8f8f979`) the block was reported every time, also when the
     agent was stopped right after the block.
   - **The one missing report in `91fdbae` is not explained.** In that run the agent service was stopped about
     1–2 seconds after the block. Watch for it in the pilot: an enforced block should appear in Security Events
     within a minute.
2. **Installer refused for a missing signature was reported as "tampering" (Critical).**
   - This happened when an administrator required a signature but the installer had none. That is a setting
     problem, not an attack, and the Critical "tampered with" alert was misleading.
   - It is now "Installation blocked" (Warning). A file whose fingerprint or signature does not match is still
     reported as tampering.
3. **Test sessions expiring.** Tests that move the clock hours ahead now sign in again (test code only).

## Not tested / limitations

- **Nobody has looked at the new screens yet.** The screen self-test builds them, but a person should check
  Security Alerts, Reports and the Security Events filters.
- **A real Windows shutdown** (the "switched off normally, no alert" case) was tested with the agent's own
  shutdown notice in the integration tests, not by shutting down a real PC. Check it at the pilot: shut a PC
  down overnight and confirm no "not reporting" alert the next morning.
- **No e-mail or text messages.** Alerts are seen in the dashboard only (ADR-0011).
- **PDF text is limited to Western European characters.** Other scripts appear as "?"; the CSV keeps every
  character.
- **Deleting only the newest audit entries** is not detected automatically. The audit-log report prints the
  latest fingerprint to keep elsewhere.
