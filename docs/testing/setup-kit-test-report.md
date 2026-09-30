# Setup kit and combined program - test report

Runs: GitHub Actions 36674205199 and 36698147296 (setup wizard) (Windows Server 2025 runner, Windows PowerShell 5.1), all jobs green.

## What was built
- `OfficeSecurity.exe` - combined program: start screen with separate **Administrator** and **Staff** sign-ins
  (staff computers show only the Staff sign-in). Reuses the existing dashboard and staff screens.
- `OfficeSecurity-Setup-Kit` (zip) - ready program files + `MAKE-SETUP.bat` + `READ-ME-FIRST.txt`.
- `OfficeSecurity-Setup.exe` (142 MB) - made by `MAKE-SETUP.bat` with the C# compiler built into Windows.

## Executed and passed
| Check | Result |
|---|---|
| Combined program screen self-test (start screen, all administrator and staff screens) | PASS |
| MAKE-SETUP.bat makes the setup program (full kit, and stand-in files in a folder with spaces and brackets) | PASS |
| Setup program unpacks, runs install.ps1 with its arguments, removes its temporary files | PASS |
| Main office computer install: server Windows service running, starts automatically | PASS |
| Server answers on https://localhost:5443; first administrator setup offered | PASS |
| Firewall rule TCP 5443 (private and domain networks only) | PASS |
| Program files, role, desktop and Start menu shortcuts, entry in Settings > Apps | PASS |
| Update over an existing install: server runs again, data kept (same pairing code) | PASS |
| Staff install with a wrong pairing code: refused, no agent installed, nothing changed | PASS |
| Uninstall: service, firewall rule, program files and Apps entry removed; server data kept | PASS |
| Setup wizard window: every page builds (self-test) | PASS |
| Main office computer: program's Connect screen filled in (localhost + pairing code) | PASS |

## Defects found and fixed during testing
1. IExpress (first packaging choice) exited without creating a file on the runner: replaced by the
   Windows C# compiler.
2. Update failed with "file in use" because Windows reports a service stopped before its program has
   closed, and the server was left stopped. Setup now waits for the program to close, retries the copy,
   and restarts the previous version if an update still fails.

## Not tested (needs real office computers)
- Clicking through the setup wizard (CI checks that every page builds, and runs the same install steps
  with `-Quiet`); the uninstall-code prompt.
- A successful staff computer install through the setup program (needs a dashboard enrollment code
  and approval; the agent install itself is covered by the agent end-to-end test).
- Staff computer update in place and staff uninstall with a code through the setup program.
- Windows SmartScreen / "unknown publisher" warnings: the programs are not code-signed.
