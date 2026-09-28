# Phase 5 part 1 test report — security controls

Date: 2026-09-28
Windows CI run with all results below: https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36384631750 (commit `0c26011`)

## Automated tests (all passed on Windows)

| Test project | Passed on Windows | Linux (Windows-only tests skipped) |
|---|---|---|
| OfficeSecurity.Agent.UnitTests | 63 | 56 passed, 7 skipped |
| OfficeSecurity.Server.IntegrationTests | 63 (+ the service end-to-end test in its own step) | 63 passed, 1 skipped |
| OfficeSecurity.Server.UnitTests | 48 | 48 |
| OfficeSecurity.Policy.Tests | 23 | 23 |
| OfficeSecurity.Client.Core.Tests | 20 | 17 passed, 3 skipped |

## Every Windows setting checked against Windows' own policy definitions

A test reads the policy definition files that ship with Windows (`C:\Windows\PolicyDefinitions\*.admx`). It
confirms each value the agent writes is a defined policy setting. CI output:

| Value written by the agent | Windows policy |
|---|---|
| `{53f5630d-…}\Deny_Read`, `Deny_Write`, `Deny_Execute` = 1 | Removable Disks: Deny read / write / execute access |
| `{53f56308-…}\Deny_Read`, `Deny_Write` = 1 | CD and DVD: Deny read / write access |
| `{53f56311-…}` and `{53f5630b-…}` Deny_Read / Deny_Write = 1 | Floppy Drives / Tape Drives: Deny read / write access |
| `{6AC27878-…}` and `{F33FDC04-…}` Deny_Read / Deny_Write = 1 | WPD Devices: Deny read / write access |
| `Installer\DisableMSI` = 1 | Turn off Windows Installer = For non-managed applications only |
| `Appx\BlockNonAdminUserInstall` = 1 | Prevent non-admin users from installing packaged Windows apps |

## The real agent service on Windows (end-to-end test)

A policy with every new protection switched on was sent to the installed service:

| Check | Result |
|---|---|
| All six protections applied and verified by the service | after **30 s** |
| USB drives, memory cards, CD/DVD | On (verified) |
| Phones and cameras | On (verified) |
| Software installation by staff | Partly on (as designed: portable programs need Application Control) |
| Website restrictions | On (verified) |
| Program network blocking | On (verified) |
| Agent self-protection | On (verified) |
| **Real effect — Edge:** blocked site `example.com` | Edge showed **"This page is blocked. Your organization doesn't allow you to view this site"** |
| **Real effect — Edge:** allowed site `example.org` (same content) | Loaded normally ("Example Domain") |
| **Real effect — Firewall:** blocked copy of `curl.exe` to https://www.microsoft.com | **Failed to connect** (exit code 7) |
| **Real effect — Firewall:** the same program not on the list | Connected (exit code 0) |
| **Tampering:** USB block deleted from the registry by an administrator | Restored by the agent after **40 s** |
| **Tampering:** service permissions changed so every user could stop the agent | Restored by the agent after **60 s** |
| Critical `PolicyTamperAttempt` alerts received by the server | 2 (both changes) |
| Temporary exception for USB drives created in the dashboard API | USB block lifted after 16 s; phone block stayed on |
| Exception ended early | USB block back on after 30 s |
| Approved software installed by the agent while staff installs are blocked | Succeeded (exit code 0); the unsigned installer that required a signature was still refused |
| `uninstall` | Removed exactly the agent's settings ("21 Windows settings, 1 firewall rule"); the test confirmed they are gone |

The Phase 3 and Phase 4 checks passed again: enrollment, policy updates, restart after kill, sign-in ticket and
software installation.

## Defects found and fixed during testing

1. **Wrong Windows Installer setting (caught by the policy-definition test).** The first version used
   "Prohibit User Installs" (`DisableUserInstalls` = 2).
   - Windows defines only 0 (Allow) and 1 (Hide) for it, and "Hide" does not prevent per-user installs.
   - Replaced by "Turn off Windows Installer: for non-managed applications only" (`DisableMSI` = 1).
   - The end-to-end test confirms the agent's own approved installations still work with it on.
2. **Firewall rule lookup crashed when a rule did not exist.** Windows reports "not found" through a different
   error type than expected. Found by the Windows firewall test; fixed.
3. **Test defects** (test code only):
   - The Edge check looked for an error code that Edge does not show; it now compares page content.
   - The tampering step built an invalid permission string.

## Not tested yet — must be checked on a real office PC

- **A real USB drive, phone or CD/DVD.** The build machine has none.
  - The settings are verified and match Windows' definitions.
  - The blocking itself is not proven here, nor the case of an external USB hard disk.
- **A standard (non-administrator) staff account** trying to install an MSI or Store app. The build machine
  has no such account, so only the settings are verified.
- **Google Chrome and Mozilla Firefox.** Their policy values are written and verified; only Edge's blocking
  was tested for real.
- **Windows 10/11 Pro desktops.** The build machine runs Windows Server 2025.
- **An office network with a domain Group Policy** that sets the same values. The agent would overwrite them
  and report a Warning.
- **Visual check of the new screens by a person.** The screens are built by the self-test, but nobody has
  looked at them.

## Not available yet (reported as "Not available yet", no effect)

- Application Control (unapproved programs)
- approved USB devices by hardware ID
- Bluetooth
- Wi-Fi restriction
- company folder protection (permissions, access records, ransomware protection)
- disk encryption
- backup
- Windows sign-in restriction and sign-in records
