# Phase 5 part 2 test report

Date: 2026-09-28. Covers:
- Application Control
- Windows sign-in records
- company folder protection
- the BitLocker check

Windows CI run with all results below: https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36387901588 (commit `d879c9d`)

## Automated tests: all passed on Windows

| Test project | Passed on Windows |
|---|---|
| OfficeSecurity.Agent.UnitTests | 78 |
| OfficeSecurity.Server.IntegrationTests | 63 (+ the service end-to-end test in its own step) |
| OfficeSecurity.Server.UnitTests | 48 |
| OfficeSecurity.Policy.Tests | 23 |
| OfficeSecurity.Client.Core.Tests | 20 |

The **policy-definition check** confirmed the new ransomware-protection values against Windows' own Defender
definitions (WindowsDefender.admx):
- `EnableControlledFolderAccess` = 1
- the protected-folders list

## The real agent service on Windows (end-to-end test)

A policy with the part 2 protections was sent to the installed service. Part 1 and Phases 3–4 were checked again
in the same run and all passed.

| Check | Result |
|---|---|
| Protections applied and reported | after **30 s** |
| **Application Control, Audit mode** | Audit only. An unapproved program in a user's temp folder **still ran** and was reported: "Audit mode — would be blocked by Application Control: C:\Users\…\Temp\…\probe.exe" |
| **Application Control, Enforce mode** | On (verified) after 32 s |
| **Real effect:** the same program in a user folder | **Refused by Windows: "An Application Control policy has blocked this file." (error 4551)** |
| **Real effect:** the same program installed in Program Files | Ran normally (exit code 0) |
| Block reported to the server | yes ("Blocked by Application Control: …") |
| The agent service **restarted while Application Control was enforced** | Running again after 2 s and reporting normally |
| Application Control switched **off** | Policy removed after 18 s. The program in the user folder **runs again**, without a Windows restart. |
| **Windows sign-in records** | On (verified) |
| **Real effect:** wrong password for a test account | Reported: "Failed Windows sign-in for …\ocsstest (at the computer): wrong password." |
| **Real effect:** successful sign-in of the test account | Reported: "…\ocsstest signed in to Windows (at the computer)." |
| **File access records** | On (verified) |
| **Real effect:** a file in the protected folder opened | Reported: "…\runneradmin opened C:\OcssTest\Company\salaries.txt (program: …)" |
| **Ransomware protection** | Correctly reported as **not supported on this machine**: "Microsoft Defender Antivirus real-time protection is off on this computer". The build machine runs with Defender real-time protection off; nothing was changed. |
| **BitLocker check** | Correctly reported **FAILED — "NOT encrypted: C:, D:"**. The build machine's drives are not encrypted. |
| `uninstall` | Removed everything the agent had set: 21 Windows settings, 1 firewall rule, 3 audit settings, 1 folder audit entry. The Application Control policy had already been removed when switched off. |

## Defects found and fixed during testing

1. **Test defect:** the Windows `net user` command stops to ask a question when a password is longer than 14
   characters, so the test account was not created. The test now uses a shorter password (test code only).

No product defects were found in part 2 on the build machine.

## Not tested yet — check on a real office PC first

- **Ransomware protection's real effect.** The build machine has Defender real-time protection switched off.
  The settings are verified against Windows' definitions, but the blocking itself was not seen. Test on a PC
  where Microsoft Defender is the antivirus.
- **BitLocker on an encrypted PC** reporting "On". Only the not-encrypted case was seen.
- **Application Control on Windows 11 Pro desktops** with real office software. It was tested on Windows Server
  2025.
  - Run **Audit mode for several days first** and review the "would be blocked" events.
  - Per-user programs (e.g. installed in AppData) will be blocked in Enforce.
- **A standard (non-administrator) staff account** trying to run a blocked program. The test ran as an
  administrator; Windows applies Application Control to everyone.
- **Sign-in records from remote desktop and screen unlock.** Only "at the computer" sign-ins were produced.
- **Visual check of the new policy options** by a person.

## Still not available (reported as "Not available yet", no effect)

- Approved USB devices by hardware ID
- Bluetooth
- Wi-Fi restriction
- company folder permissions
- switching BitLocker on, with recovery keys
- backup
- Windows sign-in restriction to assigned computers
