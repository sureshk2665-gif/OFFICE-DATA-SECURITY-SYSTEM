# Phase 5 part 3 test report

Date: 2026-09-28. Covers:
- approved USB drives by hardware ID
- Wi-Fi restriction
- Bluetooth
- BitLocker recovery keys kept on the server
- the `check` self-check command

Windows CI run with the results below: https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36406541563 (commit `fec9a1c`).
All steps passed:
- build
- all test projects
- the policy-definition check
- the screen self-test
- the server and agent start-up tests
- the service end-to-end test
- the secret scan

## Automated tests

On Windows, the "Test" step passed for every project. The counts below are from the development machine (Linux,
where Windows-only tests are skipped), after the last change:

| Test project | Passed (Linux) |
|---|---|
| OfficeSecurity.Agent.UnitTests | 82 (9 Windows-only skipped) |
| OfficeSecurity.Server.IntegrationTests | 65 (1 Windows-only skipped) |
| OfficeSecurity.Server.UnitTests | 48 |
| OfficeSecurity.Policy.Tests | 23 |
| OfficeSecurity.Client.Core.Tests | 17 (3 Windows-only skipped) |

New tests cover:
- **Approved USB drives:**
  - the Windows values written
  - removal of unapproved USB storage devices
  - expiry, and temporary exceptions
  - the "approved drive connected" event
- **Wi-Fi:**
  - the safety rule (never applied while connected to an unlisted network)
  - tamper restore
  - undo
  - computers without Wi-Fi
- **Bluetooth:**
  - radio off, kept off, and back on
  - an adapter that was already off stays off
  - file-transfer blocking depending on the Application Control mode
  - the deny rule in the Application Control policy
- **Recovery keys:**
  - the agent sends them only when BitLocker is required, and only when they change
  - the server stores them encrypted: the plain-text key is not found in the database file
  - administrators and auditors are refused (403); a super administrator can reveal a key
  - each reveal is in the audit log, without the key
  - staff are refused

The **policy-definition check** on Windows passed for the new "Device Installation Restrictions" values
(DeviceInstallation.admx):
- AllowDenyLayered
- DenyDeviceIDs with its list
- AllowInstanceIDs with its list

## The real agent service on Windows (end-to-end test)

The Phase 3, Phase 4, part 1 and part 2 checks all passed again in the same run.

| Check | Result |
|---|---|
| **Bluetooth file transfer blocked** (with Application Control on Enforce) | Reported as "Partly on". **Real effect:** Windows refused to start its Bluetooth file transfer program `C:\Windows\system32\fsquirt.exe`: "An Application Control policy has blocked this file." (error 4551) |
| **Bluetooth file transfer, Application Control off** | Correctly reported as **FAILED**, with the reason: it needs Application Control on Enforce |
| **Approved USB drive** (a made-up drive ID; the build machine has no USB drives) | "Approved USB devices" **On (verified)** after 30 s. The Windows settings are in place: USB storage (`USB\Class_08`) is denied except the approved drive's two IDs, and the blanket read/write denial is replaced by "deny running programs" only. |
| **Approvals removed** | After 30 s: the blanket USB denial is back and the device installation settings are gone |
| **Wi-Fi restriction** | Correctly reported: "This computer has no Wi-Fi, so there is nothing to restrict." |
| **Bluetooth off (DisableRadio)** | Correctly reported: "No Bluetooth adapter on this computer. One added later is switched off within a minute." |
| **`OfficeSecurity.Agent.exe check`** | Ran and printed each section. It correctly found **2 problems** (drives C: and D: not encrypted) and exited with code 3. For USB it said "No USB drive or memory card is connected. Plug one in and run this check again." |
| `uninstall` | Removed everything the agent had set. The test confirmed the device installation settings are gone. |

Note: under "Phones and cameras" the check listed a portable device named "Temp" on the build machine. It is
listed for information only (not ✓ or ✗). What this virtual device is was not investigated; check this on a real
PC during the pilot.

## Defects found and fixed during this part

1. **Bluetooth: switching the setting off could switch on an adapter that was already off** before the agent
   touched it. Found in review. Fixed so the agent only switches back on the adapters it switched off, and a
   test was added. This fix is in commit `0029426`, after the CI run above; its Windows run was still in progress
   when this report was written.

## NOT tested yet — must be checked on a real office PC (use the pilot checklist in READ-ME-FIRST)

The build machine has no USB ports in use, no Wi-Fi and no Bluetooth. These have therefore **not** been seen
working:
- **A real approved USB drive working** while an unapproved one is refused. Also check that an unapproved drive
  that was used before is removed from Windows and does not come back.
- **The USB drive's ID in the dashboard:**
  - Some cheap drives have no serial number; their ID may change between USB ports.
  - Approve on the computer and port where it will be used, and check with `check`.
- **Wi-Fi filters on a real Wi-Fi adapter:**
  - The office network stays usable and a phone hotspot disappears.
  - The safety rule while connected to an unlisted network.
- **Switching a real Bluetooth adapter off and on.** Check that a Bluetooth keyboard or mouse is not needed
  first.
- **BitLocker recovery keys from a real encrypted PC** reaching the dashboard, and "Show selected recovery key".
  Only the not-encrypted case was seen on the build machine.
- **The new dashboard screens by a person:**
  - "Approve this USB drive"
  - the approved-drive list
  - the recovery keys card

  The screen self-test builds them, but nobody has looked at them.
- **Windows 11 Pro desktops.** The build machine runs Windows Server 2025.

## Still not available (reported as "Not available yet", no effect)

- company folder permissions
- switching BitLocker on
- backup
- Windows sign-in restriction to assigned computers
