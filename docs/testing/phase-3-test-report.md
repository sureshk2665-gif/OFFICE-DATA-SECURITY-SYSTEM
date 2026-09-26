# Phase 3 test report

Date: 2026-09-26

| Windows CI run | Commit | What it covered |
|---|---|---|
| https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36243939844 | `b17c4f9` | Agent service end-to-end test |
| https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36244260020 | latest Phase 3 code | Screens and all tests |

## Automated test results

| Test project | Passed | Skipped | Failed |
|---|---|---|---|
| OfficeSecurity.Server.UnitTests | 48 | 0 | 0 |
| OfficeSecurity.Server.IntegrationTests | 45 | 1 | 0 |
| OfficeSecurity.Policy.Tests | 23 | 0 | 0 |
| OfficeSecurity.Agent.UnitTests | 17 | 2 | 0 |
| OfficeSecurity.Client.Core.Tests | 16 | 0 | 0 |

These counts are from Linux. The 3 skipped tests are Windows-only:
- On Windows CI, the 2 agent tests (TPM/machine key store, fake-agent pipe rejection) **run and pass**.
- The Windows Service end-to-end test is skipped in the general test step. It **runs and passes** in its own
  CI step against the published `OfficeSecurity.Agent.exe`.

## Windows Service end-to-end test (real service on the CI Windows machine)

The published `OfficeSecurity.Agent.exe` was installed as a Windows Service against a real HTTPS server.
Results from the CI log:

| Step | Result |
|---|---|
| `install --server … --pairing-code … --enrollment-code …` | exit 0, registered immediately |
| Approval in the server → computer online, Windows inventory received, policy v1 applied | after 18 s |
| Policy changed in the server → new version applied by the service | after 30 s |
| Service configured Automatic start and restart-on-failure (`sc qc`, `sc qfailure`) | verified |
| Service process killed → Windows restarted it (new PID) | after 6 s |
| Staff-app pipe: status from the genuine installed agent (server identity verified) | passed |
| Sign-in ticket from the agent → assigned staff member signed in | passed |
| Start-up events from both service runs uploaded | passed |
| `uninstall` → service removed | exit 0; `sc query` reports the service does not exist (1060) |

The agent `inventory` command was also run on Windows, reading details through WMI:
- Windows name and build, manufacturer and model, serial number
- processor, memory and system disk size
- TPM (reported absent on the CI machine) and workgroup

## Other things the tests cover

### Enrollment
- A computer only becomes trusted after administrator approval.
- Invalid and reused enrollment codes are refused.
- Rejected and removed computers are refused.
- Certificates not issued by the server are refused, both in-memory and over real TLS.

### Mutual TLS (real Kestrel server)
- An agent enrolls, is approved and reports using its client certificate.

### Policies
- Signed per-computer policies with strictly increasing versions.
- Editing a policy, or assigning a different one, reaches the agent.
- The agent rejects a policy that:
  - is signed with a different key
  - targets another computer
  - is an older version
- A tampered policy cache file is rejected at start-up, deleted and reported.
- The last valid policy stays enforced after a restart while the server is offline.

### Offline operation
- Events are kept while the server is unreachable and uploaded when it returns.
- Uploads are idempotent: duplicates are stored once.
- The event store is capped.

### Devices
- Device inventory is reported.
- USB connection and disconnection events are logged.

### Staff restricted to computers
- Without a ticket → refused.
- Ticket from another computer → refused.
- Ticket from an assigned computer → allowed.
- A ticket can be used only once.

### Policy management rules
- The default policy cannot be deleted.
- Invalid settings and duplicate names are rejected.
- Auditors are read-only.

### Screen self-test (Windows)
All dashboard screens are built, including the new Computers (with detail and install instructions), Security
Policies (editor) and Security Events pages, plus all staff-app screens.

## Defects found and fixed during Phase 3 testing

1. **Agent key storage failed on computers without a TPM.**
   - Cause: `CngKey.Exists` on the Microsoft Platform Crypto Provider throws "device not ready" instead of
     returning false.
   - Found by: the Windows-only key store test in CI.
   - Impact: without the fix, the agent could not have started on PCs without a TPM chip.
   - Fix: treat an unavailable TPM provider as "no key there" and use the software provider.
2. **A new endpoint was not registered as anonymous.** The authorization test flagged two new anonymous
   endpoints, the agent enrollment endpoints. They were reviewed and added to the explicit anonymous list;
   they are protected by the enrollment code / poll token and by rate limits.
3. **Test helper defect.** A test helper used an untrusted HTTPS client in real-TLS mode (test code only).

## Not tested yet

- **Real office hardware and Windows 10/11 Pro desktops.** CI uses Windows Server 2025 without a TPM, so the
  TPM-backed key path has not been exercised.
- **A reboot** of a computer with the agent installed. Start type Automatic is verified, but an actual restart
  of Windows is not.
- **A real USB drive, phone or Bluetooth device** being detected. The WMI query runs, but the CI machine has no
  such devices; detection logic is tested with simulated devices.
- **A standard (non-administrator) user trying to stop the service.** The service permissions are set, but
  this attempt is not run automatically.
- **Two PCs over a real office network,** including the Windows Firewall rule for port 5443.
- **Visual check of the new screens** by a person.
- **Blocking.** No security control is enforced yet (Phase 5).
