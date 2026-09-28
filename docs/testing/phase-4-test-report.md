# Phase 4 test report

Date: 2026-09-28

| Windows CI run | Commit | What it covered |
|---|---|---|
| https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36380266291 | `a64ce55` | All tests, including a real MSI installed by the Windows Service |
| https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36380719412 | `37e40d4` | New screens (screen self-test) and all tests |

## Automated test results

| Test project | Passed | Skipped | Failed |
|---|---|---|---|
| OfficeSecurity.Server.UnitTests | 48 | 0 | 0 |
| OfficeSecurity.Server.IntegrationTests | 55 | 1 | 0 |
| OfficeSecurity.Policy.Tests | 23 | 0 | 0 |
| OfficeSecurity.Agent.UnitTests | 30 | 2 | 0 |
| OfficeSecurity.Client.Core.Tests | 17 | 3 | 0 |

These counts are from Linux. The skipped tests are Windows-only. On Windows CI:
- the 3 signature-check tests and the 2 agent tests **run and pass** in the general test step
- the Windows Service end-to-end test **runs and passes** in its own step

## Windows Service end-to-end test: software installation (real service, real msiexec)

A small test MSI ("OCSS Test Package", unsigned) is built in CI with the WiX Toolset. The installed agent
service then handles two installations. Results from the CI log:

| Step | Result |
|---|---|
| Installer uploaded with "signed by CN=Contoso Ltd required" → deployed | **Not run.** Reported Failed: "it has no digital signature and unsigned installers were not allowed for it". Critical event raised. |
| Same installer uploaded with "unsigned allowed" → deployed | Installed by msiexec silently: **Succeeded, exit code 0**, 14 s after deployment |
| New program appears in the computer's inventory, as approved, version 1.0.0 | after 16 s |
| `SoftwareInstalled` event received | passed |

All Phase 3 service checks passed again: install; approval (online after 18 s); policy update (30 s); restart
after the process was killed (6 s); staff sign-in ticket; uninstall.

## Other things the tests cover

### Approved list and installer upload
- Duplicate and empty names are refused.
- An uploaded file keeps its exact SHA-256 fingerprint and size.
- Refused uploads:
  - wrong file type
  - EXE without silent options
  - unsigned without "allow unsigned"
  - path characters in the file name
  - empty file
- A program with installers, or an installer already used, cannot be deleted.
- Uploads are audited with their fingerprint.
- **Real HTTPS:** a 40 MB installer is uploaded through the dashboard's client, above the web server's default
  30 MB limit, and installed on the agent over mutual TLS. A check confirmed the test fails without the fix.

### Staff requests
- A staff member signed in through the agent asks for a program. The request records that computer.
- The administrator sees it on the overview and in the list and approves it with an installer.
- The agent downloads exactly the uploaded file and runs it once. The request shows "Succeeded" in the
  staff member's list.
- A rejected request shows the note and installs nothing.
- A decided request cannot be decided again.
- A request from no managed computer cannot be approved without choosing an approved computer.

### Deployments
- Installations go only to approved computers.
- Deploying the same installer twice while queued creates one installation.
- A cancelled installation is not run.
- A failed installation (exit code 1603) is recorded as Failed, with a Warning event.

### Agent isolation
- A computer cannot see, start, download or report another computer's installation.
- An installer cannot be downloaded before the job is started.
- After 3 interrupted attempts the installation is marked Failed and no longer offered.

### Installer verification on the computer (agent unit tests)
Never run:
- a changed file (fingerprint mismatch)
- a file of the wrong size
- a file larger than approved (download aborted)
- a file signed by another publisher
- an unsigned, broken or unverifiable signature, unless unsigned was allowed
- a broken signature, even when unsigned was allowed

Also tested:
- A file name sent by the server cannot place the file outside the agent's folder.
- The installer file is deleted afterwards.

### Signature check (Windows only)
- A Microsoft-signed .NET file is Valid, with its signer name.
- A modified copy of it is Invalid.
- A plain file is NotSigned.

### Inventory
- The first report is a baseline, with no events.
- A newly installed unapproved program raises a Warning event; a removed program raises an event.
- Approved and unapproved programs are flagged correctly, including name-prefix matching.
- The overview counts computers with unapproved programs.

### Access control
- Staff and auditors cannot change the approved list, upload, deploy or approve.
- Staff cannot read other people's requests or the inventory. Auditors can read them.
- Administrators cannot use the staff request or agent endpoints.

### Screen self-test (Windows)
All screens are built:
- Software Management, with every panel open
- Installation Requests, with the decision panel
- the computer detail page, with installed programs and installations
- the staff app home page, with the request form and "My requests"

## Defects found and fixed during Phase 4 testing

1. **The software request list failed with a server error (500).** The database layer could not translate the
   combined request query. Found by the new integration tests. Fixed by loading the related names separately.
2. **Large installer uploads would have been refused.** The web server's default limit is 30 MB. The upload
   endpoint now raises the limit to 4 GB for that request only. Found by the real-HTTPS test.
3. **Uploads from the dashboard would have been cut off after 20 seconds** by the normal request time limit.
   Uploads now use a connection without that limit. A download that stalls for 2 minutes on the agent is
   abandoned and retried later.

## Not tested yet

- **A signed commercial installer**, such as Adobe Reader or 7-Zip, installed end to end. The signature
  check itself is tested on Windows with Microsoft-signed files, and the installation path with an unsigned
  test MSI.
- **EXE installers.** Their silent options are publisher-specific; only MSI was run for real.
- **Per-user programs.** The registry reading of per-user programs (`HKU`) ran on CI, but no per-user program
  was installed there.
- **Uploads of several GB** over a real office network (tested up to 40 MB).
- **Visual check of the new screens** by a person, including the file picker dialog.
- **Real office hardware, Windows 10/11 Pro, a reboot during an installation.**
- **Blocking unapproved programs.** Not built: they are reported only (Phase 5).
