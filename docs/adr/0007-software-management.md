# ADR-0007: Software inventory, installation requests and approved deployment (Phase 4)

- Status: Accepted (2026-09-28).

## Decisions

1. **Inventory source.** The agent reads the programs listed in Windows "Installed apps", from the registry's
   Uninstall keys:
   - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, in both the 64-bit and 32-bit views
     ("Installed for: Machine")
   - the same key under each loaded user profile, `HKU\S-1-5-21-…` ("Installed for: User")

   It skips entries hidden from "Installed apps": system components, updates and hotfixes, and child entries.
   The list is reported with the other inventory every 15 minutes, and right after an installation. No file
   system scan and no process monitoring take place.

2. **Change detection.** The server stores the first report from a computer as its **baseline** and raises no
   events for it. After that:
   - a program that appears raises `SoftwareInstalled`. It is a *Warning* when the program is not on the
     approved list, *Information* otherwise.
   - a program that disappears raises `SoftwareRemoved`.

3. **Approved list.** An administrator lists approved programs by name and, optionally, publisher. An
   installed program counts as approved when its name *starts with* the approved name (case-insensitive), so
   "Microsoft Office" covers "Microsoft Office Professional Plus 2021". If a publisher is given, it must match
   exactly.

   Phase 4 only **reports** unapproved programs. Nothing is removed or blocked; blocking unapproved
   applications (application control) is Phase 5.

4. **Installer files.** Administrators upload `.msi` or `.exe` installers in the dashboard.
   - **Before upload**, the dashboard checks the file's Authenticode signature on the administrator's
     computer:
     - A valid signature → its signer name is stored with the file.
     - An unsigned file → can only be uploaded if the administrator ticks "I trust this unsigned file".
     - A broken signature → the file is refused.
   - **The server** streams the file to `packages\{id}.pkg` in its protected data folder (up to 4 GB) and
     records its SHA-256 fingerprint.
   - **EXE installers** must have silent install options. Otherwise they would wait for someone to click.

5. **Deployment jobs.** An installation job is created only by an administrator (Admin or SuperAdmin role),
   either directly ("Install on computers…") or by approving a staff request, and only for approved computers.
   The agent learns of jobs through the heartbeat (`PendingJobs`) and fetches them over mutual TLS.
   - A computer can only see and download **its own** jobs.
   - It can download a job's installer only after it has *started* the job.
   - Starting a job counts an attempt. After 3 attempts (e.g. repeated restarts during installation) the job
     is marked Failed.
   - Queued jobs can be cancelled. Used installer files cannot be deleted, so the record stays complete.

6. **Verification on the computer — nothing unverified is ever run.** The agent downloads the installer into
   its protected data folder, under a file name it builds itself (server-supplied names cannot escape the
   folder). It then checks, in order:
   1. The size equals the approved size (a larger download is aborted while downloading).
   2. The SHA-256 fingerprint equals the approved fingerprint.
   3. The Authenticode signature, checked with Windows `WinVerifyTrust`:
      - A signer was approved → the signature must be valid **and** the signer must match exactly.
      - "Unsigned allowed" → a valid, missing or uncheckable signature is accepted. A *broken* signature
        never is.
      - Neither → a valid signature is required.

   If any check fails:
   - the installer is deleted without being run
   - the job is reported Failed with the reason
   - a *Critical* `PolicyTamperAttempt` event is raised

7. **Running the installer.** Only the verified file runs, as LocalSystem, with no shell:
   - **MSI:** `%SystemRoot%\System32\msiexec.exe /i "<file>" /qn /norestart /l*v "<log>" [admin options]`
   - **EXE:** `"<file>" <admin silent options>`

   Results:

   | Exit code | Status |
   |---|---|
   | 0 | Succeeded |
   | 3010 / 1641 | SucceededRebootRequired |
   | anything else | Failed. For MSI, the error lines from msiexec's log are added. |

   MSI installations never restart the computer (`/norestart`). For EXE installers this depends on the silent
   options the administrator enters.

   Installations stop after 60 minutes. They run in the background, so heartbeats, policy updates and event
   uploads continue meanwhile.

8. **Staff requests.** A staff member asks for software in the staff app: the program name and a reason.
   - The request records the computer the staff member signed in on, as confirmed by the agent's one-time
     computer ticket.
   - Each staff member may have at most 10 pending requests.
   - An administrator approves a request by choosing an uploaded installer and the target computer (the
     request's computer by default), or rejects it with a note.
   - The staff member sees the decision, the note and the installation status.

9. **Audit.** Every catalog change, upload (with SHA-256 and signer), deployment, cancellation, approval,
   rejection and installation result is written to the append-only audit log.

## Why

- The registry Uninstall keys are what Windows itself shows in "Installed apps". They are the supported,
  documented source and need no WMI `Win32_Product` query, which triggers MSI repair actions.
- Checking the hash **and** the signature on the endpoint means neither a compromised server disk nor a network
  attacker can substitute a different program.
- Administrator-only job creation keeps the agent free of any general remote-command capability (threat
  model: "Agent used as a remote-access backdoor").

## Consequences and limitations

- An administrator can install any program they upload, including an EXE with arbitrary silent options, and it
  runs as LocalSystem. That is inherent to software deployment. It is limited to administrators and fully
  audited, and staff can never trigger it.
- Signature revocation is not checked online (offices without internet access). A revoked but otherwise valid
  signature is accepted.
- Programs that do not register in "Installed apps" (portable programs, some Microsoft Store apps) do not appear
  in the inventory.
- Uninstalling software remotely is not provided in Phase 4.
