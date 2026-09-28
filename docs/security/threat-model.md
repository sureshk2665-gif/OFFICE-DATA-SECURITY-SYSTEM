# Threat model (STRIDE) — Phase 1

## Assets
Company files · policy integrity · audit trail integrity · admin credentials · device identities (certificates) ·
server CA and policy-signing keys · staff credentials.

## Actors
| Actor | Trust |
|---|---|
| Administrator | Trusted; still audited. |
| Staff member (standard Windows user) | Authorized for their work only; potentially curious or careless, occasionally malicious. |
| Local administrator on a staff PC | **Out of scope for prevention**. Only detection is possible (the agent goes silent, which raises an alert). |
| Visitor / rogue device on the LAN | Untrusted. |
| Stolen laptop / disk | Untrusted; mitigated by BitLocker. |

## Trust boundaries
1. Staff app ↔ agent (named pipe on the same PC)
2. Agent ↔ server (LAN, mTLS)
3. Admin dashboard ↔ server (LAN, TLS + JWT + MFA)
4. Server ↔ database file (same host, NTFS ACL)
5. Removable media / network ↔ staff PC (the enforcement boundary)

## Threats and mitigations

| STRIDE | Threat | Mitigation | Phase |
|---|---|---|---|
| **S**poofing | Rogue PC pretends to be an enrolled computer | mTLS client certificates; single-use enrollment codes; admin approval of pending computers | 3 |
| S | Attacker guesses admin password | PBKDF2 hashing, lockout after 5 failures, TOTP two-step login, login audit + alert | 2 |
| S | Fake server on the LAN (DNS/ARP spoofing) sends policies | Agent pins the server CA; policies are separately signed and the signing key is pinned | 3 |
| **T**ampering | Staff edits the local policy cache to loosen rules | Cache is ACL'd to SYSTEM/Administrators; signature is verified on every load; an invalid cache falls back to the last good copy + alert | 3 |
| T | Staff stops or deletes the agent | Service DACL (stop/config reserved to SYSTEM/Admins); install folder ACL; SCM auto-restart; missing heartbeat → "agent unavailable" alert | 3/5 |
| T | Someone edits the audit log in the DB file | UPDATE/DELETE triggers; SHA-256 hash chain; scheduled verification; DB file ACL | 6 |
| T | Tampered software package pushed for remote install | SHA-256 + Authenticode signer checked against the approved record before execution | 4 |
| **R**epudiation | Admin denies approving a request or changing a policy | Every admin action is written to the append-only audit log with actor, time and source IP | 2+ |
| **I**nformation disclosure | Traffic sniffed on LAN | TLS 1.2+ only (TLS 1.3 preferred); no plaintext HTTP endpoints | 2 |
| I | Data copied to USB / phone / cloud | See controls C1–C14 in the plan; residual risks listed in plan §14 | 5 |
| I | Secrets leaked from the repository | No secrets in code or installers; secret scanning in CI; runtime secrets are generated on the server and DPAPI-protected | 1+ |
| I | Excessive personal data collected | No screen, keystroke, webcam or microphone capture; only event metadata; optional usage stats off by default | all |
| **D**enial of service | Event flooding from one agent | Per-device rate limits and batch size limits on the API; alert on flood | 3/6 |
| D | Server offline | Agents keep enforcing cached policy and queue events locally | 3 |
| **E**levation of privilege | Staff abuses the agent's SYSTEM privileges through the pipe | Pipe exposes **read-only** status queries only; strict message schema; no command execution endpoints | 3 |
| E | Staff account calls admin API | Role-based authorization on every endpoint; an automated authz-matrix test covers all endpoints | 2 |
| E | Agent used as a remote-access backdoor | No shell / arbitrary command API by design; installs are limited to admin-approved, hash-verified packages | 4 |

## Phase 2 status
Implemented and tested:
- password hashing, TOTP two-step for administrators, lockout, sign-in rate limiting
- server-side revocable sessions and role authorization with a deny-by-default fallback
- the append-only, hash-chained audit log
- the private CA with pinned HTTPS and pairing codes

Implemented, but only partly verified:
- The ACL-restricted data folder and DPAPI-protected keys on Windows are exercised by the Windows
  server start-up test in CI.
- No automated test yet checks that the folder permissions actually exclude standard users. This must be
  checked manually on a test PC.

Known gap: truncating the newest audit entries is not yet detectable. An external anchor (Windows Event
Log) is planned for Phase 6.

## Phase 4 status
Implemented and tested (automated; see the Phase 4 test report):
- Installers run only when their size, SHA-256 fingerprint and Authenticode signer match the administrator's
  approved record. Any mismatch → not run + Critical event.
- Only administrators create installation jobs, only for approved computers. A computer can see and download
  only its own started jobs.
- Staff can request software, but cannot create jobs or read other people's requests or the inventory.
- Server-supplied file names cannot place the download outside the agent's protected folder.

Accepted risks (ADR-0007):
- An administrator can run any uploaded installer as LocalSystem. This is limited to administrators and audited.
- Signature revocation is not checked online.
- The file is verified and then run from the agent's data folder. Between those two steps only SYSTEM and
  administrators can modify it.

## Phase 5 part 1 status (ADR-0008)
Implemented:
- **Blocking:** USB drives, memory cards, CD/DVD and phones are blocked through Windows Removable Storage Access
  policies. Staff per-user MSI and packaged-app installs are blocked. Edge, Chrome and Firefox get website
  lists and have private browsing disabled. Windows Firewall rules block the listed programs.
- **Tampering:** every protection is re-checked every minute. A change by anyone else is reversed and raises a
  Critical `PolicyTamperAttempt` event. The service's own start, restart and permission settings are checked
  and restored the same way.
- **Exceptions** are time-limited, administrator-only, part of the signed policy (staff cannot forge them) and
  audited.

Accepted limitations:
- **Local administrators** can undo settings between checks or stop the agent. Staff must use standard Windows
  accounts; otherwise they can defeat any client-side control.
- **Other routes around the controls:**
  - Portable programs, other browsers and copies of blocked programs are only stopped by Application Control
    (part 2).
  - Website blocking cannot stop uploads to *allowed* websites.
  - External USB hard disks reported as fixed disks may not be covered (to be verified with hardware).

## Phase 5 part 2 status (ADR-0009)
- **Application Control:** programs brought in by users are blocked (Enforce) or reported (Audit). Windows
  enforces it in the kernel; removing the policy is detected and reversed within a minute.
- **Records:** Windows sign-ins, failed sign-ins and file access in company folders are recorded from Windows'
  own Security log. A local administrator can clear that log, but events already forwarded stay on the server.
- **Ransomware protection** relies on Microsoft Defender being the active antivirus.
- **Accepted:**
  - scripts are not restricted
  - programs in admin-writable folders are trusted
  - BitLocker is only checked, not switched on

## Phase 5 part 3 status (ADR-0010)
- **Approved USB drives** are identified by Windows' device instance ID, which includes the drive's serial number.
  A drive without a unique serial number, or a device built to copy another drive's IDs, could pass as approved.
  Only approve company drives, and prefer drives with a hardware serial number.
- **Wi-Fi restriction** hides other networks (Windows WLAN filters). The safety rule means a computer already on an
  unlisted network keeps using it until someone adds it or it disconnects; this is reported. Cable networks and
  USB network adapters (phone tethering over a cable) are not covered.
- **Bluetooth file transfer** is blocked by denying Windows' own transfer program under Application Control.
  Other Bluetooth file programs would also need blocking by Application Control; switching the radio off covers
  everything.
- **BitLocker recovery keys** are sensitive: anyone with a key can unlock that drive. They are stored encrypted
  with the server's data-protection key, only super administrators can show one, and every reveal is in the
  tamper-evident audit log. Whoever can read the server's data folder *and* its protection keys could decrypt
  them; keep the server PC and its backups secured.

## Residual risks (accepted, documented to owner)
Local administrators can disable controls. Screenshots, photographs and uploads to *allowed* websites cannot be
fully prevented without extra DLP products (plan §14).
