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

## Residual risks (accepted, documented to owner)
Local administrators can disable controls. Screenshots, photographs and uploads to *allowed* websites cannot be
fully prevented without extra DLP products (plan §14).
