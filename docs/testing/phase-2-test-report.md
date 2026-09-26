# Phase 2 test report

Date: 2026-09-26 · Commit tested: `2682d07` · Windows CI run: https://github.com/sureshk2665-gif/OFFICE-DATA-SECURITY-SYSTEM/actions/runs/36226145599

## Environments

| Where | What ran |
|---|---|
| Linux build container (development) | Full build, all automated tests |
| GitHub Actions `windows-latest` | Full Release build (0 warnings, 0 errors), all automated tests, screen self-tests of both desktop apps, start-up test of the published `OfficeSecurity.Server.exe`, gitleaks secret scan |

## Automated test results (Windows CI, identical on Linux)

| Test project | Passed | Failed |
|---|---|---|
| OfficeSecurity.Server.UnitTests | 48 | 0 |
| OfficeSecurity.Server.IntegrationTests | 33 | 0 |
| OfficeSecurity.Policy.Tests | 23 | 0 |
| OfficeSecurity.Client.Core.Tests | 16 | 0 |
| OfficeSecurity.Agent.UnitTests | 4 | 0 |
| **Total** | **124** | **0** |

## What the tests cover

### Passwords and codes
- PBKDF2 hashing: salts, wrong or malformed hashes, rehash
- The password policy
- TOTP against the RFC 6238 test vectors, including clock drift and replay rejection
- Base32 against the RFC 4648 test vectors
- The format and uniqueness of setup codes and tokens
- Pairing codes

### First-time setup
- Only the server-generated code is accepted
- The account needs a valid authenticator code before it is active
- Setup cannot be repeated

### Administrator sign-in
- Both password and two-step code are required
- A two-step code cannot be reused
- Lockout after 5 failures, and unlock after 15 minutes (controlled clock)
- The idle timeout ends the session
- Signing out ends the session
- Changing the password signs out other sessions

### Staff accounts
- Creation → setup code → activation → sign-in
- Duplicate employee codes are rejected
- A setup code works only once
- Disabling an account ends its sessions immediately
- Enabling works
- A reset invalidates the old password
- Search, status filter, paging and overview counts

### Authorization
- The set of anonymous endpoints matches an explicit list
- Every other endpoint returns 401 without a session
- Staff get 403 on administrator endpoints
- An Auditor can read but not change anything
- An Admin cannot manage administrators
- A SuperAdmin cannot disable themselves or the last SuperAdmin

### Audit log
- Actions are recorded
- No passwords, setup codes or typed wrong passwords appear in the log
- The raw database file contains no plain-text passwords or codes
- The database triggers reject UPDATE and DELETE
- Direct tampering is detected by chain verification

### HTTPS (real Kestrel server)
- The correct pairing code works
- A wrong pairing code is rejected
- A client pinned to a different server refuses to connect
- An address not covered by the certificate is rejected
- A full administrator and staff flow runs through the desktop client library

### Certificate authority
- The HTTPS certificate chains to the CA and covers the host names
- Private keys are not stored in readable form
- The CA is reused after a restart
- A new certificate is issued when host names change or expiry nears

## Windows-only checks in CI

### Screen self-test (`--smoke-test`)
- All 24 administrator dashboard screens and sections built successfully.
- All 5 staff application screens built successfully.

This proves each screen's layout loads. It does **not** prove a screen looks right or behaves correctly
when clicked.

### Server start-up test

The published `OfficeSecurity.Server.exe` was run on Windows:
- It started and served HTTPS on port 5443, using Windows TLS and DPAPI-protected keys.
- It reported that first-time setup is required.
- It wrote the setup code, connection information and database files.
- It returned 401 for the staff list without a session.

## Defects found and fixed during Phase 2 testing

1. **Audit chain broke after saving.**
   - Cause: the standard EF Core date conversion drops sub-millisecond precision, so the stored timestamp
     no longer matched the hashed one.
   - Found by: `Direct_tampering_is_detected_by_chain_verification`, which failed on an untouched log.
   - Fix: a lossless UTC-ticks converter.
2. **Test password was rejected.** A test password contained the user name; the password policy correctly
   rejected it. The test data was changed; the product was not.

## Not tested yet (must be checked manually or in later phases)

- **Visual appearance and clicking through the screens on a real Windows desktop.** Nobody has looked at the
  screens yet. The owner's walkthrough (READ-ME-FIRST.txt, steps 1–6) is the first real check.
- **Scanning the QR code with a real phone app.** The QR content is covered by tests; an actual scan is not.
- **Data-folder permissions.** No test confirms that a standard Windows user is denied access to
  `C:\ProgramData\OfficeSecurity\Server`.
- **Connecting a second PC over the office network,** including the Windows Firewall prompt for port 5443.
- **Running the server as a Windows Service.** Service registration arrives with the installer in Phase 7;
  in Phase 2 the server runs as a console program.
- **Restoring from a backup.**
