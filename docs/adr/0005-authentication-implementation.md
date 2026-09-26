# ADR-0005: Authentication implementation (Phase 2)

- Status: Accepted (2026-09-26). Amends ADR-0003 items 4–5 and the "Tokens" row of the plan's technology table.

## Decisions

1. **Server-side sessions instead of JWT.**
   - A sign-in returns a random 256-bit bearer token. Only its SHA-256 hash is stored (`sessions` table).
   - Every request is checked against the database. This means disabling an account, resetting it, changing
     a password or signing out takes effect **immediately**. With self-contained JWTs it would only take
     effect when the token expires.
   - The load (≤100 PCs) makes the per-request lookup negligible.
   - Session limits:

     | Account | Absolute lifetime | Idle timeout |
     |---|---|---|
     | Administrator | 8 h | 30 min |
     | Staff | 12 h | 4 h |

   - No extra dependency is needed.
2. **Password hashing:** PBKDF2-HMAC-SHA512 with **210,000 iterations** (the OWASP 2023+ recommendation for this
   algorithm), 16-byte salt and constant-time comparison.
   - ADR-0003 said 600,000 iterations; that figure is the OWASP value for PBKDF2-HMAC-*SHA256*.
   - Hashes are upgraded automatically at sign-in if the iteration count is raised later.
3. **Password rules (NIST SP 800-63B):**
   - 12–128 characters
   - not on a common-password block-list
   - not containing the user name or employee code
   - not overly repetitive
   - no forced symbol/number rules
4. **Administrator two-step verification:**
   - Uses RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s, ±1 step of clock drift), which works with Microsoft and
     Google Authenticator.
   - A used code cannot be replayed: the last accepted time step is stored.
   - Secrets are encrypted with ASP.NET Core Data Protection. On Windows the keys are protected with
     machine-scope DPAPI.
   - The first administrator is created with a one-time **bootstrap code**. The server shows it at start-up
     and writes it to `FIRST-ADMIN-SETUP-CODE.txt` in the ACL-restricted data folder. It is regenerated at
     each start until setup completes.
5. **Staff and invited administrators** activate their accounts with a one-time **setup code** (12 characters,
   no ambiguous letters, valid 72 h).
   - Only the code's hash is stored.
   - Administrators never see or choose another person's password. A "reset" clears the password (and, for
     administrators, two-step verification) and issues a new code.
6. **Lockout:** 5 failed attempts lock the account for 15 minutes. Wrong passwords, wrong two-step codes,
   wrong setup codes and a wrong current password during a password change all count.
   - Sign-in endpoints are also rate-limited per IP address (20 requests per minute).
   - Error messages do not reveal whether an account exists. The exact reason is recorded in the audit log.
7. **HTTPS and pairing:**
   - The server's private CA issues the HTTPS certificate. The certificate covers the computer name, its
     current IPv4 addresses and `localhost`, and is re-issued automatically when these change or expiry
     nears.
   - Clients **pin** the CA: they accept only certificates issued by it, and never publicly trusted ones.
   - On first connection the user types the 20-character **pairing code** (80 bits of the CA's SHA-256
     fingerprint) shown by the server. A spoofed server cannot produce a matching CA.
   - Plain HTTP is not served at all.
8. **Roles** (enforced on the server; the dashboard only hides buttons for convenience):

   | Role | Access |
   |---|---|
   | `SuperAdmin` | Everything, including administrator accounts |
   | `Admin` | Everything except administrator accounts |
   | `Auditor` | Read-only |
   | `Staff` | Own account only |

   - Every endpoint requires a signed-in session unless it is on an explicit anonymous list. An automated
     test fails if a new anonymous endpoint appears.
