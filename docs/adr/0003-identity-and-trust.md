# ADR-0003: Identity, trust and signing

- Status: Accepted (2026-09-26)

## Decisions

1. **Server TLS and device identity** use a private certificate authority created by the server on first
   run (ECDSA P-256).
   - The CA private key is stored encrypted with DPAPI (LocalMachine scope) under the server's
     ProgramData folder. The folder is ACL-restricted to the service account and Administrators.
   - No certificate or key is ever committed to source control or packaged in an installer.
2. **Computer enrollment** works like this:
   - The admin creates a single-use enrollment code (valid for 24 hours by default; only its hash is stored).
   - The agent generates a non-exportable key pair. It uses the Microsoft Platform Crypto Provider (TPM)
     when present and the software key storage provider otherwise.
   - The agent sends a CSR together with the enrollment code.
   - The computer then stays `Pending` until an admin approves it. Only after approval does it receive
     a client certificate used for mutual TLS.
3. **Policy documents** are signed by a separate ECDSA P-256 *policy signing key*:
   - The signature covers the canonical UTF-8 JSON of the policy (see `OfficeSecurity.Policy`).
   - Agents pin the policy public key they receive during enrollment.
   - Agents reject any policy with an invalid signature, a lower version number, or a different computer
     target. They keep enforcing the last valid policy.
4. **Passwords** are hashed with PBKDF2-HMAC-SHA512 (see ADR-0005 for the final parameters; originally stated as 600,000
   iterations).
   - Admin accounts require TOTP two-step login.
   - Staff credentials are provisioned through one-time set-password codes, so the admin never sees or
     sets a staff member's final password.
5. **The first administrator account** is created interactively during server setup. There are no default
   or hardcoded credentials.
