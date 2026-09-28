# Database schema (Phases 2–4)

## Storage

- SQLite file `office-security.db` in the server data folder (ADR-0002), in WAL mode.
- Migrations are in `src/Server/OfficeSecurity.Server.Infrastructure/Persistence/Migrations` and are applied
  automatically at server start.
- Timestamps are stored as exact UTC ticks (`INTEGER`).
- Enums are stored as text.

## Tables

| Table | Purpose | Key constraints |
|---|---|---|
| `admin_accounts` | Administrators: user name, role, status, PBKDF2 password hash, encrypted TOTP secret, lockout counters | Unique `NormalizedUsername` |
| `staff_accounts` | Staff: employee code, name, department, status, PBKDF2 password hash, lockout counters | Unique `NormalizedEmployeeCode`; indexes on `Status`, `DisplayName` |
| `account_setup_codes` | One-time setup/bootstrap codes (SHA-256 hash only), expiry, used/revoked time | Index (`AccountType`, `AccountId`), index `CodeHash` |
| `sessions` | Signed-in sessions (SHA-256 of token), last seen, expiry, end reason, source IP, computer (staff) | Unique `TokenHash`; index (`PrincipalType`, `PrincipalId`) |
| `computers` | Enrolled computers: status (PendingApproval, Trusted, Rejected, Retired), certificate thumbprint, last seen, inventory JSON, control status JSON, assigned policy, per-computer policy version | Unique `CertificateThumbprint`; indexes on `Status`, `Hostname`; FK `PolicyId` → policies |
| `enrollment_codes` | One-time computer enrollment codes (hash only) | Unique `CodeHash` |
| `device_inventory` | Removable/phone/Bluetooth devices per computer, first/last seen, connected flag | Unique (`ComputerId`, `InstanceId`) |
| `security_events` | Events uploaded by agents | Unique (`ComputerId`, `EventId`) for idempotent uploads; indexes by computer/time and type/time |
| `policies` | Named policies; `SettingsJson` holds `PolicySettings`; one `IsDefault` | Unique `Name` |
| `staff_computer_assignments` | Which staff may sign in on which computers | PK (`StaffId`, `ComputerId`) |
| `software_inventory` | Programs reported per computer (name, version, publisher, scope Machine/User, install date), first/last seen, present flag | Unique (`ComputerId`, `Name`, `Version`, `Scope`); index `Name` |
| `approved_software` | Approved programs: name prefix, optional publisher, notes | Unique `Name` |
| `software_packages` | Uploaded installer files: file name, type (Msi/Exe), SHA-256, size, silent options, required signer, unsigned allowed; the file itself is `packages\{id}.pkg` in the data folder | FK `ApprovedSoftwareId` (restrict) |
| `software_requests` | Staff requests: program, reason, computer (from the sign-in ticket), status, reviewer, note, resulting installation | Indexes on (`Status`, `CreatedAtUtc`), `StaffId` |
| `deployment_jobs` | Installations: installer, computer, originating request, status (Queued, Running, Succeeded, SucceededRebootRequired, Failed, Cancelled), attempts, exit code, message | Index (`ComputerId`, `Status`); FK `PackageId` (restrict) |
| `audit_log` | Append-only, hash-chained audit trail | Triggers `audit_log_no_update` / `audit_log_no_delete` reject changes; indexes on `OccurredAtUtc`, `Action` |

## Audit hash chain

Each entry stores:
- `PreviousHash`: the previous entry's hash
- `Hash`: SHA-256 over all fields plus `PreviousHash`

`GET /api/v1/audit/verify` recomputes the chain.

- **Detected:** editing, inserting or deleting any entry except the newest ones.
- **Limitation:** truncating the newest entries is only detectable against an external anchor, which is
  planned for Phase 6.

## Not stored

Plain-text passwords, setup codes, session tokens and TOTP secrets are never stored. An automated test scans
the raw database file for them.
