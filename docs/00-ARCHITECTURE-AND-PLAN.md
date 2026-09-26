# Office Computer Security System — Architecture & Implementation Plan

Status: **APPROVED 2026-09-26** — Phase 1 in progress. Later decisions are recorded as ADRs in `docs/adr/` and take precedence over this document (notably ADR-0002: SQLite is now the default central database).
Scope of this document: the "First Task" of the master specification (sections 1–14 below).
No application code has been written yet. The repository was empty (only a one-line README) at the time of analysis.

---

## 0. Executive summary

The system is feasible as a **policy orchestrator + audit platform** that sits on top of Windows' own,
documented enforcement mechanisms. The application itself does not "block" things by magic; it
configures and verifies Windows features (Device Installation Restrictions, Removable Storage Access
policies, App Control for Business / AppLocker, Windows Defender Firewall, NTFS ACLs, audit policy,
BitLocker, Controlled Folder Access) and then collects the resulting events centrally.

That approach is reliable for **USB/removable storage, software installation, application execution,
service protection against standard users, and local/shared file permissions**.

It is **not** sufficient on its own for **online data-loss prevention** (uploads through an allowed
browser/website, copy/paste, printing content inspection). Those need either endpoint DLP (Microsoft
Purview Endpoint DLP or a third-party DLP product) and/or a managed network gateway with TLS inspection.
This is stated explicitly throughout; the system will report such controls as "not enforced" rather
than pretend.

The single most important precondition: **staff must use standard (non-administrator) Windows
accounts.** Any user with local administrator rights can defeat every control in this document.

---

## 1. Recommended architecture

```
                       ┌──────────────────────────────────────────────┐
                       │      Central Management Server (1 host)      │
                       │  ASP.NET Core Web API (Kestrel, HTTPS/mTLS)  │
                       │  hosted as a Windows Service                 │
                       │  ├─ Auth (admin/staff JWT, device mTLS)      │
                       │  ├─ Policy service (signs policy documents)  │
                       │  ├─ Device / software / request services     │
                       │  ├─ Event ingestion → alerts engine          │
                       │  ├─ Reporting (CSV/PDF)                      │
                       │  └─ Package repository (approved installers) │
                       │                 │                            │
                       │          PostgreSQL 16+                      │
                       └───────▲───────────────▲──────────────▲───────┘
                  HTTPS (JWT)  │               │ mTLS (device │ HTTPS (JWT)
                               │               │ certificate) │
        ┌──────────────────────┴──┐   ┌────────┴──────────────┴────────────────────┐
        │ Administrator Dashboard │   │ Each office PC                              │
        │ WPF (.NET), MVVM        │   │ ┌─────────────────────────────────────────┐ │
        │ runs on admin PC        │   │ │ Security Agent — Windows Service         │ │
        └─────────────────────────┘   │ │ (LocalSystem, auto-start, recovery)      │ │
                                      │ │ ├─ Policy cache (signed, ACL-protected)  │ │
                                      │ │ ├─ Enforcers (device, app, firewall,     │ │
                                      │ │ │   file ACL, audit policy, BitLocker)   │ │
                                      │ │ ├─ Verifiers (read back applied state)   │ │
                                      │ │ ├─ Event collectors (Event Log, device   │ │
                                      │ │ │   notifications, inventory)            │ │
                                      │ │ ├─ Offline event queue (SQLite)          │ │
                                      │ │ └─ Named-pipe IPC (ACL'd) ◄──────────┐   │ │
                                      │ └──────────────────────────────────────│───┘ │
                                      │ ┌──────────────────────────────────────┴───┐ │
                                      │ │ Staff Application — WPF, runs as the     │ │
                                      │ │ logged-on standard user, no privileges   │ │
                                      │ └──────────────────────────────────────────┘ │
                                      └──────────────────────────────────────────────┘
```

Key design principles

1. **Enforcement lives in Windows, orchestration lives in the agent.** The agent writes documented
   policy settings / APIs, then *verifies* them by reading back effective state. Status is reported as
   `Enforced`, `Partially enforced`, `Not supported on this edition`, `Failed`, never assumed.
2. **The staff app has zero privileges.** It talks to the server with the staff user's token and to the
   local agent over an ACL-restricted named pipe for read-only status. It cannot change policy.
3. **Signed policies.** The server signs each policy document (ECDSA P-256). The agent refuses unsigned or
   tampered policies and keeps enforcing the last valid one while offline.
4. **Device identity by certificate.** Each PC enrolls with a one-time, admin-issued enrollment token, generates
   a non-exportable key (TPM-backed where available), and receives a client certificate from the server's
   internal CA. An admin must approve the pending registration before the PC is trusted.
5. **Append-only, hash-chained audit.** Audit rows cannot be updated/deleted by the application DB role; each
   row carries a hash of the previous row so tampering is detectable.
6. **Offline resilience.** Events are queued locally (SQLite, SYSTEM-only ACL, HMAC-protected rows) and
   uploaded in order on reconnection with idempotency keys.

Why a dedicated server host: a central SQLite file on a share is not safe for concurrent writers and
cannot enforce access control; PostgreSQL on a single always-on Windows machine (or Windows Server /
Linux VM) is the minimum reliable option.

---

## 2. Technology stack

| Layer | Choice | Reason |
|---|---|---|
| Runtime | **.NET 10 (LTS)** | Current LTS (supported to Nov 2028). All components on one runtime. |
| Admin dashboard | WPF, MVVM via **CommunityToolkit.Mvvm** | Native Windows desktop, mature, no web stack needed. |
| Staff app | WPF, MVVM | Same shared UI library as dashboard. |
| Agent | .NET Worker Service + `Microsoft.Extensions.Hosting.WindowsServices` | Supported Windows Service hosting, DI, structured logging. |
| Windows APIs | CfgMgr32/SetupAPI (P/Invoke), WMI/CIM, `System.Diagnostics.Eventing.Reader`, `netsh advfirewall`/`INetFwPolicy2` COM, `CiTool.exe`, `auditpol`, `icacls`/`System.Security.AccessControl`, BitLocker WMI | All documented, supported interfaces. |
| Server | ASP.NET Core Web API (minimal APIs or controllers), Kestrel with HTTPS + client-cert auth | Can run as a Windows Service; no IIS required. |
| ORM / migrations | EF Core + Npgsql, code-first migrations | Versioned, reviewable schema changes. |
| Central DB | ~~PostgreSQL 16+~~ → **SQLite, single-writer server (see ADR-0002)**; PostgreSQL optional later | No separate DB install for a non-technical office; only the server process opens the file. |
| Agent local store | SQLite (Microsoft.Data.Sqlite) | Single-writer local queue/cache only — appropriate use of SQLite. |
| Password hashing | ASP.NET Core Identity `PasswordHasher` (PBKDF2-HMAC-SHA512, ≥600k iterations) | No extra dependency; admin accounts additionally get TOTP MFA. |
| Tokens | Short-lived JWT access + rotating refresh tokens (stored hashed server-side) | Revocable sessions. |
| Logging | `Microsoft.Extensions.Logging` + Serilog (file + Windows Event Log sinks) | Structured logs. |
| PDF export | QuestPDF (community licence is free below USD 1M revenue — **licensing to confirm**) | CSV export uses no dependency. |
| Installer | **WiX Toolset** MSI packages + a bundle bootstrapper | Standard MSI: silent install, GPO/Intune deployable, repair/upgrade. **Note:** WiX v6+ requests an Open Source Maintenance Fee from revenue-generating users — to confirm, or fall back to WiX v5/other MSI tooling. |
| Tests | xUnit, FluentAssertions-free assertions, Testcontainers (PostgreSQL), WebApplicationFactory; Windows VM test lab for enforcement | See §9. |
| CI | GitHub Actions `windows-latest` (build + unit/integration tests) | WPF / Windows-specific code must build and test on Windows. |

---

## 3. Project folder structure

```
OFFICE-DATA-SECURITY-SYSTEM/
├─ OfficeSecurity.sln
├─ Directory.Build.props              # common settings: nullable, warnings-as-errors, analyzers
├─ Directory.Packages.props           # central package version management
├─ src/
│  ├─ Shared/
│  │  ├─ OfficeSecurity.Contracts/        # API DTOs, enums, event schemas (versioned)
│  │  └─ OfficeSecurity.Policy/           # policy model, canonical JSON, signing/verification
│  ├─ Server/
│  │  ├─ OfficeSecurity.Server.Domain/        # entities, domain rules
│  │  ├─ OfficeSecurity.Server.Application/   # use cases, validation, authorization rules
│  │  ├─ OfficeSecurity.Server.Infrastructure/# EF Core, migrations, CA, file storage, PDF
│  │  └─ OfficeSecurity.Server.Api/           # endpoints, auth, hosting (Windows Service)
│  ├─ Agent/
│  │  ├─ OfficeSecurity.Agent/                # Windows Service host, sync, queue, IPC server
│  │  ├─ OfficeSecurity.Agent.Enforcement/    # IEnforcer implementations (one per feature)
│  │  │   ├─ DeviceControl/  AppControl/  Firewall/  FileProtection/
│  │  │   ├─ AuditPolicy/    BitLocker/   Bluetooth/ WiFi/
│  │  ├─ OfficeSecurity.Agent.Collectors/     # event log readers, device watcher, inventory
│  │  └─ OfficeSecurity.Agent.Native/         # P/Invoke signatures (CfgMgr32, etc.)
│  └─ Clients/
│     ├─ OfficeSecurity.Client.Core/          # typed API client, token handling, pipe client
│     ├─ OfficeSecurity.Client.Wpf/           # shared styles, controls, converters
│     ├─ OfficeSecurity.AdminDashboard/       # WPF admin app
│     └─ OfficeSecurity.StaffApp/             # WPF staff app
├─ tests/
│  ├─ OfficeSecurity.Policy.Tests/
│  ├─ OfficeSecurity.Server.UnitTests/
│  ├─ OfficeSecurity.Server.IntegrationTests/  # real PostgreSQL via Testcontainers
│  ├─ OfficeSecurity.Agent.UnitTests/          # enforcers against fakes
│  └─ OfficeSecurity.Agent.WindowsTests/       # run only on disposable Windows VMs (opt-in)
├─ installer/
│  ├─ Server.Installer/   Agent.Installer/   AdminDashboard.Installer/   Bundle/
├─ deploy/
│  ├─ scripts/            # server bootstrap, CA init, first-admin creation (no secrets inside)
│  └─ policies/           # baseline WDAC/AppLocker XML templates, example policy JSON
├─ docs/
│  ├─ 00-ARCHITECTURE-AND-PLAN.md  (this file)
│  ├─ api/  database/  security-controls/  deployment/  testing/
└─ .github/workflows/     # build-and-test.yml (windows-latest)
```

---

## 4. Database schema (provider-neutral; SQLite by default per ADR-0002)

Conventions: `uuid` primary keys, `timestamptz` in UTC, `created_at/updated_at`, soft-delete via
`status` where history must be preserved, `xmin`-based optimistic concurrency. All FKs indexed.

### 4.1 Identity & access

| Table | Key columns | Notes |
|---|---|---|
| `admin_accounts` | id, username (unique, citext), password_hash, totp_secret_enc, role (`SuperAdmin`,`Admin`,`Auditor`), status, failed_attempts, locked_until, must_change_password | First account created by setup tool, never hardcoded. TOTP secret encrypted with a key held outside the DB (DPAPI / key file). |
| `staff_accounts` | id, employee_code (unique), display_name, department, password_hash, status (`Active`,`Disabled`), must_change_password, windows_account_sid (nullable) | No personal data beyond what is needed. |
| `refresh_tokens` | id, principal_type, principal_id, token_hash, expires_at, revoked_at, replaced_by | Hashed; rotation + reuse detection. |
| `password_reset_tickets` | id, staff_id, ticket_hash, issued_by_admin_id, expires_at, used_at | One-time provisioning codes; admin never sees the password. |
| `staff_computer_assignments` | staff_id, computer_id, assigned_by, assigned_at | PK (staff_id, computer_id). |

### 4.2 Computers & enrollment

| Table | Key columns | Notes |
|---|---|---|
| `enrollment_tokens` | id, token_hash, created_by, expires_at, used_at, intended_hostname | Single-use, short-lived. |
| `computers` | id, hostname, os_edition, os_build, hardware_id_hash, tpm_present, status (`Pending`,`Trusted`,`Retired`,`Revoked`), agent_version, last_seen_at, last_policy_version_applied, health_state | Unique on hardware_id_hash among non-retired. |
| `computer_certificates` | id, computer_id, thumbprint (unique), serial, not_before, not_after, revoked_at | mTLS identity. |
| `computer_health_reports` | id, computer_id, reported_at, service_state, per-control status JSONB | Latest row cached on `computers`. Partitioned by month. |

### 4.3 Policies

| Table | Key columns | Notes |
|---|---|---|
| `security_policies` | id, name, description, current_version | |
| `policy_versions` | id, policy_id, version, document JSONB, signature, created_by, created_at | Immutable once published. |
| `policy_assignments` | id, policy_id, scope (`All`,`Group`,`Computer`), target_id, priority | Effective policy resolved server-side. |
| `computer_groups`, `computer_group_members` | | For "selected computers". |
| `policy_exceptions` | id, computer_id, staff_id?, control, reason, approved_by, starts_at, expires_at, revoked_at | Temporary, always time-boxed. |

### 4.4 Devices

| Table | Key columns | Notes |
|---|---|---|
| `device_inventory` | id, computer_id, device_instance_id, hardware_ids, vid, pid, serial, setup_class_guid, friendly_name, first_seen, last_seen | Identification never by display name alone. |
| `approved_devices` | id, match_type (`InstanceId`,`VidPidSerial`), match_value, scope (`All`/`Computer`), computer_id?, approved_by, reason, expires_at | |

### 4.5 Software

| Table | Key columns | Notes |
|---|---|---|
| `software_inventory` | id, computer_id, name, publisher, version, install_scope (`Machine`/`User`), source (`MSI`/`ARP`/`Appx`), first_seen, last_seen | |
| `approved_software` | id, name, publisher, signer_certificate / file hash rule, allowed_versions, package_id? | Feeds WDAC/AppLocker allow rules. |
| `software_packages` | id, approved_software_id, file_name, sha256, size, authenticode_signer, silent_args, uploaded_by | Stored in server package repository. |
| `software_requests` | id, staff_id, computer_id, software_name, reason, status (`Pending`,`Approved`,`Rejected`,`Installing`,`Installed`,`Failed`,`Cancelled`), reviewed_by, review_note, created_at, decided_at | CHECK: reviewer ≠ requester (admins and staff are separate tables anyway). |
| `deployment_jobs` | id, request_id?, package_id, computer_id, status, attempts, result_code, log_excerpt, started_at, finished_at | |

### 4.6 Events, alerts, audit

| Table | Key columns | Notes |
|---|---|---|
| `security_events` | id, computer_id, staff_id?, event_type, severity, occurred_at, received_at, source (`Agent`,`WindowsEventLog`), result, device_json, application_json, details JSONB, idempotency_key (unique) | Partitioned by month; indexes on (computer_id, occurred_at), (event_type, occurred_at). |
| `file_protection_events` | id, computer_id, staff_id?, path_hash, path_display, operation, result, process_path, occurred_at | Subset of security events with file columns for reporting. |
| `alerts` | id, rule_code, severity, computer_id?, staff_id?, first_event_id, event_count, status (`Open`,`Acknowledged`,`Resolved`), assigned_to, resolved_by, resolved_at | Deduplicated by rule+target+window. |
| `alert_rules` | code, enabled, severity, threshold, window | |
| `audit_log` | id (bigint identity), actor_type, actor_id, action, target_type, target_id, occurred_at, ip, details JSONB, prev_hash, row_hash | **Append-only**: app role has INSERT/SELECT only; trigger rejects UPDATE/DELETE; hash chain verified by a scheduled job. |
| `login_audit` | id, principal_type, principal_id?, username_attempted, computer_id?, result, reason, occurred_at, logout_at | Never stores passwords. |

### 4.7 Operations

| Table | Notes |
|---|---|
| `app_usage_summaries` | *Optional, off by default* — per-day aggregate minutes per application per computer; no window titles, no content. |
| `activity_summaries` | *Optional, off by default* — per-day active/idle minutes. |
| `system_settings` | key/value with type, last changed by. |
| `backup_records` | id, kind (`Database`,`FileShare`), started_at, finished_at, result, location, size, checksum, verified_at |
| `report_exports` | id, report_type, parameters, requested_by, created_at, file_hash |

---

## 5. API design (v1, all HTTPS)

Authentication schemes:
- `AdminBearer` — admin JWT (15 min) + refresh; MFA required at login.
- `StaffBearer` — staff JWT, bound to the computer the login came from.
- `DeviceCert` — mTLS client certificate of a *trusted* computer.

All requests validated (FluentValidation-style validators in Application layer), paged lists use
`?page=&pageSize=&sort=&filter=`; errors use RFC 9457 `application/problem+json`.

| Area | Endpoint | Auth |
|---|---|---|
| Auth | `POST /api/v1/auth/admin/login` → `{mfaRequired, mfaTicket}`; `POST /auth/admin/mfa` → tokens | anonymous (rate-limited) |
| | `POST /api/v1/auth/staff/login` `{employeeCode, password, computerId}` | anonymous + DeviceCert of calling PC (via agent-signed nonce) |
| | `POST /auth/refresh`, `POST /auth/logout` | token |
| | `POST /auth/staff/set-password` (with one-time ticket or current password) | anonymous/Staff |
| Staff accounts | `GET/POST /api/v1/staff`, `GET/PATCH /staff/{id}`, `POST /staff/{id}/disable`, `POST /staff/{id}/reset-ticket`, `PUT /staff/{id}/computers` | Admin |
| Enrollment | `POST /api/v1/enrollment-tokens` | Admin |
| | `POST /api/v1/enroll` `{token, csr, hardwareInfo}` → `{computerId, status: Pending}` | anonymous (token) |
| | `GET /api/v1/enroll/{computerId}/certificate` | enrollment proof |
| Computers | `GET /api/v1/computers`, `GET /computers/{id}`, `POST /computers/{id}/approve`, `POST /computers/{id}/retire`, `GET /computers/{id}/health` | Admin |
| Agent | `POST /api/v1/agent/heartbeat` `{agentVersion, controlStatuses[], appliedPolicyVersion}` | DeviceCert |
| | `GET /api/v1/agent/policy?since={version}` → signed policy or 304 | DeviceCert |
| | `POST /api/v1/agent/events` (batch, idempotent) | DeviceCert |
| | `POST /api/v1/agent/inventory/software`, `/inventory/devices` | DeviceCert |
| | `GET /api/v1/agent/jobs`, `POST /agent/jobs/{id}/result`, `GET /agent/packages/{id}` | DeviceCert |
| Policies | `GET/POST /api/v1/policies`, `POST /policies/{id}/versions`, `PUT /policies/{id}/assignments`, `GET /policies/effective/{computerId}` | Admin |
| Exceptions | `POST /api/v1/exceptions`, `DELETE /exceptions/{id}` | Admin |
| Devices | `GET /api/v1/devices` (inventory), `GET/POST/DELETE /approved-devices` | Admin |
| Software | `GET /api/v1/software/inventory`, `GET/POST /software/approved`, `POST /software/packages` (upload) | Admin |
| Requests | `POST /api/v1/software-requests` | Staff |
| | `GET /software-requests/mine` | Staff |
| | `GET /software-requests`, `POST /software-requests/{id}/approve` `{packageId}`, `POST /{id}/reject` | Admin |
| Alerts | `GET /api/v1/alerts`, `POST /alerts/{id}/acknowledge`, `/resolve` | Admin |
| Audit | `GET /api/v1/audit`, `GET /api/v1/events`, `GET /events/{id}`, `GET /audit/verify-chain` | Admin/Auditor |
| Reports | `GET /api/v1/reports/{type}?from=&to=&computerId=&format=csv|pdf` | Admin/Auditor |
| Dashboard | `GET /api/v1/dashboard/overview` | Admin |
| Live notifications | SignalR hub `/hubs/admin` (new alerts, new requests) | Admin |

Full request/response schemas will be generated as OpenAPI (`/openapi/v1.json`) and committed under `docs/api/`.

---

## 6. Windows security implementation approach

Every control is implemented as an `IEnforcer` with three operations: `Apply(policy)`, `Verify() → ControlStatus`,
`Revert()` (used only on authorized uninstall/exception). Status is sent in every heartbeat.

| # | Control | Mechanism (documented) | Verification | Key limitations |
|---|---|---|---|---|
| C1 | Block USB mass storage / external disks | **Device Installation Restrictions** policy (deny setup classes `DiskDrive`, `WPD`, `CDROM`…; *Allow* specific **device instance IDs** with "layered order of evaluation", Win10 2004+) **plus** **Removable Storage Access** policies (deny read/write on removable disks, WPD, CD/DVD) as defence-in-depth | Read effective policy registry under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall` and `...\RemovableStorageDevices`; test-mount on lab VM; Event IDs from `Microsoft-Windows-Kernel-PnP/Configuration` | Already-installed devices need removal once policy applies (agent does this via CfgMgr32). Cheap USB drives without a unique serial get a port-dependent instance ID → approval may need to be per port/per PC. Home edition not supported. |
| C2 | Allow admin-approved USB devices | Allow-list by device instance ID (contains VID/PID/serial) in the same policy | Enumerate + compare | Serial numbers can be cloned by a determined attacker with special hardware; acceptable residual risk for office use. |
| C3 | Keep keyboards/mice/printers working | Deny is by **setup class** (storage only), never by all USB | Lab test with HID + printer | Composite devices that include storage (some phones, some headsets) will have the storage part blocked — intended. |
| C4 | Mobile phone transfers (MTP/PTP) | Deny `WPD` class + WPD Removable Storage Access policy | Plug test phone in lab | Phone can still act as a network hotspot (see C9). |
| C5 | Bluetooth file transfer | Option A: deny Bluetooth radio device class entirely. Option B (MDM): `Bluetooth/ServicesAllowedList` CSP to allow only HID/audio profiles (blocks OBEX). Plus block `fsquirt.exe` via app control | Check radio state / CSP value; attempt send in lab | Option B requires MDM (Intune or equivalent). |
| C6 | Block unauthorized software execution | **App Control for Business (WDAC)**, available on Pro/Enterprise/Education 10 & 11 (1903+). Base policy: allow Windows + Microsoft-signed + approved publishers/hashes; deny execution from user-writable paths. Deployed with `CiTool.exe` (Win11 22H2+) or multiple-policy `.cip` + refresh on Win10. **Audit mode first**, then enforce. Optionally **AppLocker** for per-user rules (edition enforcement historically Enterprise/Education; recent builds relaxed this — to be verified per target build) | `CiTool --list-policies`; Code Integrity event log (3076 audit / 3077 block) | Misconfigured WDAC can break line-of-business apps → mandatory audit phase, signed policies, recovery procedure. Scripts (PowerShell) run in Constrained Language Mode, not fully blocked. |
| C7 | Prevent software installation | Staff are standard users (UAC blocks per-machine installs) + WDAC blocks per-user/portable EXEs + Windows Installer policy `DisableUserInstalls` + Store restriction (packaged-app rules) | Attempt MSI/EXE/portable/Store install in lab | Browser extensions are "software" too → controlled via browser policy (C10). |
| C8 | Remote install of approved software | Agent (LocalSystem) downloads package over mTLS, verifies SHA-256 **and** Authenticode signer against approved record, runs `msiexec /i /qn` or vendor silent args, reports exit code & inventory delta | Inventory shows new version | Only packages admins upload; no arbitrary command execution endpoint (prevents the agent becoming a remote-access tool). |
| C9 | Network restrictions | **Windows Defender Firewall** outbound rules per program (block unapproved apps / known file-sharing clients), **WLAN filters** (`netsh wlan add filter`) to allow only office SSIDs (blocks phone hotspots), block new network adapters via device class if required | `Get-NetFirewallRule`/COM read-back; `netsh wlan show filters` | Windows Firewall cannot block by domain name natively; website blocking must be DNS/gateway/browser-policy based. USB-tethering is covered by C1/C3 class rules (RNDIS/NCM). |
| C10 | Website / cloud / email upload restrictions | **Browser policies** for Edge & Chrome (ADMX registry policies): `URLBlocklist/URLAllowlist`, disable InPrivate/Incognito, force DNS-over-HTTPS off or to office resolver, extension allowlist, `DownloadRestrictions`; block other browsers via WDAC; office **DNS filter** for category blocking | Read `HKLM\SOFTWARE\Policies\Microsoft\Edge` & `Google\Chrome`; `edge://policy` | **Cannot** stop upload of files to an *allowed* site (e.g. personal Gmail if Gmail is allowed for work, or a file pasted into an allowed chat). Requires Purview Endpoint DLP or TLS-inspecting gateway/CASB. |
| C11 | Company file permissions | Central **file server share** with NTFS ACLs by group; local protected folders ACL'd by agent (`System.Security.AccessControl`) | Read ACLs back, compare to policy | In a workgroup (no AD), per-PC local accounts make central ACL management clumsy → AD strongly recommended. |
| C12 | File access audit | **Advanced Audit Policy** (`auditpol /set /subcategory:"File System"`) + SACLs on protected folders; agent reads Security log 4663/4660/5145 and forwards | `auditpol /get`; event appears after test access | High event volume → only protected folders audited. Records *that* a file was read, not *where it went afterwards*. |
| C13 | Anti-ransomware / unauthorized modification | **Controlled Folder Access** (Microsoft Defender Antivirus) on protected folders with approved-apps list; ACL deny-delete where business allows | `Get-MpPreference` | Requires Defender as active AV (never disabled by us). |
| C14 | Encryption at rest | **BitLocker** (Pro/Enterprise) with recovery keys escrowed to the server (encrypted) | BitLocker WMI `Win32_EncryptableVolume` | Home: only "Device encryption" on supported hardware. |
| C15 | Backup & recovery | File server: VSS snapshots + versioned backup to NAS/offsite (e.g. `wbadmin`/Veeam/NAS tooling); DB: `pg_dump` scheduled + restore test | Backup record + periodic restore test | Backup tool choice depends on existing hardware. |
| C16 | Agent tamper protection | Service runs as LocalSystem; service DACL grants stop/config only to SYSTEM/Administrators; program files & ProgramData ACL'd; SCM recovery actions (restart ×3); heartbeat → "agent unavailable" alert after N minutes; WDAC also blocks unsigned tools | `sc sdshow`, `sc qfailure` | **Local administrators can always stop it.** Protected Process Light requires a Microsoft-signed ELAM driver — not feasible for this project. |
| C17 | Staff may log on only to assigned PC | Windows sign-in: **AD** `Log On To` (userWorkstations) or GPO "Allow log on locally"; in workgroup, agent provisions local standard accounts only on assigned PCs. Staff app login is an *additional* app-level check, not the security boundary | Attempt logon on non-assigned PC | Depends on AD vs workgroup decision. |
| C18 | Login audit | Security log 4624/4625/4634/4647 (+ app-level logins recorded server-side) | Event present | Logout time can be missing on hard power-off. |

Printing, copy/paste, screenshots, photographs — see §14.

---

## 7. Feature feasibility analysis

Legend — **D**: implementable directly by this application on Windows 10/11 Pro · **E**: needs Pro/Enterprise/Education or edition-specific build · **S**: needs additional security software/licence · **I**: needs additional infrastructure · **X**: cannot be reliably guaranteed.

| Requirement | Category | Notes |
|---|---|---|
| Admin/staff accounts, roles, MFA, password hashing, audit | D | Pure server/app work. |
| Computer registration, trust approval, health, offline/online | D | Needs server host (I). |
| Signed policy distribution, offline enforcement, event queue | D | |
| Software inventory (ARP/MSI/Appx) | D | |
| Software request/approval workflow | D | |
| Approved software remote install | D | Needs signed installers or hash rules. |
| Block USB storage, external HDD, CD/DVD, MTP phones | **E** | Device Installation + Removable Storage policies; Home unsupported. |
| Per-device USB approval | **E** | Instance-ID allow-list (serial quality caveat). Fine-grained per-user device control with read-only mode → **S** (Microsoft Defender for Endpoint device control). |
| Bluetooth file transfer block | E (disable radio) / **S/I** (profile-level via MDM CSP) | |
| Block unauthorized software execution | **E** | WDAC on Pro+ (1903+); AppLocker per-build verification. |
| Prevent staff disabling agent | D **if staff are standard users** | Impossible against local admins (X). |
| Windows Firewall per-app blocking | D | |
| Block phone hotspot / unknown Wi-Fi | D | WLAN filters. |
| Website category blocking | **I** | DNS filter or firewall/NGFW; browser policies are D. |
| Block uploads to personal email / cloud through a browser | **S/I** | Purview Endpoint DLP (M365 E5 / E5 Compliance) or TLS-inspecting gateway/CASB. Without these: only coarse domain blocking. |
| Block messaging apps | D/E | Desktop apps via WDAC/firewall; web versions via URL blocklist (I for DNS). |
| Content-aware DLP (detect sensitive content leaving) | **S** | Out of scope for self-built code. |
| File permissions on shared folders | D + **I** | Needs a file server (and ideally AD). |
| File access auditing | D (Pro) | |
| Prevent modification/deletion | D (ACL, CFA) | Only against unauthorized users/apps; authorized users can still delete what they may write → backups. |
| Encryption at rest | E | BitLocker. |
| Backup & recovery | **I** | NAS/backup target required. |
| Copy/paste control | **S** | Endpoint DLP only. |
| Printing control | D (restrict printer installation, log print jobs via PrintService log) / **S** (content-aware) | |
| Screenshots / photographs of screen | **X** | Documented limitation; not monitored by design. |
| VPN / proxy / Tor bypass | E (block the apps via WDAC) + I (egress firewall) | Not 100% guaranteed. |
| App usage / active-idle statistics | D (optional) | Aggregate only, off by default, disclosed to staff; see legal note. |
| Protection against local administrators | **X** | By definition. |
| Protection against booting another OS / removing the disk | E (BitLocker + UEFI password + Secure Boot) | Firmware password is manual per machine. |

---

## 8. Development phases (aligned to the specification)

| Phase | Deliverables | Exit criteria |
|---|---|---|
| **1. Requirements & architecture** | This document refined with your answers (§12 decisions), ADRs, final schema doc, OpenAPI skeleton, solution skeleton compiling, CI pipeline, threat model (STRIDE) | Approved architecture; CI green on `windows-latest`. |
| **2. Foundation** | Server with PostgreSQL + migrations, first-admin setup tool, admin login + MFA, staff accounts + provisioning tickets, role authorization, internal CA + HTTPS, admin dashboard shell (Overview, Staff), staff app login | Auth/role integration tests pass; no hardcoded secrets (secret scan in CI). |
| **3. Computer management** | Enrollment tokens, CSR/mTLS, approve/retire, agent Windows Service skeleton with heartbeat, signed policy fetch + cache, offline queue, device & hardware inventory, online/offline status, Computers screen | Agent survives reboot & network loss in VM tests; policy signature tamper test fails closed. |
| **4. Software management** | Software inventory, request workflow (staff → admin), package upload & verification, deployment jobs, results; Software & Requests screens | End-to-end install of a signed test MSI on VM; staff cannot approve. |
| **5. Security enforcement** | Enforcers C1–C18 incrementally, each with Apply/Verify/Revert, audit mode before enforce, per-control status in dashboard, exceptions | Each control verified on Win10 Pro + Win11 Pro (+ Enterprise if used) VMs; documented results, including failures. |
| **6. Audit & reporting** | Event collectors, alert rules engine, hash-chained audit, search/filter/paging, reports CSV/PDF, weekly/monthly summaries, SignalR notifications | Reports reconcile with raw events in tests. |
| **7. Testing & deployment** | MSI packages + bundle, upgrade/uninstall (admin-authorized), deployment guide, security test report, backup/restore drill, pilot on 1–2 office PCs | Pilot sign-off; limitations list published. |

---

## 9. Testing strategy

- **Unit tests** (every PR, CI): domain rules, validators, policy signing/verification, effective-policy
  resolution, alert rules, hash chain, enforcer logic against fake Windows adapters.
- **Integration tests** (CI): API + real PostgreSQL (Testcontainers), authz matrix test that calls every
  endpoint with every role and asserts allow/deny, idempotent event ingestion, migrations up from empty.
- **Windows enforcement tests** (manual-triggered, disposable Hyper-V VMs with checkpoints — never
  production PCs): USB storage/MTP/Bluetooth/hotspot, WDAC audit→enforce, install attempts as standard
  user, service stop attempts as standard user and as admin (expected: admin succeeds, alert fires),
  reboot/recovery, network cut & resync, policy tamper, clock skew.
- **Security tests**: dependency & secret scanning, TLS config check, JWT tampering/replay, brute-force
  lockout, enrollment-token reuse, device impersonation without certificate, SQL-injection/validation fuzzing.
- **Resilience**: DB unavailable (server returns 503, agent keeps queue), disk full on agent, corrupted cache.
- **Installer tests**: clean install, upgrade N-1→N, repair, uninstall requiring admin authorization.
- **Backup/restore drill**: restore DB to a fresh server and verify audit hash chain.
- Results recorded in `docs/testing/` with date, environment, pass/fail — failures and open limitations
  are documented, not hidden.

Note on this development environment: code is authored in a Linux cloud container. WPF, the Windows
Service and all enforcement code **cannot be executed here**; they will be built and unit-tested on
GitHub Actions Windows runners, and enforcement must be verified by you (or me with your guidance) on
Windows test VMs. I will not report Windows enforcement tests as passed unless they were actually run.

---

## 10. Required Windows permissions

| Component | Runs as | Needs |
|---|---|---|
| Security Agent | LocalSystem (Windows Service) | Write HKLM policy keys, manage devices (CfgMgr32), deploy WDAC policies, firewall rules, ACLs, auditpol, read Security event log, run installers, BitLocker WMI. |
| Agent installation / uninstall | Local Administrator (or deployment via GPO/Intune/RMM) | MSI per-machine install. Uninstall additionally requires a server-issued authorization code. |
| Staff application | Logged-on standard user | Nothing privileged; named-pipe read access granted to Interactive users. |
| Admin dashboard | Admin's Windows user (standard is fine) | Network access to server; admin credentials + MFA. |
| Central server | Dedicated low-privilege service account (virtual account `NT SERVICE\OfficeSecurityServer`) | Bind HTTPS port, read cert private key, DB connection, write to package/log folders. |
| PostgreSQL | its own service account | Separate DB roles: `app_rw` (no UPDATE/DELETE on audit), `migrator`, `backup`, `readonly_auditor`. |
| Staff Windows accounts | **Standard users** | Removal of any existing local-admin rights is mandatory. |

---

## 11. Required Windows editions

| Edition | Support |
|---|---|
| Windows 10/11 **Home** | **Not supported** for managed staff PCs (no Group Policy engine for device installation/removable storage policies, no BitLocker, no domain join). Agent will report controls as "Not supported on this edition". |
| Windows 10/11 **Pro** (22H2 / 23H2 / 24H2+) | **Minimum supported.** C1–C4, C6 (WDAC), C7–C14, C16–C18 available. |
| Windows 10/11 **Enterprise / Education** | Full support incl. AppLocker, `RemoveWindowsStore`, better MDM coverage. |
| Windows 10 | End of mainstream support Oct 2025 — only with Extended Security Updates; **plan to move to Windows 11**. |
| Server host | Windows 10/11 Pro always-on machine is workable for small offices; **Windows Server 2022/2025** recommended. |

---

## 12. Required external software / infrastructure & open decisions

Infrastructure required
1. **Central server host** (always on, UPS, static IP / DNS name) + PostgreSQL.
2. **Internal certificate authority** — built into the server (for agent mTLS and server HTTPS), or your existing AD CS.
3. **Backup target** — NAS or external backup with offsite/immutable copy.
4. **File server / NAS share** for company files (strongly recommended — files scattered on desktops cannot be protected centrally).
5. **DNS filtering or a firewall/UTM** that supports category-based web filtering (for website/cloud blocking).
6. **Code-signing certificate** (OV/EV) to sign agent, apps and installers — needed for WDAC signer rules and to avoid SmartScreen warnings.

Optional / for stronger guarantees
7. **Active Directory domain** (Windows Server) — central logon restrictions, file-share permissions, GPO fallback.
8. **Microsoft 365 Business Premium** (Intune + Defender for Business) or **E3/E5** — MDM CSPs (Bluetooth profiles), Defender device control with per-user/read-only rules.
9. **Microsoft Purview Endpoint DLP** (M365 E5 / E5 Compliance) or a third-party DLP — required for upload-to-allowed-site, clipboard, content-aware print control.
10. **TLS-inspecting gateway / CASB** — alternative to endpoint DLP for web upload control.

**Decisions I need from you before Phase 1**
1. How many computers? Is there an **Active Directory domain**, or is it a **workgroup**?
2. Which **Windows editions/builds** are on the office PCs today (Home/Pro/Enterprise; 10 vs 11)?
3. Do staff currently have **local administrator** rights? (They must lose them.)
4. Which machine will host the **central server**? Is there a file server/NAS?
5. Which **company email/cloud** is sanctioned (Microsoft 365, Google Workspace, other)? This defines the allow-list.
6. Any existing **Microsoft 365 / Defender / Intune** licences?
7. What **router/firewall** does the office use (does it support DNS/web filtering)?
8. Staff sign-in model: should the staff app login be the same credential as their Windows login, or a separate app account mapped to a Windows account?
9. Should the optional **application usage / active-idle statistics** be built at all? (Recommended: off by default.)
10. Budget/licensing acceptance for: code-signing certificate, QuestPDF (if revenue ≥ USD 1M), WiX OSMF.
11. Legal: confirm employees will be **notified in writing** of the security controls and audit logging (required or advisable under most employment/privacy laws).

---

## 13. Estimated development complexity

Overall: **High**. Rough effort for one senior developer, assuming answers above and access to Windows test VMs:

| Phase | Estimate |
|---|---|
| 1 Architecture & skeleton | 1–2 weeks |
| 2 Foundation (auth, DB, shells) | 3–4 weeks |
| 3 Computer management + agent core | 3–5 weeks |
| 4 Software management | 3–4 weeks |
| 5 Security enforcement (C1–C18) | 6–10 weeks (highest risk: WDAC, device control edge cases) |
| 6 Audit, alerts, reports | 3–4 weeks |
| 7 Installer, testing, pilot | 3–5 weeks |
| **Total** | **~22–34 weeks** |

Highest-risk items: WDAC policy authoring without breaking business apps; USB devices without unique serials;
workgroup (non-AD) file-permission management; reliable online-DLP expectations.

---

## 14. Important security limitations (must be accepted explicitly)

1. **Local administrators can disable everything.** The system protects against standard users only.
2. **Online DLP is partial without endpoint DLP or a TLS-inspecting gateway.** With this application alone:
   - *Blocked*: unapproved desktop apps (Dropbox/Telegram/WhatsApp Desktop/VPN clients), unapproved browsers,
     private browsing, listed domains (via browser policy + DNS filter), unknown Wi-Fi/hotspots, USB tethering.
   - *Still possible*: uploading to any **allowed** website (e.g. a personal account on an allowed service),
     pasting text into allowed web apps, sending as email attachment from an allowed mail client to an external
     address (unless mail server rules / DLP restrict it), sites not yet on the blocklist.
3. **Copy/paste** between applications cannot be controlled without endpoint DLP.
4. **Printing**: printer installation can be restricted and print jobs logged (document name, printer, user);
   content cannot be inspected; paper leaves the building.
5. **Screenshots & photographs**: a staff member can photograph the screen with a phone or take a screenshot and
   re-type/share it. By design (no screen monitoring), this is **not detected**. Mitigation is organisational:
   need-to-know access, phone policy in sensitive areas, NDAs.
6. **Authorized users can leak what they are authorized to see.** ACLs limit *who* can read; they do not control
   what an authorized reader does next beyond the transfer channels above.
7. **USB device approval** relies on hardware serial numbers, which can be absent or spoofed.
8. **Offline machines** keep enforcing the last policy, but alerts arrive only after reconnection.
9. **Physical attacks** (removing the disk, booting from USB) require BitLocker + firmware password + Secure Boot.
10. **Windows 10** is past end of support; unpatched OSes undermine every control.
11. This system **does not replace antivirus/EDR**; Microsoft Defender stays enabled and is never modified
    except to configure Controlled Folder Access.

---

*Next step: review this plan, answer the decisions in §12, and approve (or request changes). Phase 1 will then
turn this into ADRs, a threat model, the solution skeleton and CI.*
