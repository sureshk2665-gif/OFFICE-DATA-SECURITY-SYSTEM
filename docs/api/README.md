# API reference (v1)

Base address: `https://<server>:5443`. HTTPS only; clients pin the server CA (see ADR-0005).

- Request and response bodies are JSON (camelCase).
- Errors use RFC 9457 `application/problem+json`; the `detail` field is a message suitable for users.
- Signed-in calls send `Authorization: Bearer <token>`.
- All request and response types are defined in `src/Shared/OfficeSecurity.Contracts`.

## Access levels

| Level | Who |
|---|---|
| Anonymous | No sign-in needed |
| Signed-in | Any administrator or staff member |
| AdminRead | SuperAdmin, Admin, Auditor |
| AdminWrite | SuperAdmin, Admin |
| SuperAdmin | SuperAdmin only |

## Server and pairing

| Method & route | Access | Request → Response |
|---|---|---|
| `GET /api/v1/health` | Anonymous | → `HealthResponse` |
| `GET /api/v1/pairing/ca-certificate` | Anonymous | → CA certificate (DER, `application/pkix-cert`) |

## First-time setup and sign-in

Every endpoint in this group is anonymous and rate-limited.

| Method & route | Request → Response |
|---|---|
| `GET /api/v1/setup/status` | → `SetupStatusResponse` |
| `POST /api/v1/setup/first-admin` | `FirstAdminSetupRequest` → `MfaEnrollmentResponse` |
| `POST /api/v1/auth/admin/activate` | `AdminActivateRequest` → `MfaEnrollmentResponse` |
| `POST /api/v1/auth/admin/confirm-mfa` | `ConfirmMfaRequest` → 204 |
| `POST /api/v1/auth/admin/login` | `AdminLoginRequest` → `AdminLoginResponse` (MFA ticket) |
| `POST /api/v1/auth/admin/mfa` | `AdminMfaRequest` → `SessionResponse` |
| `POST /api/v1/auth/staff/login` | `StaffLoginRequest` → `SessionResponse` |
| `POST /api/v1/auth/staff/activate` | `StaffActivateRequest` → `SessionResponse` |

## Current session

| Method & route | Access | Request → Response |
|---|---|---|
| `GET /api/v1/auth/me` | Signed-in | → `CurrentUserResponse` |
| `POST /api/v1/auth/logout` | Signed-in | → 204 |
| `POST /api/v1/auth/change-password` | Signed-in | `ChangePasswordRequest` → 204 |

## Dashboard and staff accounts

| Method & route | Access | Request → Response |
|---|---|---|
| `GET /api/v1/dashboard/overview` | AdminRead | → `DashboardOverviewResponse` |
| `GET /api/v1/staff?page&pageSize&search&status` | AdminRead | → `PagedResult<StaffSummary>` |
| `GET /api/v1/staff/{id}` | AdminRead | → `StaffSummary` |
| `POST /api/v1/staff` | AdminWrite | `CreateStaffRequest` → `SetupCodeResponse` |
| `PUT /api/v1/staff/{id}` | AdminWrite | `UpdateStaffRequest` → `StaffSummary` |
| `POST /api/v1/staff/{id}/disable` | AdminWrite | → `StaffSummary` |
| `POST /api/v1/staff/{id}/enable` | AdminWrite | → `StaffSummary` |
| `POST /api/v1/staff/{id}/reset` | AdminWrite | → `SetupCodeResponse` |

## Administrator accounts

| Method & route | Access | Request → Response |
|---|---|---|
| `GET /api/v1/admins` | AdminRead | → `AdminSummary[]` |
| `POST /api/v1/admins` | SuperAdmin | `CreateAdminRequest` → `SetupCodeResponse` |
| `POST /api/v1/admins/{id}/disable` | SuperAdmin | → `AdminSummary` |
| `POST /api/v1/admins/{id}/enable` | SuperAdmin | → `AdminSummary` |
| `POST /api/v1/admins/{id}/reset` | SuperAdmin | → `SetupCodeResponse` |

## Audit log

| Method & route | Access | Request → Response |
|---|---|---|
| `GET /api/v1/audit?page&pageSize&search&from&to` | AdminRead | → `PagedResult<AuditEntryResponse>` |
| `GET /api/v1/audit/verify` | AdminRead | → `AuditVerificationResponse` |

## Computers, policies and events (administrators)

| Method & route | Access | Request → Response |
|---|---|---|
| `POST /api/v1/computers/enrollment-codes` | AdminWrite | → `EnrollmentCodeResponse` |
| `GET /api/v1/computers?page&pageSize&search&status` | AdminRead | → `PagedResult<ComputerSummary>` |
| `GET /api/v1/computers/{id}` | AdminRead | → `ComputerDetail` |
| `POST /api/v1/computers/{id}/approve` | AdminWrite | → `ComputerSummary` |
| `POST /api/v1/computers/{id}/reject` | AdminWrite | → `ComputerSummary` |
| `POST /api/v1/computers/{id}/retire` | AdminWrite | → `ComputerSummary` |
| `PUT /api/v1/computers/{id}/policy` | AdminWrite | `AssignPolicyRequest` → `ComputerSummary` |
| `PUT /api/v1/computers/{id}/staff` | AdminWrite | `AssignStaffRequest` → `StaffReference[]` |
| `GET /api/v1/events?page&pageSize&computerId&search` | AdminRead | → `PagedResult<SecurityEventResponse>` |
| `GET /api/v1/policies` | AdminRead | → `PolicySummary[]` |
| `GET /api/v1/policies/{id}` | AdminRead | → `PolicyDetail` |
| `POST /api/v1/policies` | AdminWrite | `SavePolicyRequest` → `PolicyDetail` |
| `PUT /api/v1/policies/{id}` | AdminWrite | `SavePolicyRequest` → `PolicyDetail` |
| `DELETE /api/v1/policies/{id}` | AdminWrite | → 204 (default or assigned policy → 409) |

Policy types (`PolicySettings`, `PolicyDetail`, …) are in `src/Shared/OfficeSecurity.Policy`.

## Security agent

| Method & route | Access | Request → Response |
|---|---|---|
| `POST /api/v1/agent/enroll` | Anonymous (enrollment code), rate-limited | `AgentEnrollRequest` → `AgentEnrollResponse` |
| `POST /api/v1/agent/enroll/status` | Anonymous (poll token), rate-limited | `AgentEnrollStatusRequest` → `AgentEnrollStatusResponse` |
| `POST /api/v1/agent/heartbeat` | Computer (mTLS) | `AgentHeartbeatRequest` → `AgentHeartbeatResponse` |
| `GET /api/v1/agent/policy` | Computer (mTLS) | → `SignedPolicyEnvelope` |
| `POST /api/v1/agent/inventory` | Computer (mTLS) | `AgentInventoryRequest` → 204 |
| `POST /api/v1/agent/events` | Computer (mTLS) | `AgentEventsRequest` (≤ 500) → `AgentEventsResponse` |
| `POST /api/v1/agent/login-ticket` | Computer (mTLS) | → `ComputerLoginTicketResponse` |

| `GET /api/v1/agent/jobs` | Computer (mTLS) | → `AgentJob[]` (this computer's queued and running installations) |
| `POST /api/v1/agent/jobs/{id}/start` | Computer (mTLS) | → 204 (counts an attempt; 409 after 3 attempts or when cancelled) |
| `GET /api/v1/agent/jobs/{id}/package` | Computer (mTLS) | → installer file (only for this computer's started job; otherwise 404) |
| `POST /api/v1/agent/jobs/{id}/result` | Computer (mTLS) | `AgentJobResult` (Succeeded, SucceededRebootRequired, Failed) → 204 |

"Computer (mTLS)" means a TLS client certificate issued by this server to a currently approved computer.
`POST /auth/staff/login` and `/auth/staff/activate` accept an optional `computerTicket` (see ADR-0006).

## Software (Phase 4, ADR-0007)

| Method & route | Access | Request → Response |
|---|---|---|
| `POST /api/v1/software-requests` | Staff | `CreateSoftwareRequest` → `SoftwareRequestResponse` |
| `GET /api/v1/software-requests/mine` | Staff | → `SoftwareRequestResponse[]` (latest 100) |
| `GET /api/v1/software-requests?page&pageSize&status` | AdminRead | → `PagedResult<SoftwareRequestResponse>` |
| `POST /api/v1/software-requests/{id}/approve` | AdminWrite | `ApproveSoftwareRequest` → `SoftwareRequestResponse` (creates an installation) |
| `POST /api/v1/software-requests/{id}/reject` | AdminWrite | `RejectSoftwareRequest` → `SoftwareRequestResponse` |
| `GET /api/v1/software/approved` | AdminRead | → `ApprovedSoftwareResponse[]` (with installer files) |
| `POST /api/v1/software/approved` | AdminWrite | `SaveApprovedSoftwareRequest` → `ApprovedSoftwareResponse` |
| `PUT /api/v1/software/approved/{id}` | AdminWrite | `SaveApprovedSoftwareRequest` → `ApprovedSoftwareResponse` |
| `DELETE /api/v1/software/approved/{id}` | AdminWrite | → 204 (409 while it has installer files) |
| `POST /api/v1/software/approved/{id}/packages?fileName&installerType&silentArguments&signerSubject&allowUnsigned` | AdminWrite | raw file body (≤ 4 GB) → `SoftwarePackageResponse` |
| `DELETE /api/v1/software/packages/{id}` | AdminWrite | → 204 (409 once used by an installation) |
| `GET /api/v1/software/deployments?page&pageSize&computerId&status` | AdminRead | → `PagedResult<DeploymentResponse>` |
| `POST /api/v1/software/deployments` | AdminWrite | `CreateDeploymentRequest` (1–500 approved computers) → `DeploymentResponse[]` |
| `POST /api/v1/software/deployments/{id}/cancel` | AdminWrite | → 204 (only while queued) |
| `GET /api/v1/software/inventory?search&unapprovedOnly` | AdminRead | → `SoftwareTitleSummary[]` |
| `GET /api/v1/software/inventory/computers?computerId&name` | AdminRead | → `InstalledSoftwareResponse[]` |

`AgentInventoryRequest` has an optional `software` list (`InstalledSoftware[]`); `AgentHeartbeatResponse` has
`pendingJobs`.

## Status codes

| Code | Meaning |
|---|---|
| 400 | Validation error |
| 401 | Not signed in, session ended, or credentials wrong |
| 403 | Role not allowed, or staff account used on a computer not assigned to it |
| 404 | Not found |
| 409 | Conflict (duplicate, or not allowed in the current state) |
| 429 | Too many sign-in requests |
