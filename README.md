# Office Computer Security System

Centralized Windows computer management, file safety and security enforcement for an office LAN.
There is no screen monitoring, screen recording, screenshots, keystroke logging, webcam or microphone capture.

> **Status: Phase 2 (secure sign-in, accounts, audit log) complete — development build only.**
> **No computer security control is enforced yet.** USB, software and file protection arrive in Phases 3–5.
> Every control is reported as `NotImplemented` until its phase is delivered and tested.

## Getting the `.exe` files

Every push is built on a Windows machine by GitHub Actions:

1. Open the repository's **Actions** tab.
2. Open the latest **"Build, test and package"** run.
3. Download the **`OfficeSecurity-win-x64`** artifact (a zip file).
4. Unzip it and follow `READ-ME-FIRST.txt` inside.

| Program | Purpose |
|---|---|
| `Server\OfficeSecurity.Server.exe` | Central server (one always-on office PC). Can run as a Windows Service. |
| `Agent\OfficeSecurity.Agent.exe` | Security agent for every office PC (Windows Service). |
| `AdminDashboard\OfficeSecurity.AdminDashboard.exe` | Administrator dashboard. |
| `StaffApp\OfficeSecurity.StaffApp.exe` | Staff application. |

## Roadmap

| Phase | Content | Status |
|---|---|---|
| 1 | Architecture, decisions (ADRs), threat model, solution skeleton, signed policy format, CI | **Done** |
| 2 | Database, admin sign-in with two-step verification, staff accounts, roles, tamper-evident audit log, pinned HTTPS | **Done** |
| 3 | Computer enrollment, agent heartbeat, policy distribution, offline queue | Next |
| 4 | Software inventory, installation requests and approvals, approved deployment | Planned |
| 5 | USB / device control, application control, network & browser restrictions, file protection | Planned |
| 6 | Security events, alerts, audit log, reports (CSV/PDF) | Planned |
| 7 | MSI installers, full testing, pilot deployment | Planned |

## Documentation

- [Architecture & implementation plan](docs/00-ARCHITECTURE-AND-PLAN.md)
- [Decisions (ADRs)](docs/adr/): default assumptions, database, identity & trust, packaging
- [Threat model](docs/security/threat-model.md)
- [API reference](docs/api/README.md) · [Database schema](docs/database/schema.md)
- [Phase 2 test report](docs/testing/phase-2-test-report.md)

## For developers

```
dotnet build OfficeSecurity.slnx
dotnet test  OfficeSecurity.slnx
```

Requires the .NET 10 SDK. WPF and Windows-service projects compile on any OS (`EnableWindowsTargeting`),
but they run only on Windows.

```
src/Shared/   Contracts (API DTOs, enums) · Policy (policy model, ECDSA signing & verification)
src/Server/   Domain (entities) · Application (auth, accounts, audit) · Infrastructure (EF Core/SQLite, CA) · Api (endpoints, Windows Service host)
src/Agent/    OfficeSecurity.Agent (Windows Service) · Agent.Enforcement (IEnforcer, coordinator)
src/Clients/  Client.Core (API client, pinned TLS, pairing, shared view models) · Client.Wpf (theme, shared views) · AdminDashboard · StaffApp
tests/        Policy, Agent, Client.Core, Server unit tests · Server integration tests (in-memory and real HTTPS)
```

Both desktop apps support `--smoke-test <log file>`, which builds every screen off-screen; CI runs it on Windows.
