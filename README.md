# Office Computer Security System

Centralized Windows computer management, file safety and security enforcement for an office LAN.
There is no screen monitoring, screen recording, screenshots, keystroke logging, webcam or microphone capture.

> **Status: Phase 1 (foundation) complete — development build only.**
> The applications start and connect to each other. **No security control is enforced yet.**
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
| 2 | Database, admin login + two-step verification, staff accounts, roles, HTTPS | Next |
| 3 | Computer enrollment, agent heartbeat, policy distribution, offline queue | Planned |
| 4 | Software inventory, installation requests and approvals, approved deployment | Planned |
| 5 | USB / device control, application control, network & browser restrictions, file protection | Planned |
| 6 | Security events, alerts, audit log, reports (CSV/PDF) | Planned |
| 7 | MSI installers, full testing, pilot deployment | Planned |

## Documentation

- [Architecture & implementation plan](docs/00-ARCHITECTURE-AND-PLAN.md)
- [Decisions (ADRs)](docs/adr/): default assumptions, database, identity & trust, packaging
- [Threat model](docs/security/threat-model.md)

## For developers

```
dotnet build OfficeSecurity.slnx
dotnet test  OfficeSecurity.slnx
```

Requires the .NET 10 SDK. WPF and Windows-service projects compile on any OS (`EnableWindowsTargeting`),
but they run only on Windows.

```
src/Shared/   Contracts (API DTOs, enums) · Policy (policy model, ECDSA signing & verification)
src/Server/   OfficeSecurity.Server.Api (ASP.NET Core, Windows Service host)
src/Agent/    OfficeSecurity.Agent (Windows Service) · Agent.Enforcement (IEnforcer, coordinator)
src/Clients/  Client.Core (API client, settings) · Client.Wpf (theme) · AdminDashboard · StaffApp
tests/        Policy, Agent, Client.Core unit tests · Server integration tests
```

The server's Domain/Application/Infrastructure layers are added in Phase 2, when they get real content.
